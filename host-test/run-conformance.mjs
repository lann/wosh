// M1 conformance harness: drives the engine component (runtime-linked by
// deltic) against a real mosh server over loopback UDP, on Deno.
//
//   deno run -A run-conformance.mjs --server c    # stock C mosh-server (the gate)
//   deno run -A run-conformance.mjs --server go   # mosh-go's native server
//
// (DELTIC_TRANSLATOR must point at the pinned translator shim; the
// `just m1` recipes fetch it and set the env.)
//
// The engine is sans-I/O: this driver owns the UDP socket and the 8 ms
// tick, exactly the contract the browser client implements. Every export
// is Promise-shaped under deltic, so the pump is one async loop — feed
// inbound datagrams, tick, drain — preserving call order by construction.
// Asserts keystroke echo end-to-end (command output round-trip), resize
// propagation (stty size), transport stats sanity, and the outbound
// datagram size bound (≤ 1162 B, the iroh application ceiling).

import dgram from "node:dgram";
import process from "node:process";
import { parseArgs } from "node:util";

import { startServer } from "./mosh-servers.mjs";
import { deadline, describeError, newEngineInstance, ENGINE_INTERFACE } from "./deltic-host.ts";

const { values: opts } = parseArgs({
  args: process.argv.slice(2),
  options: {
    server: { type: "string", default: "c" },
    cols: { type: "string", default: "80" },
    rows: { type: "string", default: "24" },
  },
});

const HARD_TIMEOUT_MS = 45_000;
const SIZE_CEILING = 1162; // iroh app ceiling under the 1200 B MTU profile

const log = (...a) => console.log("[conformance]", ...a);
const fail = (msg) => {
  throw new Error(msg);
};

// --- ANSI stripping (assertions run on visible text) --------------------
const stripAnsi = (s) =>
  s
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "") // OSC
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "") // CSI
    .replace(/\x1b[@-Z\\-_]/g, "") // 2-byte escapes
    .replace(/[\x00-\x09\x0b-\x1f\x7f]/g, ""); // controls except \n

// --- main -----------------------------------------------------------------
const hardTimer = setTimeout(() => {
  console.error("FAIL: hard timeout");
  process.exit(2);
}, HARD_TIMEOUT_MS);

const inst = await newEngineInstance("../engine-go/main.wasm", {
  label: "conformance-engine",
});
const engine = inst.exports[ENGINE_INTERFACE];
log(await engine.version());

const server = await startServer(opts.server);
log(`server (${opts.server}) on 127.0.0.1:${server.port}`);

const cols = Number(opts.cols);
const rows = Number(opts.rows);
const sess = await deadline(
  // initial-seq: none — a fresh session starts at 0 (finding 13/20
  // reattach flows pass a floor; conformance never reattaches).
  engine.Session.connect(server.key, cols, rows, undefined),
  10_000,
  "session connect",
);

const sock = dgram.createSocket("udp4");
let inbound = [];
let recvMax = 0;
sock.on("message", (msg) => {
  inbound.push(new Uint8Array(msg));
  if (msg.length > recvMax) recvMax = msg.length;
});

let sentSizes = [];
let visible = ""; // cumulative stripped output
const decoder = new TextDecoder();

// The pump: one async loop so handle-datagram/tick/drain-output never
// overlap (deltic admits export calls in order, but explicit is better).
let pumping = true;
let pumpFailure = null;
const pump = (async () => {
  try {
    while (pumping) {
      const batch = inbound;
      inbound = [];
      for (const d of batch) await sess.handleDatagram(d);
      for (const d of await sess.tick()) {
        sentSizes.push(d.length);
        sock.send(d, server.port, "127.0.0.1");
      }
      const out = await sess.drainOutput();
      if (out.length) visible += stripAnsi(decoder.decode(out));
      await new Promise((r) => setTimeout(r, 8));
    }
  } catch (e) {
    pumpFailure = e;
  }
})();

const feed = (s) => sess.feedKeys(new TextEncoder().encode(s));
const waitFor = async (re, label, timeoutMs = 12_000) => {
  const deadlineAt = Date.now() + timeoutMs;
  while (!re.test(visible)) {
    if (pumpFailure) throw pumpFailure;
    if (Date.now() > deadlineAt)
      fail(`timeout waiting for ${label} (${re})\n--- visible tail ---\n${visible.slice(-500)}`);
    await new Promise((r) => setTimeout(r, 25));
  }
};

let failed = null;
try {
  // Phase 0: shell prompt arrives through the full stack.
  await waitFor(/\$/, "shell prompt");
  log("prompt OK");

  // Phase 1: keystroke echo — command output round-trip. The typed
  // line never contains the contiguous marker, so a match proves the
  // server executed what we typed and the diff pipeline rendered it.
  await feed("echo m0sh_$(printf conf)_ok\r");
  await waitFor(/m0sh_conf_ok/, "echo marker");
  log("echo round-trip OK");

  // Phase 2: resize propagates to the server-side pty.
  await sess.resize(100, 30);
  await feed("stty size\r");
  await waitFor(/30 100/, "stty size after resize");
  log("resize OK");

  // Phase 3: bulk paste — one feed-keys large enough that the client
  // diff must fragment (multi-datagram reassembly on the server, and
  // the patched 1100 B fragment payload on our side). The blob is
  // random alphanumerics, so zlib cannot squeeze it under one
  // fragment. Mosh is a screen-state protocol — most of the echoed
  // blob scrolls straight past the framebuffer — but SSP applies the
  // keystroke diff atomically: the server sees either all 4000 chars
  // or none. The blob tail rendering on the final screen therefore
  // proves the whole multi-fragment diff arrived; phase 6 separately
  // proves it fragmented. Whitespace is stripped (the echo line-wraps).
  const blob = Array.from({ length: 4000 }, () =>
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(
      Math.floor(Math.random() * 62),
    ),
  ).join("");
  await feed(`echo ${blob}\r`);
  {
    const tail = blob.slice(-60);
    const deadlineAt = Date.now() + 15_000;
    while (!visible.replace(/\s+/g, "").includes(tail)) {
      if (pumpFailure) throw pumpFailure;
      if (Date.now() > deadlineAt)
        fail(`timeout waiting for paste blob tail\n--- visible tail ---\n${visible.slice(-300)}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  }
  log("bulk paste round-trip OK");

  // Phase 4: server→client bulk (its fragment sizing is its own
  // business — recorded, not asserted). The assertion is on the final
  // screen state: fast-scrolling intermediate rows are legitimately
  // skipped by mosh. (Leg-b note: mosh-go's server has been seen
  // dropping a leading digit mid-scroll — '99' for '299' — so only
  // the last row is asserted; the C leg is the fidelity gate.)
  await feed("seq 1 300\r");
  await waitFor(/\b300\b/, "seq output");
  log("server bulk OK");

  // Phase 5: transport stats sanity.
  const st = await sess.stats();
  log(
    `stats: sent=${st.sentNum} acked=${st.ackedNum} recv=${st.recvNum} ` +
      `rto=${st.rtoMs}ms lastRecvAge=${st.lastRecvAgeMs}ms ` +
      `predictor=${st.predictorActive} states=${st.trackedStates}`,
  );
  if (st.sentNum < 1n) fail("sentNum < 1");
  if (st.ackedNum < 1n) fail("server never acked our state");
  if (st.recvNum < 1n) fail("no server state received");
  if (st.lastRecvAgeMs === undefined) fail("lastRecvAgeMs missing after traffic");
  if (st.rtoMs < 1n) fail("rtoMs < 1");
  if (st.trackedStates < 1) fail("no tracked states");

  // Phase 6: outbound datagram size bound — including the paste,
  // whose diff must have fragmented into ceiling-sized datagrams.
  const maxSent = Math.max(...sentSizes);
  log(`datagrams: sent=${sentSizes.length} maxSent=${maxSent}B maxRecv=${recvMax}B`);
  if (maxSent > SIZE_CEILING) fail(`outbound datagram ${maxSent}B exceeds ${SIZE_CEILING}B`);
  if (maxSent < 1000) fail(`paste never fragmented (maxSent=${maxSent}B) — bulk phase broken?`);
} catch (e) {
  failed = e;
} finally {
  pumping = false;
  await pump.catch(() => {});
  sock.close();
  server.stop();
  clearTimeout(hardTimer);
}

if (failed) {
  console.error(`FAIL (${opts.server} leg):`, describeError(failed));
  process.exit(1);
}
console.log(`conformance (${opts.server} leg): OK`);
process.exit(0);
