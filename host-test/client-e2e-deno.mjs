// M5 composed-client smoke on the Deno lane: the SAME artifact and the
// SAME deltic host modules the browser page uses (relay wire, webcrypto
// identity, fail-on-call sockets — WOSH_UDP=off), driven headless against
// a real proxy. The fast diagnostic between "components broke" and
// "the browser page broke": run this before browser-e2e.mjs when the
// browser gate goes red.
//
//   just m5-client-deno
//
// Spawns iroh-relay --dev (:3348) + wosh-proxy --personal, then:
// connect-proxy (control channel, TOFU, key delivery) → M1 trio
// (prompt, echo, resize) → stats sanity → detach.

import process from "node:process";
import { deadline, describeError, newClientInstance, CLIENT_INTERFACE } from "./deltic-host.ts";

const RELAY_PORT = 3348;
const TOKEN = "deno-e2e-token";
const HERE = new URL(".", import.meta.url).pathname;

const log = (...a) => console.log("[client-deno]", ...a);

const stripAnsi = (s) =>
  s
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "")
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "")
    .replace(/\x1b[@-Z\\-_]/g, "")
    .replace(/[\x00-\x09\x0b-\x1f\x7f]/g, "");

// --- relay + proxy ------------------------------------------------------------

const children = [];
const reap = () => {
  for (const c of children.reverse()) {
    try {
      c.kill("SIGTERM");
    } catch {
      // already gone
    }
  }
};

async function portOpen(port) {
  try {
    const conn = await Deno.connect({ hostname: "127.0.0.1", port });
    conn.close();
    return true;
  } catch {
    return false;
  }
}

async function waitPort(port, tries = 100) {
  for (let i = 0; i < tries; i++) {
    if (await portOpen(port)) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`nothing listening on :${port}`);
}

const sink = (r) => r.pipeTo(new WritableStream({ write() {} })).catch(() => {});

async function startRelay() {
  const dir = await Deno.makeTempDir({ prefix: "wosh-client-deno-" });
  const cfg = `${dir}/relay.toml`;
  await Deno.writeTextFile(
    cfg,
    `http_bind_addr = "127.0.0.1:${RELAY_PORT}"\nenable_metrics = false\n`,
  );
  const child = new Deno.Command(`${HERE}../.deps/polymorph-iroh/.deps/iroh/target/release/iroh-relay`, {
    args: ["--dev", "-c", cfg],
    stdout: "null",
    stderr: "null",
  }).spawn();
  children.push(child);
  await waitPort(RELAY_PORT);
  log(`relay on :${RELAY_PORT}`);
  return dir;
}

async function startProxy(stateDir) {
  const child = new Deno.Command(`${HERE}../proxy/target/release/wosh-proxy`, {
    args: [
      "--relay",
      `http://127.0.0.1:${RELAY_PORT}`,
      "--token",
      TOKEN,
      "--no-qr",
      "--yes",
      "--personal",
      "--shell",
      "bash --noprofile --norc -i",
      "--state-dir",
      `${stateDir}/state`,
      "--component",
      `${HERE}../proxy/composed-proxy.wasm`,
    ],
    stdout: "piped",
    stderr: "inherit",
  }).spawn();
  children.push(child);

  // Scrape the connstring (1.<id>.<token>.<relay>) from proxy stdout.
  const reader = child.stdout.pipeThrough(new TextDecoderStream()).getReader();
  let buf = "";
  const connstring = await deadline(
    (async () => {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) throw new Error("proxy exited before printing a connstring");
        buf += value;
        const m = buf.match(/connstring: (\S+)/);
        if (m) {
          // Keep draining stdout so the proxy never blocks on the pipe.
          (async () => {
            try {
              for (;;) {
                if ((await reader.read()).done) break;
              }
            } catch {
              // teardown
            }
          })();
          return m[1];
        }
      }
    })(),
    20_000,
    "proxy connstring",
  );
  log(`proxy up: ${connstring.slice(0, 24)}…`);
  return connstring;
}

// --- the exam -------------------------------------------------------------------

let failed = null;
try {
  const dir = await startRelay();
  const connstring = await startProxy(dir);
  // v1 format: 1.<id>.<token>.<relay-url> — the relay URL contains dots,
  // so split unbounded and rejoin the tail (JS split's limit TRUNCATES).
  const [v, idHex, token, ...rest] = connstring.split(".");
  const relay = rest.join(".");
  if (v !== "1") throw new Error(`connstring version ${v}`);

  const inst = await newClientInstance("../client-core/composed-client.wasm", {
    label: "client-deno",
    env: { WOSH_UDP: "off" }, // the browser profile: no UDP socket
  });
  const client = inst.exports[CLIENT_INTERFACE];

  // connect-proxy: dial (relay path only), control handshake, TOFU
  // auto-accept (--yes), NewSession, key delivery, engine start.
  const session = await deadline(
    client.ClientSession.connectProxy(relay, idHex, undefined, token, 80, 24),
    60_000,
    "connect-proxy",
  );
  log("connect-proxy resolved — session live");

  let visible = "";
  const decoder = new TextDecoder();
  let pumping = true;
  const pump = (async () => {
    while (pumping) {
      const out = await session.drainOutput();
      if (out.length) visible += stripAnsi(decoder.decode(out));
      await new Promise((r) => setTimeout(r, 8));
    }
  })();

  const waitFor = async (re, label, timeoutMs = 20_000) => {
    const deadlineAt = Date.now() + timeoutMs;
    while (!re.test(visible)) {
      if (Date.now() > deadlineAt) {
        throw new Error(`timeout waiting for ${label}\n--- visible ---\n${visible.slice(-500)}`);
      }
      await new Promise((r) => setTimeout(r, 25));
    }
  };

  const feed = (s) => session.feedKeys(new TextEncoder().encode(s));

  await waitFor(/\$/, "shell prompt");
  log("prompt OK");

  await feed("echo m0sh_$(printf deno)_ok\r");
  await waitFor(/m0sh_deno_ok/, "echo marker");
  log("echo round-trip OK");

  await session.resize(100, 30);
  await feed("stty size\r");
  await waitFor(/30 100/, "stty size after resize");
  log("resize OK");

  const st = await session.stats();
  log(`stats: sent=${st.sentNum} acked=${st.ackedNum} recv=${st.recvNum} rto=${st.rtoMs}ms`);
  if (st.ackedNum < 1n) throw new Error("server never acked");
  const dgramMax = await session.maxDatagramSize();
  log(`max-datagram-size: ${dgramMax}B`);

  // Path report, observational on this lane (the browser E2E is the
  // upgrade gate): node-datachannel answers webrtc-rs on loopback.
  // Bounded poll — the upgrade runs in the background and may lose the
  // race to a short-lived session; where the wire ends up is the log.
  {
    const t0 = Date.now();
    let path = await session.path();
    while (path !== "webrtc" && Date.now() - t0 < 10_000) {
      await new Promise((r) => setTimeout(r, 250));
      path = await session.path();
    }
    log(`path: ${path}${path === "webrtc" ? ` (upgraded, ${Date.now() - t0} ms)` : " (no upgrade within 10 s)"}`);
  }

  pumping = false;
  await pump;
  await deadline(session.detach(), 15_000, "detach");
  log("detach OK");
} catch (e) {
  failed = e;
} finally {
  reap();
}

if (failed) {
  console.error("FAIL:", describeError(failed));
  process.exit(1);
}
console.log("composed client on the Deno lane (deltic): OK");
process.exit(0);
