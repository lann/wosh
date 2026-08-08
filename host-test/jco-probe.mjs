// M5 probe: the wac-composed client core under jco (JSPI, node leg) —
// the exact machinery the browser client needs, minus the DOM. This is
// the A3-blocked leg: polymorph-iroh#10 / lann/jco#11 (re-verified in
// finding 14 against jco dbad4d7d). The probe exists to *classify* the
// current failure mode against a real proxy (or to detect the unblock
// the day upstream lands it) — it never fakes the transport.
//
// Run: npm run jco-probe   (transpiles first; node needs
// --experimental-wasm-jspi, set in the npm script)
//
// Exit 0 = probe completed and printed a classification (UNBLOCKED /
// THROWS / HANGS); exit 1 = probe infrastructure failed.

import { spawn } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const RELAY_PORT = 3348;
const TOKEN = "pr0be-tok";
const CONNECT_TIMEOUT_MS = 45_000;

const log = (m) => console.log(`[jco-probe] ${m}`);
const children = [];
const reap = () => {
  for (const c of children) c.kill("SIGKILL");
};
process.on("exit", reap);

const waitPort = async (port, tries = 100) => {
  for (let i = 0; i < tries; i++) {
    const ok = await new Promise((resolve) => {
      const s = createConnection({ port, host: "127.0.0.1" }, () => {
        s.destroy();
        resolve(true);
      });
      s.on("error", () => resolve(false));
    });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`nothing listening on :${port}`);
};

// --- relay + proxy (same shape as host-test/proxy-e2e) -----------------------

const dir = await mkdtemp(join(tmpdir(), "experiment-mosh-jco-probe-"));
const relayCfg = join(dir, "relay.toml");
await writeFile(relayCfg, `http_bind_addr = "127.0.0.1:${RELAY_PORT}"\nenable_metrics = false\n`);
const relayBin = join(HERE, "../.deps/polymorph-iroh/.deps/iroh/target/release/iroh-relay");
children.push(spawn(relayBin, ["--dev", "-c", relayCfg], { stdio: "ignore" }));
await waitPort(RELAY_PORT);
log(`relay on :${RELAY_PORT}`);

const proxyBin = join(HERE, "../proxy/target/release/experiment-mosh-proxy");
const proxy = spawn(
  proxyBin,
  [
    "--relay",
    `http://127.0.0.1:${RELAY_PORT}`,
    "--token",
    TOKEN,
    "--no-qr",
    "--yes",
    "--state-dir",
    join(dir, "state"),
    "--component",
    join(HERE, "../proxy/composed-proxy.wasm"),
    "--shell",
    "bash --noprofile --norc -i",
  ],
  { stdio: ["ignore", "pipe", "inherit"] },
);
children.push(proxy);

const proxyInfo = await new Promise((resolve, reject) => {
  let buf = "";
  const timer = setTimeout(() => reject(new Error("proxy never printed connstring")), 30_000);
  proxy.stdout.on("data", (d) => {
    buf += d;
    process.stdout.write(`[proxy] ${d}`);
    const cs = buf.match(/connstring: 1\.([0-9a-f]{64})\.\S+/);
    const da = buf.match(/direct-addr: (\S+)/);
    if (cs && da) {
      clearTimeout(timer);
      resolve({ idHex: cs[1], direct: da[1].replace("0.0.0.0", "127.0.0.1") });
    }
  });
  proxy.on("exit", (c) => reject(new Error(`proxy exited early (${c})`)));
});
log(`proxy up: ${proxyInfo.idHex.slice(0, 16)}… direct=${proxyInfo.direct}`);

// --- the composed client under jco -------------------------------------------

let classification;
try {
  const t0 = Date.now();
  const mod = await import("./generated-client/composed-client.js");
  log(`transpiled module imported and instantiated in ${Date.now() - t0}ms`);
  const ClientSession = mod.client.ClientSession;

  const outcome = await Promise.race([
    (async () => {
      const session = await ClientSession.connectProxy(
        `http://127.0.0.1:${RELAY_PORT}`,
        proxyInfo.idHex,
        proxyInfo.direct,
        TOKEN,
        80,
        24,
      );
      return { kind: "connected", session };
    })().catch((e) => ({ kind: "threw", error: e })),
    new Promise((r) => setTimeout(() => r({ kind: "timeout" }), CONNECT_TIMEOUT_MS)),
  ]);

  if (outcome.kind === "connected") {
    // If we got here, A3 is unblocked — verify it's real with a prompt.
    log("connect-proxy RESOLVED — probing for a live session…");
    const session = outcome.session;
    let visible = "";
    const deadline = Date.now() + 20_000;
    while (Date.now() < deadline && !visible.includes("$")) {
      await new Promise((r) => setTimeout(r, 100));
      visible += new TextDecoder().decode(Uint8Array.from(session.drainOutput()));
    }
    classification = visible.includes("$")
      ? "UNBLOCKED: composed client speaks mosh over iroh under jco/JSPI — A3 has landed; build the browser leg"
      : "PARTIAL: connect-proxy resolved but no terminal output; new defect class — file a minimal repro upstream";
    session.detach();
  } else if (outcome.kind === "threw") {
    classification = `THROWS: ${outcome.error.message ?? outcome.error} — compare against polymorph-iroh#10 / lann/jco#11 before filing anything new`;
  } else {
    classification = `HANGS: connect-proxy pending after ${CONNECT_TIMEOUT_MS / 1000}s — matches finding 14's async-lower hang under jco (A3 still blocked)`;
  }
} catch (e) {
  classification = `THROWS AT IMPORT/INSTANTIATION: ${e.message ?? e} — the known instance is the composed-resource TDZ (lann/jco#51, minimal repro in spikes/compose-async-tdz); anything else is a new defect class`;
} finally {
  reap();
  await rm(dir, { recursive: true, force: true });
}

console.log(`\n[jco-probe] CLASSIFICATION: ${classification}`);
