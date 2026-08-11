// The M5 browser E2E — the leg jco could never run (A3), now the gate
// that proves it: the composed client (engine + glue + endpoint,
// runtime-linked by deltic IN THE PAGE) speaks real mosh SSP through a
// live proxy over iroh, from headless Chromium.
//
//   node browser-e2e.mjs        (via `just m5-browser-e2e`)
//
// Topology: iroh-relay --dev (:3352) ← native proxy (--personal,
// proxy-spawned mosh-server) ← relay websocket ← the page's composed
// client. The page is the REAL client (web/index.html + boot.mjs +
// app.mjs): the harness navigates to /#<connstring> exactly like a QR
// scan, clicks the panel's connect button, and asserts the M1 trio
// (prompt, echo round-trip, resize propagation) through xterm.js.
//
// Bounded connect retries: the endpoint guest has a known RefCell
// borrow hazard across its webcrypto-sign yield points (documented in
// polymorph-iroh host-deltic/README.md; latent on every host, reached
// more often under deltic's scheduler) — a trapped handshake gets a
// fresh page, and the attempt count is reported.

import http from "node:http";
import { readFile, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { spawn } from "node:child_process";

const HERE = import.meta.dirname;
const WEB = join(HERE, "..", "web");
const RELAY_PORT = 3352;
const TOKEN = "browser-e2e-token";
const CONNECT_ATTEMPTS = 8;

const log = (...a) => console.log("[browser-e2e]", ...a);

// --- children ----------------------------------------------------------------
const children = [];
const reap = () => {
  for (const c of children.reverse()) {
    try {
      process.kill(-c.pid, "SIGTERM");
    } catch {
      try {
        c.kill("SIGTERM");
      } catch {
        // gone
      }
    }
  }
};
process.on("exit", reap);

const waitPort = async (port, tries = 100) => {
  const net = await import("node:net");
  for (let i = 0; i < tries; i++) {
    const ok = await new Promise((resolve) => {
      const s = net.createConnection({ host: "127.0.0.1", port }, () => {
        s.destroy();
        resolve(true);
      });
      s.on("error", () => resolve(false));
    });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`nothing listening on :${port}`);
};

// --- relay + proxy -----------------------------------------------------------
const dir = await mkdtemp(join(tmpdir(), "wosh-browser-e2e-"));
const relayCfg = join(dir, "relay.toml");
await writeFile(relayCfg, `http_bind_addr = "127.0.0.1:${RELAY_PORT}"\nenable_metrics = false\n`);
const relayBin = join(HERE, "../.deps/polymorph-iroh/.deps/iroh/target/release/iroh-relay");
children.push(spawn(relayBin, ["--dev", "-c", relayCfg], { stdio: "ignore", detached: true }));
await waitPort(RELAY_PORT);
log(`relay on :${RELAY_PORT}`);

const proxyBin = join(HERE, "../proxy/target/release/wosh-proxy");
const proxy = spawn(
  proxyBin,
  [
    "--relay",
    `http://127.0.0.1:${RELAY_PORT}`,
    "--token",
    TOKEN,
    "--no-qr",
    "--yes",
    // Personal mode: the proxy spawns the mosh-server itself (the M4
    // path). The deprivileged/inner-ssh browser leg is M7's follow-up.
    "--personal",
    "--shell",
    "bash --noprofile --norc -i",
    "--state-dir",
    join(dir, "state"),
    "--component",
    join(HERE, "../proxy/composed-proxy.wasm"),
  ],
  { stdio: ["ignore", "pipe", "inherit"], detached: true },
);
children.push(proxy);

const connstring = await new Promise((resolve, reject) => {
  let buf = "";
  const timer = setTimeout(() => reject(new Error("proxy connstring timeout")), 20_000);
  proxy.stdout.on("data", (d) => {
    buf += d;
    const m = buf.match(/connstring: (\S+)/);
    if (m) {
      clearTimeout(timer);
      resolve(m[1]);
    }
  });
  proxy.on("exit", () => reject(new Error("proxy exited before connstring")));
});
log(`proxy up: ${connstring.slice(0, 24)}…`);

// --- static server (the real client tree, no dev bridge) ----------------------
const MIME = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".css": "text/css",
  ".wasm": "application/wasm",
};
const ROUTES = [
  [/^\/$/, () => join(WEB, "index.html")],
  [/^\/(app|boot|connstring|storage|idb-keys|prf-wrap)\.mjs$/, (m) => join(WEB, `${m[1]}.mjs`)],
  [/^\/xterm\/xterm\.css$/, () => join(WEB, "node_modules/@xterm/xterm/css/xterm.css")],
  [/^\/xterm\/xterm\.js$/, () => join(WEB, "node_modules/@xterm/xterm/lib/xterm.js")],
  [/^\/xterm\/addon-fit\.js$/, () => join(WEB, "node_modules/@xterm/addon-fit/lib/addon-fit.js")],
  [/^\/dist\/deltic\.js$/, () => join(WEB, "dist/deltic.js")],
  [/^\/dist\/composed-client\.wasm$/, () => join(HERE, "../client-core/composed-client.wasm")],
  [
    /^\/dist\/deltic-translator-shim\.wasm$/,
    () => {
      if (!process.env.DELTIC_TRANSLATOR) throw new Error("DELTIC_TRANSLATOR unset");
      return process.env.DELTIC_TRANSLATOR;
    },
  ],
];
const httpServer = http.createServer(async (req, res) => {
  const pathname = decodeURIComponent(req.url.split("?")[0]);
  const route = ROUTES.find(([re]) => re.test(pathname));
  if (!route || pathname.includes("..")) {
    res.statusCode = 404;
    res.end("not found");
    return;
  }
  try {
    const file = route[1](route[0].exec(pathname));
    res.setHeader("content-type", MIME[extname(file)] ?? "application/octet-stream");
    res.end(await readFile(file));
  } catch (e) {
    res.statusCode = 404;
    res.end(String(e));
  }
});
await new Promise((r) => httpServer.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${httpServer.address().port}`;

// --- the browser -------------------------------------------------------------
const { chromium } = await import("playwright-core");
const { findChrome } = await import("./chrome.mjs");
const executablePath = await findChrome();
if (!executablePath) throw new Error("no Chromium found; set CHROME_PATH");

const hardTimer = setTimeout(() => {
  console.error("FAIL: hard timeout");
  process.exit(2);
}, 300_000);

const browser = await chromium.launch({
  executablePath,
  headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

const pageText = (page) => page.evaluate(() => window.__mosh?.text?.() ?? "");
const waitText = async (page, re, label, timeoutMs = 20_000) => {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const failure = await page.evaluate(() => window.__mosh?.failure ?? null);
    if (failure) throw new Error(`page failure while waiting for ${label}: ${failure}`);
    const t = await pageText(page);
    if (re.test(t)) return;
    if (Date.now() > deadline)
      throw new Error(`timeout waiting for ${label} (${re})\n--- screen ---\n${t}`);
    await new Promise((r) => setTimeout(r, 50));
  }
};

/** One connect attempt on a fresh page; resolves to the live page. */
async function connectOnce(context, fragment, label) {
  const page = await context.newPage();
  page.on("console", (m) => {
    if (m.type() === "error") console.error(`[page console] ${m.text()}`);
  });
  await page.goto(`${base}/#${fragment}`);
  // The fragment flow: boot parsed it into the pending row.
  await page.waitForSelector("#connect-pending-btn", { timeout: 10_000 });
  await page.click("#connect-pending-btn");
  // Connected = iroh mode hooks installed; failure = notice line.
  const deadline = Date.now() + 45_000;
  for (;;) {
    const mode = await page.evaluate(() => window.__mosh?.mode ?? null);
    if (mode === "iroh") return page;
    const notice = await page.evaluate(() => window.__moshBoot?.notice ?? "");
    if (notice.startsWith("connect failed")) throw new Error(`${label}: ${notice}`);
    if (Date.now() > deadline) throw new Error(`${label}: neither session nor failure in 45s`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

let failed = null;
try {
  const context = await browser.newContext();

  // Phase 0 (negative first, cheap): a wrong pairing token is refused
  // with a legible notice — and the proxy stays up for the real run.
  {
    const [v, id, , ...rest] = connstring.split(".");
    const badFragment = [v, id, "wrong-token", rest.join(".")].join(".");
    let refusal = null;
    try {
      const p = await connectOnce(context, badFragment, "negative");
      await p.close();
    } catch (e) {
      refusal = e.message;
    }
    if (!refusal) throw new Error("wrong pairing token was accepted");
    log(`wrong token refused: ${refusal.slice(0, 100)}`);
  }

  // Phase 1: connect (bounded retries over the guest RefCell hazard).
  let page = null;
  let attempts = 0;
  let lastErr = null;
  while (attempts < CONNECT_ATTEMPTS && !page) {
    attempts++;
    try {
      page = await connectOnce(context, connstring, `attempt ${attempts}`);
    } catch (e) {
      lastErr = e;
      log(`connect attempt ${attempts}/${CONNECT_ATTEMPTS} failed: ${e.message.slice(0, 140)}`);
    }
  }
  if (!page) throw new Error(`no connect attempt succeeded; last: ${lastErr?.message}`);
  log(`connected (attempt ${attempts}/${CONNECT_ATTEMPTS})`);

  // Phase 2: the M1 trio through the whole stack.
  await waitText(page, /\$/, "shell prompt");
  log("prompt OK");

  await page.click("#term");
  await page.keyboard.type("echo m0sh_$(printf browser)_ok", { delay: 5 });
  await page.keyboard.press("Enter");
  await waitText(page, /m0sh_browser_ok/, "echo marker");
  log("echo round-trip OK");

  await page.evaluate(() => window.__mosh.resize(100, 30));
  await page.keyboard.type("stty size", { delay: 5 });
  await page.keyboard.press("Enter");
  await waitText(page, /30 100/, "stty size after resize");
  log("resize OK");

  // Phase 3: stats sanity from the page (Promise-shaped hook).
  const st = await page.evaluate(async () => {
    const s = await window.__mosh.stats();
    return { sent: String(s.sentNum), acked: String(s.ackedNum), recv: String(s.recvNum) };
  });
  log(`stats: sent=${st.sent} acked=${st.acked} recv=${st.recv}`);
  if (Number(st.acked) < 1) throw new Error("server never acked");

  // Phase 3b: the WebRTC upgrade. The connection was relay-dialed; with
  // the wire enabled on both sides the packets move to the data channel
  // in the background. `path` is not latched, so poll for the move —
  // and echo again afterwards: the session must survive the migration.
  {
    const t0 = Date.now();
    let path = null;
    while (Date.now() - t0 < 30_000) {
      path = await page.evaluate(() => window.__mosh.path());
      if (path === "webrtc") break;
      await new Promise((r) => setTimeout(r, 250));
    }
    if (path !== "webrtc") {
      throw new Error(`connection.path stayed "${path}" (no WebRTC upgrade within 30 s)`);
    }
    log(`path upgraded to webrtc in ${Date.now() - t0} ms`);

    await page.keyboard.type("echo p0st_$(printf upgrade)_ok", { delay: 5 });
    await page.keyboard.press("Enter");
    await waitText(page, /p0st_upgrade_ok/, "echo after webrtc upgrade");
    log("echo over the data channel OK");
  }

  await page.screenshot({ path: "/tmp/opencode/m5-browser-e2e.png" });
  log("screenshot: /tmp/opencode/m5-browser-e2e.png");

  // Phase 4: detach cleanly (the glue closes the connection; the proxy
  // logs the session end).
  await page.evaluate(() => window.__mosh.detach());
  log("detach OK");
  await page.close();
} catch (e) {
  failed = e;
} finally {
  await browser.close();
  httpServer.close();
  reap();
  clearTimeout(hardTimer);
}

if (failed) {
  console.error("FAIL:", failed.message);
  process.exit(1);
}
console.log("browser E2E (M5 gate, deltic): OK");
process.exit(0);
