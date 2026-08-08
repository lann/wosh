// M2 browser smoke: xterm.js + the jco-transpiled engine in a real
// (headless) browser, datagrams over a throwaway ws↔UDP bridge.
//
//   node browser-smoke.mjs             # headless assertions (the M2 gate)
//   node browser-smoke.mjs --serve     # manual mode: prints a URL, ^C to stop
//
// Bridge contract (deliberately dumb, replaced by iroh from M3/M5):
// each ws connection spawns its own mosh-server; the first frame is a
// JSON hello {key, delayMs}; afterwards every binary frame is exactly
// one mosh datagram. ?delay=N adds N ms artificial latency each way
// (prediction observation; keep RTT well under the predictor's 500 ms
// expiry).
//
// Serves: / and /app.mjs from ../web, /xterm/* from web's node_modules,
// /generated/* (the transpiled engine) and /shim/* (preview2-shim
// browser dist) from this package.

import dgram from "node:dgram";
import http from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { parseArgs } from "node:util";

import { WebSocketServer } from "ws";

import { startServer } from "./mosh-servers.mjs";

const { values: opts } = parseArgs({
  options: {
    serve: { type: "boolean", default: false },
    server: { type: "string", default: "c" },
    delay: { type: "string", default: "150" }, // test mode: prediction-phase delay
  },
});

const HERE = import.meta.dirname;
const WEB = join(HERE, "..", "web");
const log = (...a) => console.log("[browser-smoke]", ...a);

// --- static file server -----------------------------------------------------
const MIME = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".css": "text/css",
  ".wasm": "application/wasm",
  ".json": "application/json",
};

const ROUTES = [
  [/^\/$/, () => join(WEB, "index.html")],
  [/^\/(app|boot|connstring|storage|idb-keys)\.mjs$/, (m) => join(WEB, `${m[1]}.mjs`)],
  [/^\/xterm\/xterm\.css$/, () => join(WEB, "node_modules/@xterm/xterm/css/xterm.css")],
  [/^\/xterm\/xterm\.js$/, () => join(WEB, "node_modules/@xterm/xterm/lib/xterm.js")],
  [/^\/xterm\/addon-fit\.js$/, () => join(WEB, "node_modules/@xterm/addon-fit/lib/addon-fit.js")],
  [/^\/generated\/([A-Za-z0-9._-]+)$/, (m) => join(HERE, "generated", m[1])],
  [/^\/generated\/interfaces\/([A-Za-z0-9._-]+)$/, (m) => join(HERE, "generated", "interfaces", m[1])],
  [
    /^\/shim\/([A-Za-z0-9._-]+)$/,
    (m) => join(HERE, "node_modules/@bytecodealliance/preview2-shim/dist/browser", m[1]),
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

// --- ws ↔ UDP bridge ---------------------------------------------------------
const liveSessions = new Set();
const wss = new WebSocketServer({ server: httpServer, path: "/ws" });
wss.on("connection", async (sock, req) => {
  const q = new URL(req.url, "http://x").searchParams;
  const delayMs = Math.max(0, Number(q.get("delay") ?? 0) || 0);
  // Independent per-datagram drop probability, each way (0..1) — the
  // M5 measurement knob. Mosh SSP owns recovery; the bridge stays a
  // dumb lossy pipe like the network it stands in for.
  const loss = Math.min(1, Math.max(0, Number(q.get("loss") ?? 0) || 0));

  let srv;
  try {
    srv = await startServer(opts.server);
  } catch (e) {
    sock.close(1011, String(e).slice(0, 100));
    return;
  }
  liveSessions.add(srv);
  log(
    `session: mosh-server :${srv.port} for ws client` +
      `${delayMs ? ` (delay ${delayMs}ms/way)` : ""}${loss ? ` (loss ${loss * 100}%/way)` : ""}`,
  );

  const udp = dgram.createSocket("udp4");
  const later = (fn) => {
    if (loss && Math.random() < loss) return;
    if (delayMs) setTimeout(fn, delayMs);
    else fn();
  };
  udp.on("message", (m) => later(() => sock.readyState === sock.OPEN && sock.send(m)));
  sock.on("message", (m, isBinary) => {
    if (!isBinary) return;
    later(() => udp.send(m, srv.port, "127.0.0.1"));
  });
  sock.on("close", () => {
    udp.close();
    srv.stop();
    liveSessions.delete(srv);
  });

  sock.send(JSON.stringify({ key: srv.key, delayMs, loss }));
});

const stopAll = () => {
  for (const srv of liveSessions) srv.stop();
  liveSessions.clear();
};
process.on("exit", stopAll);

await new Promise((r) => httpServer.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${httpServer.address().port}`;

// --- manual mode --------------------------------------------------------------
if (opts.serve) {
  log(`serving ${base}/ (add ?delay=150 for prediction feel) — ^C to stop`);
  process.on("SIGINT", () => {
    stopAll();
    process.exit(0);
  });
  await new Promise(() => {}); // run until interrupted
}

// --- headless assertions (the M2 gate) -----------------------------------------
const { chromium } = await import("playwright-core");
const { findChrome } = await import("./chrome.mjs");

const hardTimer = setTimeout(() => {
  console.error("FAIL: hard timeout");
  process.exit(2);
}, 90_000);

const executablePath = await findChrome();
if (!executablePath) throw new Error("no Chromium found; set CHROME_PATH");

const browser = await chromium.launch({
  executablePath,
  headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

let failed = null;
try {
  const page = await browser.newPage();
  page.on("pageerror", (e) => console.error(`[page error] ${e.message}`));
  page.on("console", (m) => {
    if (m.type() === "error") console.error(`[page console] ${m.text()}`);
  });

  const text = () => page.evaluate(() => window.__mosh?.text?.() ?? "");
  const waitText = async (re, label, timeoutMs = 20_000) => {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const failure = await page.evaluate(() => window.__mosh?.failure ?? null);
      if (failure) throw new Error(`page failure while waiting for ${label}: ${failure}`);
      const t = await text();
      if (re.test(t)) return;
      if (Date.now() > deadline)
        throw new Error(`timeout waiting for ${label} (${re})\n--- screen ---\n${t}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  };

  // Phase 1: engine + prompt through the full browser stack.
  await page.goto(`${base}/`);
  await waitText(/\$/, "shell prompt");
  log("prompt OK");

  // Phase 2: echo round-trip (typed text never contains the marker).
  await page.keyboard.type("echo m0sh_$(printf web)_ok", { delay: 5 });
  await page.keyboard.press("Enter");
  await waitText(/m0sh_web_ok/, "echo marker");
  log("echo round-trip OK");

  // Phase 3: resize propagates browser → engine → server pty.
  await page.evaluate(() => window.__mosh.resize(100, 30));
  await page.keyboard.type("stty size", { delay: 5 });
  await page.keyboard.press("Enter");
  await waitText(/30 100/, "stty size after resize");
  log("resize OK");

  // Phase 4: fresh session behind an artificially slow bridge; the
  // prediction overlay must paint keystrokes before any server echo
  // can arrive (one-way delay × 2 = RTT; typing finishes well before).
  const delayMs = Number(opts.delay);
  await page.goto(`${base}/?delay=${delayMs}`);
  await waitText(/\$/, "shell prompt (delayed bridge)", 30_000);

  const activeSeen = page.evaluate(
    () =>
      new Promise((resolve) => {
        const t0 = Date.now();
        const iv = setInterval(() => {
          if (window.__mosh?.stats?.().predictorActive) {
            clearInterval(iv);
            resolve(true);
          } else if (Date.now() - t0 > 4000) {
            clearInterval(iv);
            resolve(false);
          }
        }, 10);
      }),
  );
  const typeStarted = Date.now();
  await page.keyboard.type("predictme", { delay: 10 });
  const paintedAt = Date.now() - typeStarted;
  const screenNow = await text();
  const underlined = await page.evaluate(() => window.__mosh.underlinedCells());
  if (paintedAt < 2 * delayMs && !screenNow.includes("predictme")) {
    throw new Error(
      `prediction did not paint locally (sampled ${paintedAt}ms after typing began, ` +
        `RTT ${2 * delayMs}ms)\n--- screen ---\n${screenNow}`,
    );
  }
  if (!(await activeSeen)) throw new Error("predictorActive never became true while typing");
  log(
    `prediction OK: painted locally ${paintedAt}ms after first keystroke ` +
      `(RTT ${2 * delayMs}ms), ${underlined} underlined speculative cells`,
  );

  await page.keyboard.press("Enter");
  await page.screenshot({ path: "/tmp/opencode/m2-smoke.png" });
  log("screenshot: /tmp/opencode/m2-smoke.png");
} catch (e) {
  failed = e;
} finally {
  await browser.close();
  stopAll();
  httpServer.close();
  clearTimeout(hardTimer);
}

if (failed) {
  console.error("FAIL:", failed.message);
  process.exit(1);
}
console.log("browser smoke (M2 gate): OK");
process.exit(0);
