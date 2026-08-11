// M2 browser smoke: xterm.js + the engine component (runtime-linked by
// deltic, in-page) in a real (headless) browser, datagrams over a
// throwaway ws↔UDP bridge.
//
//   node browser-smoke.mjs             # headless assertions (the M2 gate)
//   node browser-smoke.mjs --serve     # manual mode: prints a URL, ^C to stop
//
// (DELTIC_TRANSLATOR must point at the pinned translator shim; the
// `just m2` / `just web-serve` recipes fetch it and set the env.)
//
// Bridge contract (deliberately dumb, replaced by iroh from M3/M5):
// each ws connection spawns its own mosh-server; the first frame is a
// JSON hello {key, delayMs}; afterwards every binary frame is exactly
// one mosh datagram. ?delay=N adds N ms artificial latency each way
// (prediction observation; keep RTT well under the predictor's 500 ms
// expiry).
//
// Serves: / and the page modules from ../web, /xterm/* from web's
// node_modules, and /dist/* — the deltic page bundle (just web-bundle)
// plus the wasm artifacts (engine, composed client, translator shim).

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
  [/^\/(manifest\.json|icons\/[a-z0-9.-]+\.png)$/, (m) => join(WEB, m[1])],
  [/^\/(app|boot|connstring|storage|idb-keys|prf-wrap|passkey|mobile|overlay)\.mjs$/, (m) => join(WEB, `${m[1]}.mjs`)],
  [/^\/xterm\/xterm\.css$/, () => join(WEB, "node_modules/@xterm/xterm/css/xterm.css")],
  [/^\/xterm\/xterm\.js$/, () => join(WEB, "node_modules/@xterm/xterm/lib/xterm.js")],
  [/^\/xterm\/addon-fit\.js$/, () => join(WEB, "node_modules/@xterm/addon-fit/lib/addon-fit.js")],
  [/^\/dist\/deltic\.js$/, () => join(WEB, "dist/deltic.js")],
  [/^\/dist\/main\.wasm$/, () => join(HERE, "../engine-go/main.wasm")],
  [/^\/dist\/composed-client\.wasm$/, () => join(HERE, "../client-core/composed-client.wasm")],
  [
    /^\/dist\/deltic-translator-shim\.wasm$/,
    () => {
      if (!process.env.DELTIC_TRANSLATOR) {
        throw new Error("DELTIC_TRANSLATOR unset (run via the justfile recipes)");
      }
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
  let closed = false;
  const later = (fn) => {
    if (loss && Math.random() < loss) return;
    // Delayed sends may outlive the sockets (page navigations close
    // mid-flight); a closed bridge drops like the lossy pipe it is.
    if (delayMs) setTimeout(() => closed || fn(), delayMs);
    else closed || fn();
  };
  udp.on("message", (m) => later(() => sock.readyState === sock.OPEN && sock.send(m)));
  sock.on("message", (m, isBinary) => {
    if (!isBinary) return;
    later(() => udp.send(m, srv.port, "127.0.0.1"));
  });
  sock.on("close", () => {
    closed = true;
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
}, 120_000);

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
  page.on("pageerror", (e) => console.error(`[page error] ${e.stack ?? e.message}`));
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
  // Poll-until for non-screen state (DOM classes, focus, layout):
  // input events and Runtime.evaluate travel different pipelines into
  // the renderer, so a single sample right after tap()/type() races
  // the page's own handler (observed as CI-only flakes).
  const until = async (fn, label, timeoutMs = 5_000) => {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      if (await fn()) return;
      if (Date.now() > deadline) throw new Error(`timeout waiting for ${label}`);
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
        const iv = setInterval(async () => {
          // stats() is Promise-shaped under deltic.
          const s = await window.__mosh?.stats?.();
          if (s?.predictorActive) {
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
  // The proof of LOCAL paint is the full string appearing strictly
  // before the earliest possible server echo (typeStarted + RTT).
  // Poll up to that window instead of sampling once: the paint of the
  // final keystroke races a single immediate evaluate on slow runners
  // (observed in CI: 8 of 9 chars at 108 ms). The assert below keeps
  // the original lenience — if the window is already spent, locality
  // is unprovable this run and only predictorActive is asserted.
  let screenNow = await text();
  let paintedAt = Date.now() - typeStarted;
  while (!screenNow.includes("predictme") && Date.now() - typeStarted < 2 * delayMs - 40) {
    await new Promise((r) => setTimeout(r, 10));
    screenNow = await text();
    paintedAt = Date.now() - typeStarted;
  }
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

  // Phase 5: mobile UX (web/mobile.mjs) on a touch-emulated context —
  // (pointer: coarse) shows the extra-keys bar; keys inject through
  // the same onData path as typing (cat -v renders the injected ESC as
  // ^[), sticky Ctrl transforms the NEXT soft-keyboard key (Ctrl+C
  // kills cat), ↑ recalls history, ⌨ dismisses the keyboard focus.
  // The desktop context above must keep the bar hidden.
  if (await page.$eval("#keys", (el) => el.offsetHeight > 0)) {
    throw new Error("extra-keys bar visible on a fine-pointer context");
  }
  const mctx = await browser.newContext({
    viewport: { width: 390, height: 844 },
    hasTouch: true,
    isMobile: true,
  });
  const mpage = await mctx.newPage();
  mpage.on("pageerror", (e) => console.error(`[mobile page error] ${e.stack ?? e.message}`));
  const mtext = () => mpage.evaluate(() => window.__mosh?.text?.() ?? "");
  const mwait = async (pred, label, timeoutMs = 20_000) => {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const failure = await mpage.evaluate(() => window.__mosh?.failure ?? null);
      if (failure) throw new Error(`mobile page failure while waiting for ${label}: ${failure}`);
      const t = await mtext();
      if (pred(t)) return;
      if (Date.now() > deadline)
        throw new Error(`timeout waiting for ${label}\n--- screen ---\n${t}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  };

  await mpage.goto(`${base}/`);
  await mwait((t) => /\$/.test(t), "shell prompt (mobile)");
  await until(
    () => mpage.$eval("#keys", (el) => el.offsetHeight > 0),
    "extra-keys bar on a coarse-pointer context",
  );

  await mpage.keyboard.type("cat -v", { delay: 5 });
  await mpage.keyboard.press("Enter");
  await mpage.tap('#keys button:text-is("esc")');
  await mpage.keyboard.press("Enter"); // cat is line-buffered; flush
  await mwait((t) => t.includes("^["), "bar esc rendered by cat -v");
  log("mobile bar esc OK");

  await mpage.tap('#keys button:text-is("ctrl")');
  await until(
    () => mpage.$eval('#keys button:text-is("ctrl")', (el) => el.classList.contains("armed")),
    "ctrl to arm",
  );
  await mpage.keyboard.type("c"); // sticky Ctrl ⇒ 0x03 ⇒ SIGINT kills cat
  await mwait((t) => t.includes("^C"), "sticky ctrl+c killed cat");
  await until(
    async () =>
      !(await mpage.$eval('#keys button:text-is("ctrl")', (el) => el.classList.contains("armed"))),
    "ctrl to disarm (one-shot)",
  );
  log("mobile sticky ctrl OK");

  await mpage.tap('#keys button:text-is("↑")');
  await mwait((t) => {
    const lines = t.trimEnd().split("\n");
    return /\$\s*cat -v\s*$/.test(lines[lines.length - 1] ?? "");
  }, "↑ recalled history");
  log("mobile arrow history OK");

  const focused = () => mpage.evaluate(() => document.activeElement === window.__mosh.term.textarea);
  await until(focused, "terminal focus before ⌨ toggle");
  await mpage.tap('#keys button:text-is("⌨")');
  await until(async () => !(await focused()), "⌨ to blur the terminal");
  await mpage.tap('#keys button:text-is("⌨")');
  await until(focused, "⌨ to refocus the terminal");
  log("mobile ⌨ toggle OK");

  await mpage.screenshot({ path: "/tmp/opencode/m2-smoke-mobile.png" });
  log("screenshot: /tmp/opencode/m2-smoke-mobile.png");
  await mctx.close();
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
