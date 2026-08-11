// The M6 browser ceremony E2E (the leg finding 24 unblocked): the full
// passkey lifecycle from the REAL page against a REAL webauthn-rs RP —
// register → PRF-wrapped escrow → detach → page reload (fresh client
// process, localStorage survives) → assertion-gated reattach: the
// pre-detach screen resyncs, the engine resumes above the escrowed
// floor, and the arm is re-sealed at floor+FLOOR_JUMP and re-escrowed.
//
//   node passkey-browser-e2e.mjs        (via `just m6-browser`)
//
// Topology: iroh-relay --dev (:3353) ← native proxy (--personal,
// --rp-origin http://localhost:3354) ← relay websocket ← the page's
// composed client. WebAuthn needs a valid RP ID, so the page is served
// at http://localhost:3354 (Chromium resolver-mapped to 127.0.0.1) and
// ceremonies run against a CDP virtual authenticator (ctap2.1, hasPrf,
// resident keys — the web-tests phase-3 configuration).
//
// Negative ceremony paths (bogus session, garbage assertion) are the
// native M6 gate's territory (passkey-e2e); this leg proves the
// browser-side integration positively.

import http from "node:http";
import { readFile, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { spawn } from "node:child_process";

const HERE = import.meta.dirname;
const WEB = join(HERE, "..", "web");
const RELAY_PORT = 3353;
const PAGE_PORT = 3354;
const TOKEN = "m6-browser-token";
const CONNECT_ATTEMPTS = 8;

const log = (...a) => console.log("[m6-browser]", ...a);

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

// --- static server (bound FIRST: the proxy's --rp-origin names it) -----------
const MIME = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".css": "text/css",
  ".wasm": "application/wasm",
};
const ROUTES = [
  [/^\/$/, () => join(WEB, "index.html")],
  [
    /^\/(app|boot|connstring|storage|idb-keys|prf-wrap|passkey)\.mjs$/,
    (m) => join(WEB, `${m[1]}.mjs`),
  ],
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
await new Promise((r) => httpServer.listen(PAGE_PORT, "127.0.0.1", r));
const base = `http://localhost:${PAGE_PORT}`;

// --- relay + proxy -----------------------------------------------------------
const dir = await mkdtemp(join(tmpdir(), "wosh-m6-browser-"));
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
    "--personal",
    "--shell",
    "bash --noprofile --norc -i",
    "--state-dir",
    join(dir, "state"),
    "--component",
    join(HERE, "../proxy/composed-proxy.wasm"),
    // The RP: id must be the page's host, origin its exact origin.
    "--rp-id",
    "localhost",
    "--rp-origin",
    base,
  ],
  { stdio: ["ignore", "pipe", "inherit"], detached: true },
);
children.push(proxy);

let proxyLog = "";
proxy.stdout.on("data", (d) => {
  proxyLog += d;
});
const proxySaw = async (re, label, timeoutMs = 10_000) => {
  const deadline = Date.now() + timeoutMs;
  while (!re.test(proxyLog)) {
    if (Date.now() > deadline) {
      throw new Error(`proxy log never showed ${label} (${re})\n--- proxy ---\n${proxyLog}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
};

const connstring = await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("proxy connstring timeout")), 20_000);
  const poll = setInterval(() => {
    const m = proxyLog.match(/connstring: (\S+)/);
    if (m) {
      clearTimeout(timer);
      clearInterval(poll);
      resolve(m[1]);
    }
  }, 50);
  proxy.on("exit", () => reject(new Error("proxy exited before connstring")));
});
log(`proxy up: ${connstring.slice(0, 24)}…`);

// --- the browser -------------------------------------------------------------
const { chromium } = await import("playwright-core");
const { findChrome } = await import("./chrome.mjs");
const executablePath = await findChrome();
if (!executablePath) throw new Error("no Chromium found; set CHROME_PATH");

const hardTimer = setTimeout(() => {
  console.error("FAIL: hard timeout");
  console.error(`--- proxy ---\n${proxyLog}`);
  process.exit(2);
}, 300_000);

const browser = await chromium.launch({
  executablePath,
  headless: true,
  args: [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    // "localhost" is a valid RP ID; keep it on our v4 listener.
    "--host-resolver-rules=MAP localhost 127.0.0.1",
  ],
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

/** Wait until the boot panel reports idle with `notice` empty or matching. */
const waitNotice = async (page, re, label, timeoutMs = 30_000) => {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const notice = await page.evaluate(() => window.__moshBoot?.notice ?? "");
    if (re.test(notice)) return notice;
    if (/failed/.test(notice)) throw new Error(`${label}: ${notice}`);
    if (Date.now() > deadline) throw new Error(`${label}: notice stayed "${notice}"`);
    await new Promise((r) => setTimeout(r, 100));
  }
};

/** A fresh page with the virtual authenticator attached (ceremonies
 * need it before any WebAuthn call; it survives same-page goto()s). */
async function newAuthPage(context) {
  const page = await context.newPage();
  page.on("console", (m) => {
    if (m.type() === "error") console.error(`[page console] ${m.text()}`);
  });
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: true,
      automaticPresenceSimulation: true,
    },
  });
  return page;
}

/** One connect attempt; resolves to the live page (RefCell hazard: see
 * browser-e2e.mjs — a trapped handshake gets a fresh page). */
async function connectOnce(context, fragment, label) {
  const page = await newAuthPage(context);
  await page.goto(`${base}/#${fragment}`);
  await page.waitForSelector("#connect-pending-btn", { timeout: 10_000 });
  await page.click("#connect-pending-btn");
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

  // Phase 1: connect (bounded retries), marker on the screen.
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

  await waitText(page, /\$/, "shell prompt");
  await page.click("#term");
  await page.keyboard.type("echo persist_$(printf mark)er_ok", { delay: 5 });
  await page.keyboard.press("Enter");
  await waitText(page, /persist_marker_ok/, "pre-detach marker");
  log("prompt + marker OK");

  // Phase 2: persist (registration ceremony + PRF escrow) via the
  // panel button — the exact path a user clicks.
  await page.click("#persist-btn");
  await waitNotice(page, /persistent \(passkey-gated reattach\)/, "persist");
  await proxySaw(/is now persistent \(passkey-bound\)/, "escrow stored");
  const stored = await page.evaluate(() => {
    const s = window.__moshBoot.state.sessions[0];
    return s && { sessionId: s.sessionId, arm: Object.keys(s.key)[0], floor: s.key.prf?.seqFloor };
  });
  if (!stored || stored.arm !== "prf") throw new Error(`bad stored session: ${JSON.stringify(stored)}`);
  log(`persisted: session ${stored.sessionId}, prf arm, floor=${stored.floor}`);

  // Phase 3: detach; the proxy must keep the server.
  await page.evaluate(() => window.__mosh.detach());
  await proxySaw(/kept \(persistent\)/, "server kept on detach");
  log("detach OK (server kept)");

  // Phase 4: reload — a fresh client process; localStorage (and the
  // virtual authenticator's resident credential) survive.
  await page.goto(base);
  await page.waitForSelector(".reattach-btn", { timeout: 10_000 });
  await page.fill(".boot-proxy .token-input", TOKEN);
  await page.click(".reattach-btn");
  const reattachDeadline = Date.now() + 60_000;
  for (;;) {
    const mode = await page.evaluate(() => window.__mosh?.mode ?? null);
    if (mode === "iroh") break;
    const notice = await page.evaluate(() => window.__moshBoot?.notice ?? "");
    if (notice.startsWith("reattach failed")) throw new Error(notice);
    if (Date.now() > reattachDeadline) throw new Error("reattach: neither session nor failure in 60s");
    await new Promise((r) => setTimeout(r, 100));
  }
  log("reattached (assertion-gated)");

  // The SAME session: the pre-detach marker resyncs without typing.
  await waitText(page, /persist_marker_ok/, "pre-detach marker resync");
  log("pre-detach screen state resynced");

  await page.click("#term");
  await page.keyboard.type("echo re_$(printf atta)ch_ok", { delay: 5 });
  await page.keyboard.press("Enter");
  await waitText(page, /re_attach_ok/, "post-reattach echo");
  log("post-reattach echo OK");

  // Phase 5: the floor-jump re-escrow happened — on the proxy (a
  // second escrow write) and locally (arm floor jumped ≥ 2^32).
  const escrows = (proxyLog.match(/is now persistent \(passkey-bound\)/g) ?? []).length;
  if (escrows < 2) throw new Error(`expected a re-escrow (saw ${escrows} escrow write(s))`);
  const refreshed = await page.evaluate(() => window.__moshBoot.state.sessions[0].key.prf.seqFloor);
  if (!(refreshed >= 2 ** 32)) {
    throw new Error(`stored floor did not jump (${refreshed})`);
  }
  log(`re-escrowed at jumped floor ${refreshed}`);

  // Phase 6: detach again — still persistent, still kept.
  await page.evaluate(() => window.__mosh.detach());
  const kept = () => (proxyLog.match(/kept \(persistent\)/g) ?? []).length;
  const keptDeadline = Date.now() + 10_000;
  while (kept() < 2 && Date.now() < keptDeadline) await new Promise((r) => setTimeout(r, 100));
  if (kept() < 2) throw new Error("proxy did not keep the session on the second detach");
  log("second detach OK (still persistent)");
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
  console.error("FAIL:", failed.message ?? failed);
  console.error(`--- proxy ---\n${proxyLog}`);
  process.exit(1);
}
console.log("passkey browser E2E (M6 ceremony leg): OK");
process.exit(0);
