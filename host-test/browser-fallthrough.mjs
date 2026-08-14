// Browser fall-through gate: when a session cannot be resumed, the
// page must fall through to a FRESH session -- quickly and silently.
//
// The scenario a resume cannot bridge: the LISTENER restarts. Its
// session registry is memory, so the parked session is simply gone;
// the client's resume is refused ("unknown session"), the component
// classifies the death as `lost` (terminal.wit's close-kind), and the
// page -- holding a pinned host key and a silent credential -- starts
// a new session on the same parameters by itself. The terminal keeps
// its scrollback, gains a dim `[wosh]` divider, and the connect dialog
// never opens.
//
// What has to line up for the silence, all of it real behavior:
//   - the host-key pin (remember-checkbox, opted into at first
//     connect) answers the TOFU gate without a prompt;
//   - pairing enrollment (this browser presented a valid token once)
//     lets the STALE connstring keep working across the restart's
//     token rotation;
//   - the default auto method resolves to the browser key, which
//     signs without a human.
//
// Environment (the `just browser-fallthrough` recipe supplies it):
//   WOSH_CONNSTRING       the listener's connection string   (required)
//   WOSH_AUTHORIZED_KEYS  sshd's authorized_keys path        (required)
//   WOSH_STOP_CMD         shell command: stop the listener   (required)
//   WOSH_START_CMD        shell command: start it again,
//                         same identity dir                  (required)
//   WOSH_USER             login user (default: $USER)
//   WOSH_HTTP_PORT        static server port (default: 8132)
import { chromium } from "playwright-core";
import { execSync } from "node:child_process";
import { appendFileSync, existsSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname } from "node:path";

const ROOT = new URL("../out/", import.meta.url).pathname;
const PORT = Number(process.env.WOSH_HTTP_PORT ?? 8132);
const CONNSTRING = process.env.WOSH_CONNSTRING;
const AUTH_KEYS = process.env.WOSH_AUTHORIZED_KEYS;
const STOP_CMD = process.env.WOSH_STOP_CMD;
const START_CMD = process.env.WOSH_START_CMD;
const USER = process.env.WOSH_USER ?? process.env.USER;
if (!CONNSTRING || !AUTH_KEYS || !STOP_CMD || !START_CMD || !USER) {
  console.error("need WOSH_CONNSTRING, WOSH_AUTHORIZED_KEYS, WOSH_STOP_CMD, WOSH_START_CMD; run via `just browser-fallthrough`");
  process.exit(2);
}

const MIME = { ".html": "text/html", ".mjs": "text/javascript", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm" };
const server = createServer(async (req, res) => {
  try {
    const p = decodeURIComponent(new URL(req.url, "http://x").pathname);
    const f = join(ROOT, p === "/" ? "index.html" : p);
    const b = await readFile(f);
    res.writeHead(200, { "content-type": MIME[extname(f)] ?? "application/octet-stream", "cache-control": "no-store" });
    res.end(b);
  } catch { res.writeHead(404).end(); }
});
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));

function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const glob = `${process.env.HOME}/.cache/ms-playwright`;
  const dirs = readdirSync(glob).filter((d) => d.startsWith("chromium-")).sort();
  for (const d of dirs.reverse()) {
    const p = join(glob, d, "chrome-linux", "chrome");
    if (existsSync(p)) return p;
  }
  throw new Error("no Chromium found; set CHROME_PATH");
}

const t0 = Date.now();
const say = (m) => console.log(`[${String(Date.now() - t0).padStart(6)}ms] ${m}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = await chromium.launch({ executablePath: findChrome(), args: ["--no-sandbox"] });
let failed = false;
const fail = (m) => { console.error(`FAIL: ${m}`); failed = true; };

try {
  const page = await browser.newPage();
  const pageErrors = [];
  page.on("pageerror", (e) => pageErrors.push(String(e)));

  const screenText = () => page.evaluate(() => {
    const buf = window.__wosh.term?.buffer.active;
    if (!buf) return "";
    let t = "";
    for (let i = 0; i < buf.length; i++) t += buf.getLine(i)?.translateToString(true) + "\n";
    return t;
  });
  const screenHas = (m, count) => page.waitForFunction(([mm, c]) => {
    const buf = window.__wosh.term?.buffer.active;
    if (!buf) return false;
    let t = "";
    for (let i = 0; i < buf.length; i++) t += buf.getLine(i)?.translateToString(true) + "\n";
    return t.split(mm).length - 1 >= c;
  }, [m, count], { timeout: 90_000 });

  await page.goto(`http://127.0.0.1:${PORT}/#${CONNSTRING}`, { waitUntil: "load" });
  await page.waitForSelector("#panel button", { timeout: 15_000 });
  await page.click("text=show this browser's public key");
  const line = (await page.locator("#panel .key code").first().textContent({ timeout: 120_000 })).trim();
  appendFileSync(AUTH_KEYS, line + "\n");
  await page.fill("#panel input[placeholder='user']", USER);
  await page.click("#panel button:has-text('connect')");
  await page.locator("#panel .confirm code").first().textContent({ timeout: 60_000 });
  // Opt into the pin: the silent fall-through depends on it (an
  // unpinned key would need the TOFU prompt, which the page correctly
  // refuses to auto-answer).
  await page.check("#panel #remember-hostkey");
  await page.click("#panel .confirm button:has-text('yes, connect')");
  await page.waitForFunction((u) => document.getElementById("status")?.textContent === `connected as ${u}`,
    USER, { timeout: 60_000 });
  say("[1] connected, host key pinned");

  await page.click(".xterm-screen");
  await page.keyboard.type("echo MARK_BEFORE\n", { delay: 10 });
  await screenHas("MARK_BEFORE", 2);
  say("[2] pre-restart round trip");

  // Restart the listener: same identity dir (same endpoint id, so the
  // pin and the enrollment keep meaning something), fresh process --
  // which is exactly what makes the parked session unrecoverable.
  execSync(STOP_CMD, { stdio: "inherit" });
  await sleep(1500); // the identity dir's flock releases as it exits
  execSync(START_CMD, { stdio: "inherit" });
  say("[3] listener restarted (registry gone; resume can only be refused)");

  // The whole ladder has to run unattended from here: liveness verdict
  // (or a loud transport error), resume attempts riding the backoff
  // until the listener is back, the refusal, the `lost` classification,
  // and the page's own silent fresh connect. The divider is the fresh
  // path's signature.
  await screenHas("starting a new session", 1);
  say("[4] the page fell through: divider printed");

  await page.waitForFunction((u) => document.getElementById("status")?.textContent === `connected as ${u}`,
    USER, { timeout: 90_000 });
  say("[5] fresh session connected, silently");

  if (await page.evaluate(() => document.getElementById("panel")?.open)) {
    fail("the connect dialog opened: the fall-through was not silent");
  }

  await page.click(".xterm-screen");
  await page.keyboard.type("echo MARK_AFTER\n", { delay: 10 });
  await screenHas("MARK_AFTER", 2);
  say("[6] post-fallthrough round trip");

  const text = await screenText();
  if (!text.includes("MARK_BEFORE")) {
    fail("pre-restart scrollback is gone: the page reloaded instead of reconnecting");
  }

  if (pageErrors.length) fail(`page errors:\n  ${pageErrors.join("\n  ")}`);
  if (!failed) {
    console.log("\nBROWSER FALLTHROUGH PASS: an unresumable session (listener restart) fell through" +
      " to a fresh one -- pinned key, enrolled pairing, silent auth, divider in the scrollback");
  }
} catch (e) {
  fail(String(e?.stack ?? e));
} finally {
  await browser.close();
  server.close();
}
process.exitCode = failed ? 1 : 0;
