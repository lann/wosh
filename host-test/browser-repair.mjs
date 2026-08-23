// Browser re-pair gate: a saved connection card whose ENROLLMENT is
// gone must be recoverable from the page, with the token the listener
// prints -- not left tapping a card that refuses identically forever.
//
// The scenario: a card carries no token by design (boot.mjs rebuilds a
// TOKENLESS connstring from the endpoint id and relay), so it works
// only while the listener still remembers this browser. Wipe that
// memory -- `wosh-data/paired` deleted, or a listener that ran with
// --no-token and came back with one -- and every tap on the card ends
// at the tunnel handshake with a refusal. The remedy exists (re-pair
// with the token or link the listener prints at startup) and this gate
// is where the page has to offer it.
//
// What it asserts:
//   1. a normal connect enrols this browser and leaves a card;
//   2. after the listener restarts WITHOUT the enrollment (same
//      identity, so the card still points at it) and WITH a rotated
//      token, tapping the card raises the re-pair SHEET -- not a raw
//      notice with a protocol string in it;
//   3. typing the new 32-hex-character token into that sheet
//      reconnects -- which also proves boot.mjs's tokened connstring
//      encoder agrees with the Rust decoder byte for byte, since a
//      mis-encoded token is indistinguishable from a wrong one;
//   4. the listener logs `paired (valid token`: the device is enrolled
//      again, so the saved card works unaided from here.
//
// Environment (the `just browser-repair` recipe supplies it):
//   WOSH_CONNSTRING       the listener's connection string   (required)
//   WOSH_AUTHORIZED_KEYS  sshd's authorized_keys path        (required)
//   WOSH_STOP_CMD         shell command: stop the listener   (required)
//   WOSH_START_CMD        shell command: start it again,
//                         same identity dir                  (required)
//   WOSH_PAIRED_FILE      the enrollment file to delete
//                         (<identity-dir>/paired)            (required)
//   WOSH_LOG              the listener's log file            (required)
//   WOSH_USER             login user (default: $USER)
//   WOSH_HTTP_PORT        static server port (default: 8137)
import { chromium } from "playwright-core";
import { execSync } from "node:child_process";
import { appendFileSync, existsSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname } from "node:path";

const ROOT = new URL("../out/", import.meta.url).pathname;
const PORT = Number(process.env.WOSH_HTTP_PORT ?? 8137);
const CONNSTRING = process.env.WOSH_CONNSTRING;
const AUTH_KEYS = process.env.WOSH_AUTHORIZED_KEYS;
const STOP_CMD = process.env.WOSH_STOP_CMD;
const START_CMD = process.env.WOSH_START_CMD;
const PAIRED_FILE = process.env.WOSH_PAIRED_FILE;
const LOG = process.env.WOSH_LOG;
const USER = process.env.WOSH_USER ?? process.env.USER;
if (!CONNSTRING || !AUTH_KEYS || !STOP_CMD || !START_CMD || !PAIRED_FILE || !LOG || !USER) {
  console.error(
    "need WOSH_CONNSTRING, WOSH_AUTHORIZED_KEYS, WOSH_STOP_CMD, WOSH_START_CMD, " +
      "WOSH_PAIRED_FILE, WOSH_LOG; run via `just browser-repair`",
  );
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
    // Chrome for Testing unpacks as chrome-linux64/; older Chromium
    // builds as chrome-linux/.
    for (const sub of ["chrome-linux64", "chrome-linux"]) {
      const p = join(glob, d, sub, "chrome");
      if (existsSync(p)) return p;
    }
  }
  throw new Error("no Chromium found; set CHROME_PATH");
}

const t0 = Date.now();
const say = (m) => console.log(`[${String(Date.now() - t0).padStart(6)}ms] ${m}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/// The listener prints `ready; target …(pairing token required:
/// <32 hex>)` once per start, so the LAST such line is the live
/// token. Polled: the line lands a moment after the process does.
async function currentToken(after) {
  for (let i = 0; i < 100; i++) {
    const log = existsSync(LOG) ? readFileSync(LOG, "utf8") : "";
    const all = [...log.matchAll(/pairing token required: ([A-Z2-79]{26})/g)].map((m) => m[1]);
    const last = all[all.length - 1];
    if (last && last !== after) return last;
    await sleep(200);
  }
  throw new Error("the restarted listener never printed a new pairing token");
}

const browser = await chromium.launch({ executablePath: findChrome(), args: ["--no-sandbox"] });
let failed = false;
const fail = (m) => { console.error(`FAIL: ${m}`); failed = true; };

try {
  const page = await browser.newPage();
  const pageErrors = [];
  page.on("pageerror", (e) => pageErrors.push(String(e)));
  const waitConnected = () =>
    page.waitForFunction((u) => document.getElementById("status")?.textContent === `connected as ${u}`,
      USER, { timeout: 90_000 });

  // --- 1: an ordinary connect, which enrols this browser -------------
  await page.goto(`http://127.0.0.1:${PORT}/#${CONNSTRING}`, { waitUntil: "load" });
  await page.waitForSelector("#sheet[data-ask='connect'] input[placeholder='user']", { timeout: 15_000 });
  const line = (await page.evaluate(async () => {
    const { identity } = await import("./app.mjs");
    return await identity();
  })).trim();
  appendFileSync(AUTH_KEYS, line + "\n");
  await page.fill("#sheet input[placeholder='user']", USER);
  await page.click("#sheet button:text-is('connect')");
  await page.locator("#sheet .confirm code.fp").first().textContent({ timeout: 60_000 });
  // Pin the key: this gate is about pairing, and an unpinned key would
  // put a TOFU ask in front of every dial below.
  await page.check("#sheet #remember-hostkey");
  await page.click("#sheet button:has-text('it matches')");
  await waitConnected();
  say("[1] connected: this browser is enrolled and a card is saved");

  const tokenBefore = (await currentToken(null));

  // --- 2: the listener forgets this browser --------------------------
  // Identity kept (so the saved card still names this listener), the
  // ENROLLMENT deleted, the token rotated by the restart. This is the
  // wiped-data-dir / --no-token-then-token situation exactly.
  execSync(STOP_CMD, { stdio: "inherit" });
  await sleep(1500); // the identity dir's flock releases as it exits
  rmSync(PAIRED_FILE, { force: true });
  execSync(START_CMD, { stdio: "inherit" });
  const token = await currentToken(tokenBefore);
  await sleep(6000); // the relay registration the card is about to dial
  say("[2] listener back: same identity, no enrollment, rotated token");

  // --- 3: the card cannot connect, and says what to do ---------------
  await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: "load" });
  await page.waitForSelector("#home .histrow", { timeout: 15_000 });
  await page.click("#home .histrow");
  await page.waitForSelector("#sheet[data-ask='repair']", { timeout: 90_000 });
  const notice = await page.evaluate(() => document.getElementById("home")?.textContent ?? "");
  if (notice.includes("pairing-required")) {
    fail("the raw refusal code leaked into the home notice");
  }
  say("[3] the re-pair sheet appeared instead of a dead-end notice");

  // A wrong shape must be refused inline, with the sheet still open:
  // the field is the only way out of this state, so it may not eat
  // input silently.
  await page.fill("#sheet[data-ask='repair'] input", "not-a-token");
  await page.click("#sheet button:has-text('re-pair and connect')");
  await page.waitForSelector("#sheet[data-ask='repair'] .notice:not(:empty)", { timeout: 5_000 });
  if (!(await page.isVisible("#sheet[data-ask='repair']"))) {
    fail("a bad token closed the sheet");
  }
  say("[4] a malformed token is refused inline, sheet still open");

  // --- 5: the real token, as the listener printed it -----------------
  await page.fill("#sheet[data-ask='repair'] input", token);
  await page.click("#sheet button:has-text('re-pair and connect')");
  await waitConnected();
  say("[5] re-paired and connected with the printed token");

  // The listener's own word for it: the tokened connstring this page
  // built decoded, its proof verified, the device enrolled again.
  let paired = false;
  for (let i = 0; i < 50; i++) {
    const log = readFileSync(LOG, "utf8");
    // Two runs share this log; the enrollment must be from THIS one,
    // i.e. after the token line we typed.
    const at = log.lastIndexOf(token);
    if (at >= 0 && log.slice(at).includes("paired (valid token")) { paired = true; break; }
    await sleep(200);
  }
  if (!paired) fail("the listener never logged `paired (valid token` after the re-pair");
  else say("[6] the listener enrolled this browser again");

  if (pageErrors.length) fail(`page errors:\n  ${pageErrors.join("\n  ")}`);
  if (!failed) {
    console.log("\nBROWSER REPAIR PASS: a card whose enrollment was wiped recovered from the" +
      " page with the listener's printed token (and the JS tokened connstring decoded in Rust)");
  }
} catch (e) {
  fail(String(e?.stack ?? e));
} finally {
  await browser.close();
  server.close();
}
process.exitCode = failed ? 1 : 0;
