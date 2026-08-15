// Browser resume gate: a live session must survive a relay restart.
//
// This is the roaming/resilience story end to end, and it exercises
// every moving part the tunnel-v2 work added: the client's transport
// death detection, its endpoint REBIND (an iroh endpoint shares fate
// with its relay websocket), the resume backoff, the listener's own
// accept-loop rebind and re-registration under the same identity, the
// parked session's grace, and the offset-exchange replay. The page
// must never notice: status stays "connected as ...", no dialog
// reopens, and a post-restart keystroke round-trips.
//
// Environment (the `just browser-resume` recipe supplies it):
//   WOSH_CONNSTRING       the listener's connection string   (required)
//   WOSH_AUTHORIZED_KEYS  sshd's authorized_keys path        (required)
//   WOSH_RELAY_BIN        path to the iroh-relay binary      (required)
//   WOSH_USER             login user (default: $USER)
//   WOSH_HTTP_PORT        static server port (default: 8129)
import { chromium } from "playwright-core";
import { execSync, spawn } from "node:child_process";
import { appendFileSync, existsSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname } from "node:path";

const ROOT = new URL("../out/", import.meta.url).pathname;
const PORT = Number(process.env.WOSH_HTTP_PORT ?? 8129);
const CONNSTRING = process.env.WOSH_CONNSTRING;
const AUTH_KEYS = process.env.WOSH_AUTHORIZED_KEYS;
const RELAY_BIN = process.env.WOSH_RELAY_BIN;
const USER = process.env.WOSH_USER ?? process.env.USER;
if (!CONNSTRING || !AUTH_KEYS || !RELAY_BIN || !USER) {
  console.error("need WOSH_CONNSTRING, WOSH_AUTHORIZED_KEYS, WOSH_RELAY_BIN; run via `just browser-resume`");
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

const browser = await chromium.launch({ executablePath: findChrome(), args: ["--no-sandbox"] });
let failed = false;
const fail = (m) => { console.error(`FAIL: ${m}`); failed = true; };

try {
  const page = await browser.newPage();
  const pageErrors = [];
  page.on("pageerror", (e) => pageErrors.push(String(e)));

  const screenHas = (m, count) => page.waitForFunction(([mm, c]) => {
    const buf = window.__wosh.term?.buffer.active;
    if (!buf) return false;
    let t = "";
    for (let i = 0; i < buf.length; i++) t += buf.getLine(i)?.translateToString(true) + "\n";
    return t.split(mm).length - 1 >= c;
  }, [m, count], { timeout: 60_000 });

  await page.goto(`http://127.0.0.1:${PORT}/#${CONNSTRING}`, { waitUntil: "load" });
  await page.waitForSelector("#panel button", { timeout: 15_000 });
  // The panel collapses setup material into <details> (#65); these
  // flows drive what is inside them, so open everything once the
  // panel has rendered.
  await page.evaluate(() => document.querySelectorAll("#panel details").forEach((d) => { d.open = true; }));
  await page.click("text=show this browser's public key");
  const line = (await page.locator("#panel .key code").first().textContent({ timeout: 120_000 })).trim();
  appendFileSync(AUTH_KEYS, line + "\n");
  await page.fill("#panel input[placeholder='user']", USER);
  await page.click("#panel button:has-text('connect')");
  await page.locator("#panel .confirm code").first().textContent({ timeout: 60_000 });
  await page.click("#panel .confirm button:has-text('yes, connect')");
  await page.waitForFunction((u) => document.getElementById("status")?.textContent === `connected as ${u}`,
    USER, { timeout: 60_000 });
  console.log("[1] connected");

  await page.click(".xterm-screen");
  await page.keyboard.type("echo MARK_BEFORE\n", { delay: 10 });
  await screenHas("MARK_BEFORE", 2);
  console.log("[2] pre-restart round trip");

  // Murder the relay. Both sides lose their endpoints: the listener's
  // accept loop must rebind and re-register; the client's resume
  // machine must rebind and redial.
  execSync("pkill -f 'iroh-rela[y]' || true");
  await new Promise((r) => setTimeout(r, 2000));
  spawn(RELAY_BIN, ["--dev"], { detached: true, stdio: "ignore" }).unref();
  console.log("[3] relay killed and restarted");

  // The resume machine's own backoff paces recovery; give it room.
  await new Promise((r) => setTimeout(r, 8000));

  if (await page.evaluate(() => document.getElementById("panel")?.open)) {
    fail("the connect dialog reopened: the session was declared dead instead of resumed");
  }
  const st = await page.evaluate(() => document.getElementById("status")?.textContent);
  if (st !== `connected as ${USER}`) fail(`status changed to "${st}" during the outage`);

  await page.click(".xterm-screen");
  await page.keyboard.type("echo MARK_AFTER\n", { delay: 10 });
  await screenHas("MARK_AFTER", 2);
  console.log("[4] post-restart round trip: the session survived");

  await page.click("#bar button:has-text('detach')");
  if (pageErrors.length) fail(`page errors:\n  ${pageErrors.join("\n  ")}`);
  if (!failed) {
    console.log("\nBROWSER RESUME PASS: a live session rode out a relay restart" +
      " (client rebind + resume, listener rebind + re-registration, replay)");
  }
} catch (e) {
  fail(String(e?.stack ?? e));
} finally {
  await browser.close();
  server.close();
}
process.exitCode = failed ? 1 : 0;
