// Browser freeze gate: the mobile-background story, end to end.
//
// A phone that backgrounds the page FREEZES it -- the process is not
// scheduled at all -- and the QUIC connection under the session dies
// of silence: the listener's side stops hearing ACKs, idle-times-out
// (~30s), and parks the session (sshd leg held open, `--resume-grace`).
// The page must ride that out:
//
//   freeze  -> lifecycle.mjs suspends the session (stop redialing);
//   resume  -> wake() probes the possibly-zombie connection with a
//              tunnel PING instead of waiting for QUIC's own idle
//              timeout to notice locally;
//   verdict -> the resume machine redials and the listener replays
//              from the parked session.
//
// Same session on both sides of the gap: no dialog, no fresh shell, a
// post-thaw keystroke round-trips.
//
// The freeze itself is SIGSTOP on the renderer process -- the real
// thing, an event loop that simply stops -- because CDP's
// Page.setWebLifecycleState is a no-op in this headless build
// (measured: timers kept firing at full rate and no lifecycle events
// were delivered). The `freeze`/`resume` lifecycle events are
// dispatched synthetically around the stop, the same way the mobile
// gate drives lifecycle.mjs; platforms diverge on delivering them
// anyway (iOS often skips `freeze`), and the session machinery is
// built to survive either order of "wake() ran" and "the dead
// transport surfaced".
//
// Environment (the `just browser-freeze` recipe supplies it):
//   WOSH_CONNSTRING       the listener's connection string   (required)
//   WOSH_AUTHORIZED_KEYS  sshd's authorized_keys path        (required)
//   WOSH_LISTENER_LOG     the listener's gate-proc log       (required)
//   WOSH_USER             login user (default: $USER)
//   WOSH_FROZEN_MS        how long to stay frozen (default: 45000,
//                         comfortably past the 30s QUIC idle timeout)
//   WOSH_HTTP_PORT        static server port (default: 8131)
import { chromium } from "playwright-core";
import { execSync } from "node:child_process";
import { appendFileSync, existsSync, readdirSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname } from "node:path";

const ROOT = new URL("../out/", import.meta.url).pathname;
const PORT = Number(process.env.WOSH_HTTP_PORT ?? 8131);
const CONNSTRING = process.env.WOSH_CONNSTRING;
const AUTH_KEYS = process.env.WOSH_AUTHORIZED_KEYS;
const LISTENER_LOG = process.env.WOSH_LISTENER_LOG;
const USER = process.env.WOSH_USER ?? process.env.USER;
const FROZEN_MS = Number(process.env.WOSH_FROZEN_MS ?? 45_000);
if (!CONNSTRING || !AUTH_KEYS || !LISTENER_LOG || !USER) {
  console.error("need WOSH_CONNSTRING, WOSH_AUTHORIZED_KEYS, WOSH_LISTENER_LOG; run via `just browser-freeze`");
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

// The page's renderer process: the thing a phone actually freezes.
// Chromium splits work across processes -- the browser process, a
// network service, renderers -- and ONLY the renderer runs the page's
// JS (and so the wasm client, its timers, its QUIC ACK generation).
// SIGSTOP on it is a faithful background-freeze: the network process
// keeps the relay websocket open and keeps buffering inbound frames,
// but nothing ACKs, which is exactly a phone in a pocket.
function rendererPids() {
  // playwright exposes no process handle, but the browser it launched
  // is a descendant of THIS node process -- walk down from ourselves.
  // Other worktrees' browsers belong to other gate processes, so the
  // walk cannot reach them. Headless keeps a spare renderer around
  // besides the page's; stopping a spare is harmless, so ALL renderers
  // freeze rather than guessing which one is the page.
  const root = process.pid;
  const rows = execSync("ps -eo pid=,ppid=,args=", { encoding: "utf8" })
    .trim().split("\n")
    .map((l) => {
      const m = l.trim().match(/^(\d+)\s+(\d+)\s+(.*)$/);
      return m && { pid: Number(m[1]), ppid: Number(m[2]), args: m[3] };
    })
    .filter(Boolean);
  const mine = new Set([root]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const r of rows) {
      if (mine.has(r.ppid) && !mine.has(r.pid)) { mine.add(r.pid); grew = true; }
    }
  }
  const renderers = rows.filter((r) => mine.has(r.pid) && r.args.includes("--type=renderer"));
  if (renderers.length === 0) throw new Error("no renderer process found under this gate");
  return renderers.map((r) => r.pid);
}

let failed = false;
const fail = (m) => { console.error(`FAIL: ${m}`); failed = true; };

try {
  const page = await browser.newPage();
  const pageErrors = [];
  page.on("pageerror", (e) => pageErrors.push(String(e)));
  // The component's stderr surfaces on the console: the resume
  // machine's own diagnostics live there and nowhere else.
  page.on("console", (m) => say(`  [console] ${m.text()}`));

  const screenText = () => page.evaluate(() => {
    const buf = window.__wosh.term?.buffer.active;
    if (!buf) return "";
    let t = "";
    for (let i = 0; i < buf.length; i++) t += buf.getLine(i)?.translateToString(true) + "\n";
    return t;
  });
  const screenHas = (m, count, timeout = 60_000) => page.waitForFunction(([mm, c]) => {
    const buf = window.__wosh.term?.buffer.active;
    if (!buf) return false;
    let t = "";
    for (let i = 0; i < buf.length; i++) t += buf.getLine(i)?.translateToString(true) + "\n";
    return t.split(mm).length - 1 >= c;
  }, [m, count], { timeout });

  await page.goto(`http://127.0.0.1:${PORT}/#${CONNSTRING}`, { waitUntil: "load" });
  // A fragment link is a deliberate destination: the connect sheet
  // opens for it directly.
  await page.waitForSelector("#sheet[data-ask='connect'] input[placeholder='user']", { timeout: 15_000 });
  const line = (await page.evaluate(async () => {
    const { identity } = await import("./app.mjs");
    return await identity();
  })).trim();
  appendFileSync(AUTH_KEYS, line + "\n");
  await page.fill("#sheet input[placeholder='user']", USER);
  await page.click("#sheet button:text-is('connect')");
  await page.locator("#sheet .confirm code.fp").first().textContent({ timeout: 60_000 });
  await page.click("#sheet button:has-text('it matches')");
  await page.waitForFunction((u) => document.getElementById("status")?.textContent === `connected as ${u}`,
    USER, { timeout: 60_000 });
  say("[1] connected");

  await page.click(".xterm-screen");
  await page.keyboard.type("echo MARK_BEFORE\n", { delay: 10 });
  await screenHas("MARK_BEFORE", 2);
  say("[2] pre-freeze round trip");

  // Freeze: the lifecycle event first (a phone fires it on its way to
  // the freezer; lifecycle.mjs suspends the session), then the stop
  // itself. Nothing may touch the page while it is stopped -- an
  // evaluate would simply hang -- so everything in the frozen window
  // is asserted from outside the browser.
  const renderers = rendererPids();
  await page.evaluate(() => document.dispatchEvent(new Event("freeze")));
  for (const pid of renderers) execSync(`kill -STOP ${pid}`);
  say(`[3] renderer(s) ${renderers.join(",")} frozen for ${FROZEN_MS}ms (QUIC idle timeout is 30s)`);

  // While the page is out cold, the listener's side of the connection
  // must die of silence and PARK the session -- that is what makes the
  // wake a resume rather than a survival. Asserted from the listener's
  // log, because the page cannot testify while frozen.
  const frozenUntil = Date.now() + FROZEN_MS;
  let parked = false;
  while (Date.now() < frozenUntil) {
    await sleep(1000);
    if (!parked && readFileSync(LISTENER_LOG, "utf8").includes("parked session")) {
      parked = true;
      say("[4] listener parked the session (transport died of silence)");
    }
  }
  if (!parked) {
    // Not a hard failure yet -- an unusually patient transport could
    // park late -- but the gate's premise needs it before the thaw
    // proves anything. Give it a short grace, then insist.
    for (let i = 0; i < 20 && !parked; i++) {
      await sleep(500);
      parked = readFileSync(LISTENER_LOG, "utf8").includes("parked session");
    }
    if (parked) say("[4] listener parked the session (late)");
    else fail("the listener never parked the session: the freeze did not kill the transport");
  }

  // Thaw: the process first, then the lifecycle event a phone fires on
  // the way back. Both orders of "wake() ran" and "the dead transport
  // surfaced" are legal (the machinery stalls-then-wakes in one and
  // probes in the other); this drives the common one.
  execSync(`kill -CONT ${renderers.join(" ")}`);
  await page.evaluate(() => document.dispatchEvent(new Event("resume")));
  say("[5] thawed");

  const diag = async (label) => {
    const d = await page.evaluate(() => ({
      status: document.getElementById("status")?.textContent,
      failure: window.__wosh?.failure ?? null,
      panelOpen: document.getElementById("panel")?.open ?? null,
    })).catch((e) => ({ evalFailed: String(e) }));
    say(`${label}: ${JSON.stringify(d)}`);
    return d;
  };
  // Watch the recovery unfold in the log (helps diagnose a hang).
  const watch = setInterval(() => { diag("  ...").catch(() => {}); }, 2000);

  // The thaw path: `resume` -> wake() -> probe -> verdict -> redial ->
  // resumed. All of it inside this window, without a human.
  try {
    await page.waitForFunction((u) => document.getElementById("status")?.textContent === `connected as ${u}`,
      USER, { timeout: 30_000 });

    if (await page.evaluate(() => document.getElementById("panel")?.open)) {
      fail("the connect dialog reopened: the session was declared dead instead of resumed");
    }

    // One retry on the post-thaw keystroke: the click/type can race the
    // renderer's first layout after 45s of not being scheduled, landing
    // the keystrokes outside xterm entirely -- a harness hazard, not a
    // session one (the session's own delivery is what MARK_AFTER then
    // proves). The retry re-clicks to re-acquire focus.
    await page.click(".xterm-screen");
    await page.keyboard.type("echo MARK_AFTER\n", { delay: 10 });
    try {
      await screenHas("MARK_AFTER", 2, 20_000);
    } catch {
      say("  (post-thaw keystrokes did not land; re-clicking and retrying once)");
      await page.click(".xterm-screen");
      await page.keyboard.type("echo MARK_AFTER\n", { delay: 10 });
      await screenHas("MARK_AFTER", 2);
    }
    say("[6] post-thaw round trip");
  } finally {
    clearInterval(watch);
    await diag("[post-thaw state]");
    console.log("--- listener log tail ---");
    console.log(readFileSync(LISTENER_LOG, "utf8").split("\n").slice(-8).join("\n"));
  }

  if (await page.evaluate(() => document.getElementById("panel")?.open)) {
    fail("the connect dialog reopened late: the session was declared dead after recovering");
  }

  // Same session, not a fresh one: the auto-reconnect divider is the
  // fresh path's signature, and it must NOT be here.
  const text = await screenText();
  if (text.includes("[wosh]")) {
    fail("the terminal shows a [wosh] divider: the page fell through to a fresh session instead of resuming");
  }
  if (!text.includes("MARK_BEFORE")) {
    fail("pre-freeze scrollback is gone: this is not the session that froze");
  }
  // And the bookends agree: one session opened, none closed -- a
  // resumable outage is not a session end, so no end rule may exist
  // (separator.mjs draws it only on a CONFIRMED termination).
  const bookends = await page.evaluate(() => ({
    start: document.querySelectorAll(".session-separator.start").length,
    end: document.querySelectorAll(".session-separator.end").length,
  }));
  if (bookends.start !== 1 || bookends.end !== 0) {
    fail(`expected 1 start / 0 end bookends across a resume, found ${bookends.start}/${bookends.end}`);
  }

  if (pageErrors.length) fail(`page errors:\n  ${pageErrors.join("\n  ")}`);
  if (!failed) {
    console.log("\nBROWSER FREEZE PASS: a frozen page's dead transport was probed on wake," +
      " the parked session resumed, and a post-thaw keystroke round-tripped");
  }
} catch (e) {
  fail(String(e?.stack ?? e));
} finally {
  await browser.close();
  server.close();
}
process.exitCode = failed ? 1 : 0;
