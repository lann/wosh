// Browser idle-survival gate: the REAL page in headless Chromium
// connects, round-trips one command, sits idle PAST the transport's
// 30s max_idle_timeout, then types again -- and the keystroke must
// still round-trip.
//
// History: an idle session used to die at ~30s because neither wosh
// endpoint sent QUIC keepalives (polymorph-iroh#70; fixed by its #71,
// picked up here by a pin bump). On the pre-refactor client the death
// then wedged the guest -- the next keystroke trapped with "deadlock
// detected: event loop cannot make further progress" (wosh#43's
// vocabulary). This gate holds both fixes in place: the session must
// SURVIVE the idle window, and nothing may trap.
//
// An optional second mode (WOSH_KILL_NAME) covers the other half of
// that investigation -- a tunnel dying mid-session (listener killed)
// must surface as a clean "session ended", never a trap, with
// keystrokes racing the death cascade one per second. It kills the
// listener it is pointed at, so `just check` does not run it; use it
// when touching teardown paths. The name is a gate-proc name, not a
// pkill pattern: this kills the listener THIS gate started and no
// other, the same discipline the recipes follow.
//
// Usage (the `just browser-idle-e2e` recipe supplies the env):
//   WOSH_CONNSTRING=...        the listener's connection string
//   WOSH_AUTHORIZED_KEYS=...   sshd's authorized_keys path
//   WOSH_USER                  login user       (default: $USER)
//   WOSH_IDLE_MS               idle window      (default: 40000)
//   WOSH_KILL_NAME             gate-proc name   (kill mode; off by
//                              default; this recipe's listener is
//                              started as `browser-idle`)
//   WOSH_KILL_AFTER_MS         kill delay       (default: 3000)
//
// Exits 0 on pass, 1 on failure (wedge, trap, or no round-trip), 2 on
// harness trouble.

import { chromium } from "playwright-core";
import { appendFileSync, existsSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname } from "node:path";

const ROOT = new URL("../out/", import.meta.url).pathname;
const PORT = Number(process.env.WOSH_HTTP_PORT ?? 8123);
const CONNSTRING = process.env.WOSH_CONNSTRING;
const AUTH_KEYS = process.env.WOSH_AUTHORIZED_KEYS;
const USER = process.env.WOSH_USER ?? process.env.USER;
const IDLE_MS = Number(process.env.WOSH_IDLE_MS ?? 40_000);
// When set: stop this gate-proc-named listener KILL_AFTER_MS after the
// first round-trip, then type once a second through the death cascade.
const KILL_NAME = process.env.WOSH_KILL_NAME ?? "";
const KILL_AFTER_MS = Number(process.env.WOSH_KILL_AFTER_MS ?? 3_000);

if (!CONNSTRING || !AUTH_KEYS || !USER) {
  console.error("need WOSH_CONNSTRING and WOSH_AUTHORIZED_KEYS");
  process.exit(2);
}

const MIME = {
  ".html": "text/html",
  ".mjs": "text/javascript",
  ".js": "text/javascript",
  ".css": "text/css",
  ".wasm": "application/wasm",
};

function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const glob = `${process.env.HOME}/.cache/ms-playwright`;
  const dirs = readdirSync(glob)
    .filter((d) => d.startsWith("chromium-"))
    .sort((a, b) => Number(a.split("-")[1]) - Number(b.split("-")[1]));
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

const server = createServer(async (req, res) => {
  try {
    const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
    const file = join(ROOT, path === "/" ? "index.html" : path);
    const body = await readFile(file);
    res.writeHead(200, {
      "content-type": MIME[extname(file)] ?? "application/octet-stream",
      "cache-control": "no-store",
    });
    res.end(body);
  } catch {
    res.writeHead(404).end("not found");
  }
});

await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
const browser = await chromium.launch({
  executablePath: findChrome(),
  args: ["--no-sandbox"],
});

const t0 = Date.now();
const log = (msg) => console.log(`[${String(Date.now() - t0).padStart(6)}ms] ${msg}`);
let sawWedge = false;

try {
  const page = await browser.newPage();
  page.on("console", (m) => {
    if (m.type() === "error" || m.type() === "warning") {
      log(`console.${m.type()}: ${m.text()}`);
    }
  });
  page.on("pageerror", (e) => log(`pageerror: ${e}`));

  const diag = () =>
    page.evaluate(() => ({
      status: document.getElementById("status")?.textContent,
      failure: window.__wosh?.failure ?? null,
    }));

  // Track the page's status line by polling; log transitions.
  let lastStatus = "";
  const statusWatch = setInterval(async () => {
    try {
      const d = await diag();
      const s = `${d.status}${d.failure ? ` | failure: ${d.failure}` : ""}`;
      if (s !== lastStatus) {
        lastStatus = s;
        log(`status: ${s}`);
      }
    } catch {
      // page navigating; ignore
    }
  }, 250);

  await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: "load" });
  await page.waitForSelector("#home button.scan", { timeout: 15_000 });
  log("page loaded");

  const line = (await page.evaluate(async () => {
    const { identity } = await import("./app.mjs");
    return await identity();
  })).trim();
  if (!/^ssh-ed25519 /.test(line)) throw new Error(`bad identity line: ${line}`);
  appendFileSync(AUTH_KEYS, line + "\n");
  log("identity installed");

  await page.fill("#home input.connstring", CONNSTRING);
  await page.click("#home .pasterow button.go");
  await page.waitForSelector("#sheet[data-ask='connect'] input[placeholder='user']", { timeout: 15_000 });
  await page.fill("#sheet input[placeholder='user']", USER);
  await page.evaluate(() => {
    document.querySelector("#sheet details.options").open = true;
  });
  await page.selectOption("#sheet select.method", "publickey");
  await page.click("#sheet button:text-is('connect')");

  await page.locator("#sheet .confirm code.fp").first().textContent({ timeout: 60_000 });
  await page.click("#sheet button:has-text('it matches')");
  await page.waitForFunction(
    (u) => document.getElementById("status")?.textContent === `connected as ${u}`,
    USER,
    { timeout: 60_000 },
  );
  log("connected");

  const termText = () =>
    page.evaluate(() => {
      const buf = window.__wosh.term?.buffer.active;
      if (!buf) return "";
      let text = "";
      for (let i = 0; i < buf.length; i++) {
        text += buf.getLine(i)?.translateToString(true) + "\n";
      }
      return text;
    });

  await page.click(".xterm-screen");
  await page.keyboard.type("echo FIRST_$((40+2))\n", { delay: 10 });
  await page.waitForFunction(
    () => {
      const buf = window.__wosh.term?.buffer.active;
      if (!buf) return false;
      let text = "";
      for (let i = 0; i < buf.length; i++) {
        text += buf.getLine(i)?.translateToString(true) + "\n";
      }
      return text.includes("FIRST_42");
    },
    { timeout: 30_000 },
  );
  log("first command round-tripped");

  if (KILL_NAME) {
    // --- kill mode: the tunnel dies mid-session; death must be clean ---
    log(`waiting ${KILL_AFTER_MS}ms, then killing '${KILL_NAME}'`);
    await new Promise((r) => setTimeout(r, KILL_AFTER_MS));
    execFileSync(new URL("../scripts/gate-proc.sh", import.meta.url).pathname, ["stop", KILL_NAME]);
    log("listener killed");
    // Type through the cascade: one keystroke per second, racing the
    // teardown. The historical wedge surfaced here as an "input: wasm
    // trap: deadlock ..." status; a healthy client flips to "session
    // ended" once the transport declares the loss (~30s: keepalives
    // stop being acked and max_idle_timeout fires) and swallows the
    // rest without trapping.
    let sawCleanDeath = false;
    for (let i = 0; i < 45; i++) {
      await page.keyboard.type("x");
      await new Promise((r) => setTimeout(r, 1_000));
      const d = await diag();
      log(`post-kill keystroke ${i}: status=${JSON.stringify(d.status)}` +
        (d.failure ? ` failure=${JSON.stringify(d.failure)}` : ""));
      if (/deadlock|trap/i.test(d.status ?? "") || /deadlock|trap/i.test(d.failure ?? "")) {
        sawWedge = true;
        log("FAIL: a trap surfaced during the death cascade");
        break;
      }
      if (d.status === "session ended" || /^exited/.test(d.status ?? "")) {
        sawCleanDeath = true;
        // Keep typing a few more rounds: post-death keystrokes must be
        // swallowed without trapping too.
        if (i > 40) break;
      }
    }
    log(`final page state: ${JSON.stringify(await diag())}`);
    if (!sawWedge && !sawCleanDeath) {
      sawWedge = true;
      log("FAIL: the death was never surfaced (status never left 'connected')");
    } else if (!sawWedge) {
      log("PASS: clean death, keystrokes never trapped");
    }
  } else {
    // --- idle mode: the session must SURVIVE the idle window ---
    log(`idling ${IDLE_MS}ms...`);
    await new Promise((r) => setTimeout(r, IDLE_MS));
    log(`idle over; page state: ${JSON.stringify(await diag())}`);

    log("typing after idle");
    await page.keyboard.type("echo SECOND_$((40+2))\n", { delay: 10 });
    await new Promise((r) => setTimeout(r, 4_000));

    const after = await diag();
    const text = await termText();
    log(`post-keystroke page state: ${JSON.stringify(after)}`);
    if (/deadlock|trap/i.test(after.status ?? "") || /deadlock|trap/i.test(after.failure ?? "")) {
      sawWedge = true;
      log("FAIL: the deadlock trap surfaced on the post-idle keystroke");
    } else if (!text.includes("SECOND_42")) {
      // The historical idle death: the session did not survive the
      // window (however it was surfaced).
      sawWedge = true;
      log("FAIL: post-idle keystroke did not round-trip (see states above)");
    } else {
      log("PASS: the session survived idle; post-idle keystroke round-tripped");
    }
  }
  clearInterval(statusWatch);
} catch (e) {
  console.error(`harness error: ${e?.stack ?? e}`);
  process.exitCode = 2;
} finally {
  if (!process.argv.includes("--keep")) await browser.close();
  server.close();
}
if (process.exitCode === undefined) process.exitCode = sawWedge ? 1 : 0;
