// The M7 browser leg (the last one finding 24 unblocked): inner ssh
// from the REAL page through a DEPRIVILEGED proxy — the page's
// composed client dials over iroh, authenticates end-to-end over ssh
// through the forwarded stream (x/crypto/ssh in wasm), boots its own
// mosh-server via ssh exec, and runs mosh over the datagram tunnel.
// The proxy spawns nothing and never sees the mosh key.
//
//   node ssh-browser-e2e.mjs        (via `just m7-browser`)
//
// Topology: iroh-relay --dev (:3355) ← proxy (NO --personal,
// --ssh-target = the russh sshd stand-in, spawned as the ssh-e2e
// crate's sshd-standin bin) ← relay websocket ← the page.
//
// Host-key UX under test (the M7 in-page piece): first ssh connect
// pins the observed fingerprint (TOFU) on the saved proxy record; a
// TAMPERED pin makes the next connect fail "host key mismatch" BEFORE
// the password is sent (the stand-in's password-attempts counter
// proves it); restoring the pin connects again. Auth negatives beyond
// that stay native-gate territory (ssh-e2e).

import http from "node:http";
import { readFile, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { spawn } from "node:child_process";

const HERE = import.meta.dirname;
const WEB = join(HERE, "..", "web");
const RELAY_PORT = 3355;
const TOKEN = "m7-browser-token";
const TEST_USER = "testuser";
const TEST_PASSWORD = "testpass";
const SHELL_CMD = "mosh-server new -i 127.0.0.1 -c 256 -- bash --noprofile --norc -i";
const CONNECT_ATTEMPTS = 8;

const log = (...a) => console.log("[m7-browser]", ...a);

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

// --- relay + sshd stand-in + deprivileged proxy -------------------------------
const dir = await mkdtemp(join(tmpdir(), "wosh-m7-browser-"));
const relayCfg = join(dir, "relay.toml");
await writeFile(relayCfg, `http_bind_addr = "127.0.0.1:${RELAY_PORT}"\nenable_metrics = false\n`);
const relayBin = join(HERE, "../.deps/polymorph-iroh/.deps/iroh/target/release/iroh-relay");
children.push(spawn(relayBin, ["--dev", "-c", relayCfg], { stdio: "ignore", detached: true }));
await waitPort(RELAY_PORT);
log(`relay on :${RELAY_PORT}`);

const standin = spawn(join(HERE, "ssh-e2e/target/release/sshd-standin"), [], {
  stdio: ["ignore", "pipe", "inherit"],
  detached: true,
});
children.push(standin);
let standinLog = "";
standin.stdout.on("data", (d) => {
  standinLog += d;
});
const { sshPort, standinFp } = await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("standin startup timeout")), 10_000);
  const poll = setInterval(() => {
    const m = standinLog.match(/standin: port=(\d+) fp=(\S+)/);
    if (m) {
      clearTimeout(timer);
      clearInterval(poll);
      resolve({ sshPort: Number(m[1]), standinFp: m[2] });
    }
  }, 50);
  standin.on("exit", () => reject(new Error("standin exited at startup")));
});
log(`sshd stand-in on :${sshPort} (fp ${standinFp.slice(0, 12)}…)`);
const passwordAttempts = () =>
  Number([...standinLog.matchAll(/password-attempts: (\d+)/g)].at(-1)?.[1] ?? 0);

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
    // Deprivileged: NO --personal — the proxy only forwards ssh.
    "--ssh-target",
    `127.0.0.1:${sshPort}`,
    "--state-dir",
    join(dir, "state"),
    "--component",
    join(HERE, "../proxy/composed-proxy.wasm"),
  ],
  { stdio: ["ignore", "pipe", "inherit"], detached: true },
);
children.push(proxy);

let proxyLog = "";
proxy.stdout.on("data", (d) => {
  proxyLog += d;
});
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
log(`proxy up (deprivileged): ${connstring.slice(0, 24)}…`);

// --- static server -------------------------------------------------------------
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
await new Promise((r) => httpServer.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${httpServer.address().port}`;

// --- the browser ---------------------------------------------------------------
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

/** Fill an ssh cluster (within `scope`) and click its ssh button. */
const fillAndSsh = async (page, scope) => {
  await page.fill(`${scope} .ssh-user`, TEST_USER);
  await page.fill(`${scope} .ssh-pass`, TEST_PASSWORD);
  await page.fill(`${scope} .ssh-cmd`, SHELL_CMD);
  await page.click(`${scope} .ssh-btn`);
};

/** Wait for a live session or a legible failure notice. */
const waitSshOutcome = async (page, label, timeoutMs = 60_000) => {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const mode = await page.evaluate(() => window.__mosh?.mode ?? null);
    if (mode === "iroh") return { ok: true };
    const notice = await page.evaluate(() => window.__moshBoot?.notice ?? "");
    if (notice.startsWith("connect failed")) return { ok: false, notice };
    if (Date.now() > deadline) throw new Error(`${label}: neither session nor failure`);
    await new Promise((r) => setTimeout(r, 100));
  }
};

let failed = null;
try {
  const context = await browser.newContext();

  // Phase 1: first-contact ssh connect from the pending row (bounded
  // retries over the RefCell hazard — fresh page per attempt).
  let page = null;
  let attempts = 0;
  let lastErr = null;
  while (attempts < CONNECT_ATTEMPTS && !page) {
    attempts++;
    const p = await context.newPage();
    p.on("console", (m) => {
      if (m.type() === "error") console.error(`[page console] ${m.text()}`);
    });
    try {
      await p.goto(`${base}/#${connstring}`);
      await p.waitForSelector(".boot-pending .ssh-btn", { timeout: 10_000 });
      await fillAndSsh(p, ".boot-pending");
      const r = await waitSshOutcome(p, `attempt ${attempts}`);
      if (!r.ok) throw new Error(r.notice);
      page = p;
    } catch (e) {
      lastErr = e;
      log(`ssh attempt ${attempts}/${CONNECT_ATTEMPTS} failed: ${e.message.slice(0, 140)}`);
      await p.close();
    }
  }
  if (!page) throw new Error(`no ssh attempt succeeded; last: ${lastErr?.message}`);
  log(`ssh connected (attempt ${attempts}/${CONNECT_ATTEMPTS})`);

  await waitText(page, /\$/, "shell prompt");
  await page.click("#term");
  await page.keyboard.type("echo in_$(printf page)_ssh_ok", { delay: 5 });
  await page.keyboard.press("Enter");
  await waitText(page, /in_page_ssh_ok/, "echo marker");
  log("prompt + echo over inner ssh OK");

  // The pin landed (TOFU first contact) and matches the stand-in.
  const pinned = await page.evaluate(
    () => window.__moshBoot.state.proxies[0]?.sshHostKey ?? null,
  );
  if (pinned !== standinFp) {
    throw new Error(`pinned fp ${pinned} != stand-in fp ${standinFp}`);
  }
  const noticeAfter = await page.evaluate(() => window.__moshBoot.notice);
  if (!/pinned/.test(noticeAfter)) throw new Error(`no pin notice: "${noticeAfter}"`);
  log("host key pinned on first contact");

  await page.evaluate(() => window.__mosh.detach());
  log("detach OK");

  // Phase 2: a TAMPERED pin refuses before auth. Rewrite the stored
  // fingerprint, reload (fresh client), ssh from the saved row: the
  // failure names the mismatch and the stand-in saw no new password.
  const attemptsBefore = passwordAttempts();
  await page.evaluate(() => {
    const s = JSON.parse(localStorage.getItem("wosh/v1"));
    s.proxies[0].sshHostKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    localStorage.setItem("wosh/v1", JSON.stringify(s));
  });
  await page.goto(base);
  await page.waitForSelector(".boot-proxy .ssh-btn", { timeout: 10_000 });
  await page.fill(".boot-proxy .token-input", TOKEN);
  await fillAndSsh(page, ".boot-proxy");
  const refused = await waitSshOutcome(page, "tampered-pin ssh");
  if (refused.ok) throw new Error("ssh succeeded despite a tampered host-key pin");
  if (!/host key mismatch/i.test(refused.notice)) {
    throw new Error(`refusal didn't name the mismatch: ${refused.notice}`);
  }
  await new Promise((r) => setTimeout(r, 300)); // let the counter line flush
  const attemptsAfter = passwordAttempts();
  if (attemptsAfter !== attemptsBefore) {
    throw new Error(
      `password sent to an unapproved host key (attempts ${attemptsBefore} -> ${attemptsAfter})`,
    );
  }
  log(`tampered pin refused before auth (${refused.notice.slice(0, 80)}…); attempts unchanged`);

  // Phase 3: restore the pin; ssh connects again (a fresh session).
  await page.evaluate((fp) => {
    const s = JSON.parse(localStorage.getItem("wosh/v1"));
    s.proxies[0].sshHostKey = fp;
    localStorage.setItem("wosh/v1", JSON.stringify(s));
  }, standinFp);
  await page.goto(base);
  await page.waitForSelector(".boot-proxy .ssh-btn", { timeout: 10_000 });
  await page.fill(".boot-proxy .token-input", TOKEN);
  await fillAndSsh(page, ".boot-proxy");
  const again = await waitSshOutcome(page, "restored-pin ssh");
  if (!again.ok) throw new Error(`restored-pin ssh failed: ${again.notice}`);
  await waitText(page, /\$/, "shell prompt (second session)");
  await page.click("#term");
  await page.keyboard.type("echo again_$(printf ssh)_ok", { delay: 5 });
  await page.keyboard.press("Enter");
  await waitText(page, /again_ssh_ok/, "second-session echo");
  log("restored pin: second ssh session OK");

  await page.evaluate(() => window.__mosh.detach());
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
console.log("ssh browser E2E (M7 in-page leg): OK");
process.exit(0);
