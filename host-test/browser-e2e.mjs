// Browser end-to-end gate: the REAL page in a real Chromium, against a
// real listener and a real OpenSSH sshd -- the leg `just e2e` cannot
// cover, because it drives the component with typed Rust bindings and
// so never exercises the page's reading of deltic's JS conventions.
//
// What this asserts, in order:
//
//   1. The interactive host-key prompt APPEARS, showing the server's
//      fingerprint, and the session parks on it (TOFU: no credential
//      may flow before a human approves the fingerprint). This is the
//      regression test for the `{tag}` vs `{kind}` convention drift
//      that silently skipped the prompt and made the page offer
//      credentials at the gate.
//   2. Approving it completes publickey auth with the browser-minted
//      WebCrypto key, and keystrokes round-trip through the real
//      terminal to the shell and back.
//   3. On a fresh connect, REJECTING the fingerprint ends the attempt
//      with nothing sent.
//
// Environment (the `just browser-e2e` recipe supplies all of it):
//   WOSH_CONNSTRING       the listener's connection string   (required)
//   WOSH_AUTHORIZED_KEYS  sshd's authorized_keys path        (required)
//   WOSH_EXPECT_FP        sshd's host key fingerprint        (optional)
//   WOSH_USER             login user (default: $USER)
//   WOSH_HTTP_PORT        static server port (default: 8099)
//
// Usage: node host-test/browser-e2e.mjs [--keep]

import { chromium } from "playwright-core";
import { appendFileSync, existsSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname } from "node:path";

const ROOT = new URL("../out/", import.meta.url).pathname;
const PORT = Number(process.env.WOSH_HTTP_PORT ?? 8099);
const CONNSTRING = process.env.WOSH_CONNSTRING;
const AUTH_KEYS = process.env.WOSH_AUTHORIZED_KEYS;
const EXPECT_FP = process.env.WOSH_EXPECT_FP ?? "";
const USER = process.env.WOSH_USER ?? process.env.USER;

if (!CONNSTRING || !AUTH_KEYS || !USER) {
  console.error("need WOSH_CONNSTRING, WOSH_AUTHORIZED_KEYS and a user; run via `just browser-e2e`");
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
    const p = join(glob, d, "chrome-linux", "chrome");
    if (existsSync(p)) return p;
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

const fail = (msg) => {
  console.error(`FAIL: ${msg}`);
  process.exitCode = 1;
};

// The page's own status line + failure hook, for readable diagnostics
// when a wait times out.
const diag = (page) =>
  page.evaluate(() => ({
    status: document.getElementById("status")?.textContent,
    failure: window.__wosh?.failure ?? null,
  }));

await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
const browser = await chromium.launch({
  executablePath: findChrome(),
  args: ["--no-sandbox"],
});

try {
  const page = await browser.newPage();
  const consoleErrors = [];
  page.on("console", (m) => {
    if (m.type() === "error") consoleErrors.push(m.text());
  });
  page.on("pageerror", (e) => consoleErrors.push(String(e)));

  await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: "load" });
  await page.waitForSelector("#panel button", { timeout: 15_000 });
  console.log("[1] page loaded");

  // Install this browser's key where the sshd will look for it. Same
  // path a user follows: mint, copy the line, add to authorized_keys.
  await page.click("text=show this browser's public key");
  const line = (await page.locator("#panel .key code").first()
    .textContent({ timeout: 120_000 }) ?? "").trim();
  if (!/^ssh-ed25519 /.test(line)) throw new Error(`bad identity line: ${line}`);
  appendFileSync(AUTH_KEYS, line + "\n");
  console.log("[2] browser identity installed into authorized_keys");

  const fillAndConnect = async () => {
    await page.fill("#panel input[placeholder*='connection string']", CONNSTRING);
    await page.fill("#panel input[placeholder='user']", USER);
    await page.selectOption("#panel select", "publickey");
    await page.click("#panel button:has-text('connect')");
  };

  // --- leg A: the prompt appears, and approving it yields a shell ----
  await fillAndConnect();

  // THE core assertion. If the page ever skips the host-key gate, this
  // times out -- and before the prompt is handled nothing may proceed.
  let promptFp;
  try {
    promptFp = (await page.locator("#panel .confirm code")
      .textContent({ timeout: 60_000 })).trim();
  } catch (e) {
    console.error("no host-key prompt appeared; page state:", await diag(page));
    throw e;
  }
  console.log(`[3] interactive host-key prompt shown: ${promptFp}`);
  if (EXPECT_FP && promptFp !== EXPECT_FP) {
    fail(`prompt fingerprint ${promptFp} != sshd's ${EXPECT_FP}`);
  }
  const parked = await diag(page);
  if (parked.status !== "waiting for host key confirmation") {
    fail(`expected the session parked on the prompt, status is: ${parked.status}`);
  }

  await page.click("#panel .confirm button:has-text('yes, connect')");
  try {
    await page.waitForFunction(
      (u) => document.getElementById("status")?.textContent === `connected as ${u}`,
      USER,
      { timeout: 60_000 },
    );
  } catch (e) {
    console.error("never reached 'connected'; page state:", await diag(page));
    throw e;
  }
  console.log(`[4] approved; publickey auth completed as ${USER}`);

  // Round-trip through the real terminal: keystrokes in, output painted.
  const marker = "WOSH_BROWSER_E2E_OK";
  await page.click(".xterm-screen"); // focus the terminal, not the panel
  await page.keyboard.type(`echo ${marker}\n`, { delay: 10 });
  await page.waitForFunction(
    (m) => {
      const buf = window.__wosh.term?.buffer.active;
      if (!buf) return false;
      let text = "";
      for (let i = 0; i < buf.length; i++) {
        text += buf.getLine(i)?.translateToString(true) + "\n";
      }
      // Twice: once echoed by the pty, once as the command's output.
      return text.split(m).length - 1 >= 2;
    },
    marker,
    { timeout: 30_000 },
  );
  console.log("[5] shell round-trip through the tunnel painted in xterm");

  await page.click("#panel button:has-text('detach')");
  console.log("[6] detached");

  // --- leg B: rejecting the fingerprint sends nothing ----------------
  await page.reload({ waitUntil: "load" });
  await page.waitForSelector("#panel button", { timeout: 15_000 });
  await fillAndConnect();
  await page.locator("#panel .confirm code").textContent({ timeout: 60_000 });
  await page.click("#panel .confirm button:has-text('no')");
  await page.waitForFunction(
    () => document.getElementById("status")?.textContent === "host key rejected; nothing was sent",
    undefined,
    { timeout: 30_000 },
  );
  console.log("[7] rejected fingerprint ends the attempt: nothing was sent");

  if (consoleErrors.length) {
    fail(`console errors:\n  ${consoleErrors.join("\n  ")}`);
  }

  if (!process.exitCode) {
    console.log("\nBROWSER E2E PASS: the page walks the host-key gate interactively" +
      " and completes publickey auth in a real browser");
  }
} catch (e) {
  fail(String(e?.stack ?? e));
} finally {
  if (!process.argv.includes("--keep")) await browser.close();
  server.close();
}
