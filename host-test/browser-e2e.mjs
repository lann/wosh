// Browser end-to-end gate: the REAL page in a real Chromium, against a
// real listener and a real OpenSSH sshd -- the leg `just e2e` cannot
// cover, because it drives the component with typed Rust bindings and
// so never exercises the page's reading of deltic's JS conventions.
//
// What this asserts, leg by leg:
//
//   A. The interactive host-key prompt APPEARS, showing the server's
//      fingerprint, and the session parks on it (TOFU: no credential
//      may flow before a human approves the fingerprint). This is the
//      regression test for the `{tag}` vs `{kind}` convention drift
//      that silently skipped the prompt. Approving (WITHOUT opting
//      into persistence) completes auth via the DEFAULT method --
//      auto, the server steering -- which against this publickey-only
//      sshd must resolve silently to the browser-minted WebCrypto key;
//      keystrokes round-trip through the real terminal.
//   B. After a reload, the prompt appears AGAIN: approval is not
//      persisted unless the user opted in. Rejecting ends the attempt
//      with nothing sent. This leg also pastes the whole QR LINK
//      rather than the bare connstring: the field must reduce a URL to
//      its fragment, since the link is what operators hand out.
//   C. Approving WITH "remember this approval" checked pins the
//      fingerprint (keyed by the listener's endpoint id) ...
//   D. ... so the next reload connects with NO prompt at all: the
//      pinning payoff, asserted by watching that the prompt never
//      renders on the way to "connected".
//   E. A pinned fingerprint that DIFFERS from the presented one gets
//      the loud changed-key warning, with both fingerprints shown.
//   S. The QR scan button opens a preview, puts what it decodes into
//      the connstring field, and releases the camera afterwards.
//      Camera and decoder are stubbed -- headless Chromium has neither
//      a camera nor a QR to point it at -- so what this covers is the
//      page's own scan path, not the platform's decoder.
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

  // The page's own status line + failure hook, for readable
  // diagnostics when a wait times out.
  const diag = () =>
    page.evaluate(() => ({
      status: document.getElementById("status")?.textContent,
      failure: window.__wosh?.failure ?? null,
    }));

  // The browser identity persists across page loads (a non-extractable
  // CryptoKey pair in IndexedDB, behind the component's identity-store
  // import), so ONE install serves every leg -- later legs
  // re-authenticating after a reload double as a live check of that
  // persistence: if the identity failed to survive, publickey auth
  // against the installed line would fail.
  const installIdentity = async () => {
    await page.click("text=show this browser's public key");
    const line = (await page.locator("#panel .key code").first()
      .textContent({ timeout: 120_000 }) ?? "").trim();
    if (!/^ssh-ed25519 /.test(line)) throw new Error(`bad identity line: ${line}`);
    appendFileSync(AUTH_KEYS, line + "\n");
  };

  const fillAndConnect = async (connstring = CONNSTRING) => {
    await page.fill("#panel input[placeholder*='connection string']", connstring);
    await page.fill("#panel input[placeholder='user']", USER);
    // Deliberately no selectOption: this drives the DEFAULT method,
    // which must be auto -- the server steers, and against this sshd
    // (publickey-only) that must complete silently with the browser
    // key, prompting for nothing.
    const method = await page.inputValue("#panel select");
    if (method !== "auto") fail(`default auth method is ${method}, expected auto`);
    await page.click("#panel button:has-text('connect')");
  };

  const waitPrompt = async () => {
    try {
      return (await page.locator("#panel .confirm code").first()
        .textContent({ timeout: 60_000 })).trim();
    } catch (e) {
      console.error("no host-key prompt appeared; page state:", await diag());
      throw e;
    }
  };

  const waitConnected = async () => {
    try {
      await page.waitForFunction(
        (u) => document.getElementById("status")?.textContent === `connected as ${u}`,
        USER,
        { timeout: 60_000 },
      );
    } catch (e) {
      console.error("never reached 'connected'; page state:", await diag());
      throw e;
    }
  };

  const waitStatus = async (text) => {
    await page.waitForFunction(
      (t) => document.getElementById("status")?.textContent === t,
      text,
      { timeout: 30_000 },
    );
  };

  const reload = async () => {
    await page.reload({ waitUntil: "load" });
    await page.waitForSelector("#panel button", { timeout: 15_000 });
  };

  // The QR scan path, stubbed at its two edges: headless Chromium has
  // no camera, and no screen to point one at. Everything BETWEEN the
  // edges is the page's own (button, preview, decode loop, teardown),
  // and the payload is a real connect LINK, so leg S also proves a
  // scanned link is reduced to its fragment. The fake stream is kept
  // on window so the leg can assert the camera was released.
  await page.addInitScript((cs) => {
    const canvas = document.createElement("canvas");
    canvas.width = 320;
    canvas.height = 240;
    const ctx = canvas.getContext("2d");
    setInterval(() => {
      ctx.fillStyle = "#111";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
    }, 100);
    Object.defineProperty(navigator, "mediaDevices", {
      configurable: true,
      value: {
        getUserMedia: async () => (window.__woshFakeStream = canvas.captureStream(10)),
      },
    });
    window.BarcodeDetector = class {
      static async getSupportedFormats() {
        return ["qr_code"];
      }
      async detect() {
        return [{ rawValue: `https://wosh.example/#${cs}` }];
      }
    };
  }, CONNSTRING);

  await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: "load" });
  await page.waitForSelector("#panel button", { timeout: 15_000 });
  console.log("[1] page loaded");

  // --- leg S: the scan button fills the field, then lets go -----------
  await page.click("#panel button:has-text('scan QR')");
  await page.waitForSelector("#panel .scan-view video", { timeout: 10_000 });
  try {
    await page.waitForFunction(
      (cs) => document.querySelector("#panel input.connstring")?.value === cs,
      CONNSTRING,
      { timeout: 10_000 },
    );
    console.log("[S] a scanned link landed in the field as the bare connstring");
  } catch {
    const got = await page.inputValue("#panel input.connstring");
    fail(`scan did not fill the connstring field; field holds: ${got}`);
  }
  if (await page.locator("#panel .scan-view").count() !== 0) {
    fail("the camera preview outlived the scan");
  }
  const released = await page.evaluate(() =>
    (window.__woshFakeStream?.getTracks() ?? []).every((t) => t.readyState === "ended"));
  if (!released) fail("the camera was left running after the scan");
  else console.log("[S] preview torn down and the camera released");

  // --- leg A: the prompt appears; approval is interactive ------------
  await installIdentity();
  await fillAndConnect();

  // THE core assertion. If the page ever skips the host-key gate on a
  // first contact, this times out.
  const promptFp = await waitPrompt();
  console.log(`[A] interactive host-key prompt shown: ${promptFp}`);
  if (EXPECT_FP && promptFp !== EXPECT_FP) {
    fail(`prompt fingerprint ${promptFp} != sshd's ${EXPECT_FP}`);
  }
  const parked = await diag();
  if (parked.status !== "waiting for host key confirmation") {
    fail(`expected the session parked on the prompt, status is: ${parked.status}`);
  }
  const box = page.locator("#panel .confirm input[type=checkbox]");
  if (await box.count() !== 1) {
    fail("no remember checkbox on the prompt");
  } else if (await box.isChecked()) {
    fail("the remember checkbox must default to UNCHECKED (persistence is opt-in)");
  }
  await page.click("#panel .confirm button:has-text('yes, connect')");
  await waitConnected();
  console.log(`[A] approved (without remembering); auto steered to publickey, connected as ${USER}`);

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
  console.log("[A] shell round-trip through the tunnel painted in xterm");
  await page.click("#bar button:has-text('detach')");

  // --- leg B: no opt-in, no persistence; rejecting sends nothing -----
  await reload();
  // Pasted as the whole QR LINK this time, which is what an operator
  // actually hands out: the field must reduce it to the fragment, and
  // the dial must be indistinguishable from the bare-connstring legs.
  await fillAndConnect(`http://127.0.0.1:${PORT}/#${CONNSTRING}`);
  await waitPrompt();
  const reduced = await page.inputValue("#panel input[placeholder*='connection string']");
  if (reduced !== CONNSTRING) {
    fail(`a pasted link was not reduced to its fragment: ${reduced}`);
  } else {
    console.log("[B] a pasted QR link dials: its fragment is taken as the connstring");
  }
  console.log("[B] prompt appears again after reload: approval was not persisted");
  await page.click("#panel .confirm button:has-text('no')");
  await waitStatus("host key rejected; nothing was sent");
  console.log("[B] rejected fingerprint ends the attempt: nothing was sent");

  // --- leg C: approve WITH remember ----------------------------------
  // No re-install: the identity from leg A must have survived the
  // reloads, or this auth fails.
  await reload();
  await fillAndConnect();
  await waitPrompt();
  await page.check("#panel .confirm input[type=checkbox]");
  await page.click("#panel .confirm button:has-text('yes, connect')");
  await waitConnected();
  console.log("[C] approved with 'remember this approval' checked");
  await page.click("#bar button:has-text('detach')");

  // --- leg D: the pin skips the prompt --------------------------------
  await reload();
  await fillAndConnect();
  {
    const deadline = Date.now() + 60_000;
    for (;;) {
      if (await page.locator("#panel .confirm").count() > 0) {
        fail("prompt appeared despite a matching pinned fingerprint");
        break;
      }
      const st = (await diag()).status;
      if (st === `connected as ${USER}`) break;
      if (Date.now() > deadline) {
        console.error("page state:", await diag());
        throw new Error("timed out waiting for the pinned connect");
      }
      await new Promise((r) => setTimeout(r, 150));
    }
  }
  const pinNote = await page.evaluate(() => document.querySelector("#panel .notice")?.textContent);
  console.log(`[D] pinned fingerprint connected with NO prompt (${pinNote})`);
  await page.click("#bar button:has-text('detach')");

  // --- leg E: a changed host key warns loudly -------------------------
  // Overwrite the pin for this listener's endpoint id with a bogus
  // fingerprint, exactly what a MITM or reinstalled target produces:
  // pinned != presented.
  await page.evaluate(async (cs) => {
    const { endpointIdOf } = await import("./boot.mjs");
    const id = endpointIdOf(cs);
    const pins = JSON.parse(localStorage.getItem("wosh.hostkeys.v1") ?? "{}");
    if (!id || !pins[id]) throw new Error("expected a pin to tamper with");
    pins[id] = { fp: "SHA256:0000000000000000000000000000000000000000000", at: pins[id].at };
    localStorage.setItem("wosh.hostkeys.v1", JSON.stringify(pins));
  }, CONNSTRING);
  await reload();
  await fillAndConnect();
  await waitPrompt();
  const warn = await page.evaluate(() =>
    [...document.querySelectorAll("#panel .confirm .warn")].map((n) => n.textContent).join(" "));
  if (!/CHANGED/.test(warn)) {
    fail(`expected the changed-key warning, saw: ${warn || "(no warning)"}`);
  } else {
    console.log("[E] changed pinned key produces the loud warning");
  }
  const shown = await page.evaluate(() =>
    [...document.querySelectorAll("#panel .confirm code")].map((n) => n.textContent));
  if (!(shown.some((s) => s.includes("SHA256:00000")) && shown.some((s) => s === promptFp))) {
    fail(`warning must show both fingerprints; saw: ${shown.join(", ")}`);
  }
  await page.click("#panel .confirm button:has-text('no')");
  await waitStatus("host key rejected; nothing was sent");
  console.log("[E] rejected the changed key: nothing was sent");

  // --- leg F: connection history, tap to reconnect --------------------
  // Legs A/C/D connected as the same (endpoint, user) with the
  // remember-connection box at its CHECKED default, so history holds
  // exactly one deduped row. Tapping it must rebuild a TOKENLESS
  // connstring and connect -- pairing enrollment stands in for the
  // token. (The pin is still the bogus one leg E seeded, so the tap
  // rides through the changed-key warning: history grants no security
  // shortcuts.)
  await reload();
  const rows = await page.locator("#panel .histrow").count();
  if (rows !== 1) fail(`expected exactly 1 history row, found ${rows}`);
  const detail = await page.locator("#panel .histrow").first().getAttribute("title");
  if (!/relay http/.test(detail ?? "")) {
    fail(`history hover detail must carry the relay; got: ${detail}`);
  }
  await page.click("#panel .histrow");
  await waitPrompt();
  const filled = await page.inputValue("#panel input[placeholder*='connection string']");
  if (filled === CONNSTRING) fail("history dialed the original connstring (token included?)");
  await page.click("#panel .confirm button:has-text('yes, connect')");
  await waitConnected();
  console.log("[F] history row reconnected with a tokenless connstring (enrollment vouched)");
  await page.click("#bar button:has-text('detach')");

  // --- leg G: unchecked remember records nothing (and forgets nothing);
  // forgetting is the row's own two-step affordance ------------------
  await page.waitForSelector("#panel .histrow", { timeout: 15_000 });
  await page.uncheck("#panel #remember-connection");
  await page.click("#panel .histrow");
  await waitPrompt();
  await page.click("#panel .confirm button:has-text('yes, connect')");
  await waitConnected();
  await page.click("#bar button:has-text('detach')");
  await page.waitForSelector("#panel .histrow", { timeout: 15_000 });
  let rowsAfter = await page.locator("#panel .histrow").count();
  if (rowsAfter !== 1) {
    fail(`unchecked remember must not forget; expected the row to survive, found ${rowsAfter}`);
  }
  console.log("[G] unchecked remember: nothing recorded, nothing forgotten");

  // The forget button arms on the first click and acts on the second.
  await page.click("#panel .histline button.subtle");
  rowsAfter = await page.locator("#panel .histrow").count();
  if (rowsAfter !== 1) fail("one click must only ARM the forget, not perform it");
  const armed = await page.locator("#panel .histline button.subtle").textContent();
  if (!/forget\?/.test(armed ?? "")) fail(`expected an armed 'forget?' label, got: ${armed}`);
  await page.click("#panel .histline button.subtle");
  rowsAfter = await page.locator("#panel .histrow").count();
  if (rowsAfter !== 0) fail(`confirmed forget should remove the entry; ${rowsAfter} rows remain`);
  console.log("[G] forget is two-step: armed on the first click, done on the second");

  if (consoleErrors.length) {
    fail(`console errors:\n  ${consoleErrors.join("\n  ")}`);
  }

  if (!process.exitCode) {
    console.log("\nBROWSER E2E PASS: interactive TOFU on first contact, opt-in pinning, " +
      "prompt-free reconnect on a pinned key, a loud changed-key warning, " +
      "default-method auto resolving to the browser's key, and tap-to-reconnect " +
      "history (tokenless; unchecked remember records nothing; forget is two-step)");
  }
} catch (e) {
  fail(String(e?.stack ?? e));
} finally {
  if (!process.argv.includes("--keep")) await browser.close();
  server.close();
}
