// Browser end-to-end gate: the REAL page in a real Chromium, against a
// real listener and a real OpenSSH sshd -- the leg `just e2e` cannot
// cover, because it drives the component with typed Rust bindings and
// so never exercises the page's reading of polyengine's JS conventions.
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
    // Straight off the component: the identity UI (#identity) is
    // browser-identity's subject; these legs only need the line.
    const line = (await page.evaluate(async () => {
      const { identity } = await import("./app.mjs");
      return await identity();
    })).trim();
    if (!/^ssh-ed25519 /.test(line)) throw new Error(`bad identity line: ${line}`);
    appendFileSync(AUTH_KEYS, line + "\n");
  };

  const fillAndConnect = async (connstring = CONNSTRING) => {
    await page.fill("#home input.connstring", connstring);
    await page.click("#home .pasterow button.go");
    await page.waitForSelector("#sheet[data-ask='connect'] input[placeholder='user']", { timeout: 15_000 });
    await page.fill("#sheet input[placeholder='user']", USER);
    // Deliberately no selectOption: this drives the DEFAULT method,
    // which must be auto -- the server steers, and against this sshd
    // (publickey-only) that must complete silently with the browser
    // key, prompting for nothing.
    const method = await page.inputValue("#sheet select.method");
    if (method !== "auto") fail(`default auth method is ${method}, expected auto`);
    await page.click("#sheet button:text-is('connect')");
  };

  const waitPrompt = async () => {
    try {
      return (await page.locator("#sheet .confirm code.fp").first()
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
    await page.waitForSelector("#home button.scan", { timeout: 15_000 });
  };

  // Detach lives in the session sheet: open it from the header, tap.
  const detachViaSheet = async () => {
    await page.click("#sessions-btn");
    await page.click("#sheet button:has-text('detach')");
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
  await page.waitForSelector("#home button.scan", { timeout: 15_000 });
  console.log("[1] page loaded");

  // The session fold's controls must be LIVE against the real
  // component. This is the tripwire for capability-probe mistakes: an
  // arity sniff on polyengine's runtime-built Session.connect once
  // disabled the whole feature for every real page while every gate
  // stayed green, because the mobile gate stubs the component and
  // nothing else looked at the fold.
  {
    await page.fill("#home input.connstring", CONNSTRING);
    await page.click("#home .pasterow button.go");
    await page.waitForSelector("#sheet[data-ask='connect']", { timeout: 15_000 });
    await page.evaluate(() => {
      document.querySelector("#sheet details.options").open = true;
    });
    const dead = await page.evaluate(() =>
      [...document.querySelectorAll("#sheet details.options select, #sheet details.options input")]
        .filter((n) => n.disabled).length);
    if (dead) fail(`${dead} option control(s) arrived disabled against the real component`);
    await page.click("#sheet button:text-is('cancel')");
    console.log("[1s] connect-sheet option controls are live");
  }

  // --- leg S: the scan button fills the field, then lets go -----------
  // The scan button is an icon now; its accessible name is the stable
  // handle, its class the cheap one.
  await page.click("#home button.scan");
  await page.waitForSelector("#sheet .scan-view video", { timeout: 10_000 });
  try {
    // A decoded link opens the connect sheet for its target, reduced to
    // the bare connstring (the sheet advertises what it would dial).
    await page.waitForFunction(
      (cs) => document.getElementById("sheet")?.dataset.connstring === cs,
      CONNSTRING,
      { timeout: 10_000 },
    );
    console.log("[S] a scanned link opened the connect sheet for its bare connstring");
  } catch {
    const got = await page.evaluate(() => document.getElementById("sheet")?.dataset.connstring);
    fail(`scan did not open the connect sheet for the link; sheet holds: ${got}`);
  }
  if (await page.locator("#sheet .scan-view").count() !== 0) {
    fail("the camera preview outlived the scan");
  }
  const released = await page.evaluate(() =>
    (window.__woshFakeStream?.getTracks() ?? []).every((t) => t.readyState === "ended"));
  if (!released) fail("the camera was left running after the scan");
  else console.log("[S] preview torn down and the camera released");
  await page.click("#sheet button:text-is('cancel')");

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
  const box = page.locator("#sheet .confirm input[type=checkbox]");
  if (await box.count() !== 1) {
    fail("no remember checkbox on the prompt");
  } else if (await box.isChecked()) {
    fail("the remember checkbox must default to UNCHECKED (persistence is opt-in)");
  }
  await page.click("#sheet button:has-text('it matches')");
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
  await detachViaSheet();

  // --- leg B: no opt-in, no persistence; rejecting sends nothing -----
  await reload();
  // Pasted as the whole QR LINK this time, which is what an operator
  // actually hands out: the field must reduce it to the fragment, and
  // the dial must be indistinguishable from the bare-connstring legs.
  await fillAndConnect(`http://127.0.0.1:${PORT}/#${CONNSTRING}`);
  await waitPrompt();
  const reduced = await page.evaluate(() => window.__woshDialed);
  if (reduced !== CONNSTRING) {
    fail(`a pasted link was not reduced to its fragment: ${reduced}`);
  } else {
    console.log("[B] a pasted QR link dials: its fragment is taken as the connstring");
  }
  console.log("[B] prompt appears again after reload: approval was not persisted");
  await page.click(`#sheet button:has-text("don't connect")`);
  await waitStatus("host key rejected; nothing was sent");
  console.log("[B] rejected fingerprint ends the attempt: nothing was sent");

  // --- leg C: approve WITH remember ----------------------------------
  // No re-install: the identity from leg A must have survived the
  // reloads, or this auth fails.
  await reload();
  await fillAndConnect();
  await waitPrompt();
  await page.check("#sheet .confirm input[type=checkbox]");
  await page.click("#sheet button:has-text('it matches')");
  await waitConnected();
  console.log("[C] approved with 'remember this key' checked");
  await detachViaSheet();

  // --- leg D: the pin skips the prompt --------------------------------
  await reload();
  await fillAndConnect();
  {
    const deadline = Date.now() + 60_000;
    for (;;) {
      if (await page.locator("#sheet .confirm").count() > 0) {
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
  const pinNote = await page.evaluate(() => document.querySelector("#home .notice")?.textContent);
  console.log(`[D] pinned fingerprint connected with NO prompt (${pinNote})`);
  await detachViaSheet();

  // --- leg E: a changed host key warns loudly -------------------------
  // Overwrite the pin for this listener's endpoint id with a bogus
  // fingerprint, exactly what a MITM or reinstalled target produces:
  // pinned != presented.
  const realPin = await page.evaluate(async (cs) => {
    const { endpointIdOf } = await import("./boot.mjs");
    const id = endpointIdOf(cs);
    const pins = JSON.parse(localStorage.getItem("wosh.hostkeys.v1") ?? "{}");
    if (!id || !pins[id]) throw new Error("expected a pin to tamper with");
    const displaced = pins[id];
    pins[id] = { fp: "SHA256:0000000000000000000000000000000000000000000", at: pins[id].at };
    localStorage.setItem("wosh.hostkeys.v1", JSON.stringify(pins));
    return displaced;
  }, CONNSTRING);
  await reload();
  await fillAndConnect();
  await waitPrompt();
  const warn = await page.evaluate(() =>
    [...document.querySelectorAll("#sheet .confirm .warn")].map((n) => n.textContent).join(" "));
  if (!/CHANGED/.test(warn)) {
    fail(`expected the changed-key warning, saw: ${warn || "(no warning)"}`);
  } else {
    console.log("[E] changed pinned key produces the loud warning");
  }
  const shown = await page.evaluate(() =>
    [...document.querySelectorAll("#sheet .confirm code.fp")].map((n) => n.textContent));
  if (!(shown.some((s) => s.includes("SHA256:00000")) && shown.some((s) => s === promptFp))) {
    fail(`warning must show both fingerprints; saw: ${shown.join(", ")}`);
  }
  await page.click(`#sheet button:has-text("don't connect")`);
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
  const rows = await page.locator("#home .histrow").count();
  if (rows !== 1) fail(`expected exactly 1 connection card, found ${rows}`);
  const detail = await page.locator("#home .histrow").first().getAttribute("title");
  if (!/relay http/.test(detail ?? "")) {
    fail(`the card's hover detail must carry the relay; got: ${detail}`);
  }
  await page.click("#home .histrow");
  await waitPrompt();
  const dialed = await page.evaluate(() => window.__woshDialed);
  if (dialed === CONNSTRING) fail("the card dialed the original connstring (token included?)");
  // The pin is still leg E's bogus one, so this rides the changed-key
  // sheet: the dangerous choice arms on the first tap and acts on the
  // second -- history grants no security shortcuts, and no one-tap
  // approvals either.
  await page.click("#sheet button:has-text('connect anyway')");
  await page.click("#sheet button:has-text('really connect?')");
  await waitConnected();
  console.log("[F] card reconnected with a tokenless connstring (enrollment vouched)");
  await detachViaSheet();

  // --- leg G: unchecked remember records nothing (and forgets nothing);
  // forgetting is the row's own two-step affordance ------------------
  await page.waitForSelector("#home .histrow", { timeout: 15_000 });
  // "remember new connections" is a global preference on #prefs now.
  await page.click("#home .topline button:has-text('settings')");
  await page.uncheck("#prefs #pref-remember");
  await page.click("#prefs .backrow .back");
  await page.click("#home .histrow");
  await waitPrompt();
  await page.click("#sheet button:has-text('connect anyway')");
  await page.click("#sheet button:has-text('really connect?')");
  await waitConnected();
  await detachViaSheet();
  await page.waitForSelector("#home .histrow", { timeout: 15_000 });
  let rowsAfter = await page.locator("#home .histrow").count();
  if (rowsAfter !== 1) {
    fail(`remember off must not forget; expected the card to survive, found ${rowsAfter}`);
  }
  console.log("[G] remember off: nothing recorded, nothing forgotten");

  // Forget lives on the connection-settings screen (the card's ⋯),
  // and arms on the first tap.
  await page.click("#home .histrow .more");
  await page.click("#connection button:has-text('forget this connection')");
  rowsAfter = await page.locator("#home .histrow").count();
  if (rowsAfter !== 1) fail("one tap must only ARM the forget, not perform it");
  const armed = await page.locator("#connection button.danger").textContent();
  if (!/forget it\?/.test(armed ?? "")) fail(`expected an armed 'forget it?' label, got: ${armed}`);
  await page.click("#connection button.danger");
  rowsAfter = await page.locator("#home .histrow").count();
  if (rowsAfter !== 0) fail(`confirmed forget should remove the card; ${rowsAfter} remain`);
  console.log("[G] forget is two-step: armed on the first tap, done on the second");

  // Undo leg E's tampering before the flood leg. The store still
  // holds the bogus fingerprint -- legs F and G leaned on that (every
  // reconnect re-prompted, which is part of what they test) -- but leg
  // L needs the opposite footing: its poisoned-flood REBIRTH is a
  // silent automatic reconnect, and silent is only possible onto a
  // TRUE pin. Left bogus, the rebirth's changed-key warning is the
  // page's correct answer and the leg would be testing the wrong
  // thing.
  await page.evaluate(async ({ cs, pin }) => {
    const { endpointIdOf } = await import("./boot.mjs");
    const id = endpointIdOf(cs);
    const pins = JSON.parse(localStorage.getItem("wosh.hostkeys.v1") ?? "{}");
    pins[id] = pin;
    localStorage.setItem("wosh.hostkeys.v1", JSON.stringify(pins));
  }, { cs: CONNSTRING, pin: realPin });

  // --- leg L: large output with concurrent input ----------------------
  //
  // The composed client can be POISONED under flood: the Go core's
  // cabi_realloc occasionally reads the clock (Go runtime GC pacing)
  // inside the canonical copy window, where leaving the instance is
  // forbidden -- an instant trap, and every later call answers
  // "cannot enter component instance (reentrance forbidden)". The
  // page defends in two layers (app.mjs): quick calls are serialized
  // and retried through the reentrance gate, and a poisoned death is
  // classified `lost` so the automatic reconnect starts a fresh
  // session. The user-visible invariant this leg pins: after a flood
  // with typing on top, the user has a WORKING SHELL without touching
  // anything -- same session or silently reborn.
  // Via the FORM, not a history row: leg G's closing act deliberately
  // forgot the last remaining entry, so there is no row to click and
  // a wait for one could never end (and did not, once legs G and L
  // first ran in this order). The fields get refilled either way, the
  // pin is the true one again (restored above), and remember goes
  // back to its checked default.
  await page.click("#home .topline button:has-text('settings')");
  await page.check("#prefs #pref-remember");
  await page.click("#prefs .backrow .back");
  await fillAndConnect();
  // The true pin is back, so no prompt is EXPECTED and this connect is
  // silent; the short grace only covers a pin that failed to restore,
  // so that failure answers the ask instead of typing into a parked
  // host-key gate (waitPrompt here would stall its full 60s on every
  // healthy run, and log its no-prompt diagnostic as noise).
  await page.click("#sheet button:has-text('it matches')", { timeout: 3_000 })
    .catch(() => {});
  await waitConnected();
  await page.click(".xterm-screen");
  await page.keyboard.type("seq 1 300000\n", { delay: 0 });
  const floodDeadline = Date.now() + 15_000;
  while (Date.now() < floodDeadline) {
    // Typing through the flood: each keystroke is a write-input racing
    // the drain pump, which is exactly the collision that trapped.
    await page.keyboard.type("x", { delay: 0 });
    await new Promise((r) => setTimeout(r, 120));
  }
  // Ctrl-C the flood (and the typed junk), then prove the shell
  // answers. A transient "pump: cannot enter…" status is EXPECTED on
  // the poisoned path -- it is what the page shows between the death
  // and the automatic rebirth (fresh component instantiation + silent
  // reconnect takes seconds) -- so the only failure here is never
  // getting back to a live session within the window.
  await page.keyboard.press("Control+KeyC");
  const settled = await (async () => {
    const deadline = Date.now() + 90_000;
    for (;;) {
      const st = await page.evaluate(() => document.getElementById("status")?.textContent ?? "");
      if (st.startsWith("connected as")) return true;
      if (Date.now() > deadline) return st;
      await new Promise((r) => setTimeout(r, 500));
    }
  })();
  if (settled !== true) {
    fail(`after the flood the page never returned to a live session: ${settled}`);
  } else {
    // The invariant is A WORKING SHELL, not a lossless input path: a
    // keystroke typed in the instant of the silent rebirth lands in
    // the dying session (swallowed) or splits across the swap -- the
    // first probe here raced exactly that and lost. A human would
    // just type again, so the check does too; what is NOT tolerated
    // is a shell that answers nothing three prompts in a row.
    const seek = (m) => {
      const b = window.__wosh.term.buffer.active;
      for (let i = Math.max(0, b.baseY + b.cursorY - 8); i <= b.baseY + b.cursorY; i++) {
        if (b.getLine(i)?.translateToString(true).includes(m)) return true;
      }
      return false;
    };
    let echoed = false;
    for (let attempt = 1; attempt <= 3 && !echoed; attempt++) {
      await page.waitForFunction(
        (u) => document.getElementById("status")?.textContent === `connected as ${u}`,
        USER,
        { timeout: 30_000 },
      );
      const marker = `flood-ok-${Date.now()}`;
      await page.keyboard.type(`echo ${marker}\n`, { delay: 10 });
      echoed = await page
        .waitForFunction(seek, marker, { timeout: 12_000 })
        .then(() => true, () => false);
    }
    if (!echoed) {
      // The naked timeout said nothing about WHERE the echo went
      // missing; dump what the page can see before failing, so the
      // next reader of this log is not reduced to guessing.
      const state = await page.evaluate(() => {
        const b = window.__wosh.term.buffer.active;
        const lines = [];
        for (let i = Math.max(0, b.baseY + b.cursorY - 12); i <= b.baseY + b.cursorY; i++) {
          lines.push(b.getLine(i)?.translateToString(true) ?? "");
        }
        return {
          status: document.getElementById("status")?.textContent,
          cursorTail: lines,
          sheetOpen: document.getElementById("sheet")?.open,
          ask: document.querySelector("#sheet .confirm")?.innerText,
          pins: localStorage.getItem("wosh.hostkeys.v1"),
        };
      }).catch(() => "(page unreadable)");
      console.error("marker never echoed; page state:", JSON.stringify(state, null, 1));
      fail("after the flood, three echo probes went unanswered");
    } else {
      console.log("[L] a 300k-line flood with typing on top ends in a working shell (same or reborn)");
    }
  }
  // Detach lives in the session sheet: open from the header, tap.
  await page.click("#sessions-btn").catch(() => {});
  await page.click("#sheet button:has-text('detach')").catch(() => {});

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
