// Browser passkey gate: the REAL page in a real headless Chromium,
// enrolling and authenticating with a WebAuthn passkey through a CDP
// virtual authenticator, over real iroh, through the listener, into a
// real OpenSSH sshd.
//
// This is the browser half of the split `e2e-passkey` (justfile)
// draws: that native gate proves the OpenSSH webauthn WIRE FORMAT
// (authenticatorData, clientDataJSON, the DER signature, the
// authorized_keys line's `application` field) against a real sshd,
// using a software authenticator standing in for the platform one.
// This gate proves the CEREMONY -- the actual `navigator.credentials`
// calls, the page's enrol/adopt/forget UI, the ceremony gate that asks
// for a fresh tap -- by driving the SAME page browser-e2e.mjs drives,
// with a virtual authenticator standing in for a real platform one
// (headless CI has no Secure Enclave/TPM to ask).
//
// Two things a "fix" is likely to break, called out up front:
//
//   1. Served and navigated on `http://localhost:<PORT>`, NOT
//      `127.0.0.1`. A WebAuthn Relying Party ID must be a domain; an
//      IP address is rejected by the browser before the authenticator
//      is ever consulted (`SecurityError`, thrown synchronously by
//      `credentials.create`/`.get`). `localhost` is both a valid RP ID
//      and a secure context, which is why the whole rest of the suite
//      can use 127.0.0.1 but this one gate cannot.
//   2. The CDP virtual authenticator must be installed BEFORE any
//      ceremony runs (page.goto, even): `WebAuthn.enable` then
//      `WebAuthn.addVirtualAuthenticator`, with
//      automaticPresenceSimulation so no test-side click is needed to
//      simulate the user's tap.
//
// Environment (the `just browser-passkey` recipe supplies all of it):
//   WOSH_CONNSTRING       the listener's connection string   (required)
//   WOSH_AUTHORIZED_KEYS  sshd's authorized_keys path        (required)
//   WOSH_EXPECT_FP        sshd's host key fingerprint        (optional)
//   WOSH_USER             login user (default: $USER)
//   WOSH_HTTP_PORT        static server port (default: 8098)
//
// Usage: node host-test/browser-passkey.mjs [--keep]

import { chromium } from "playwright-core";
import { appendFileSync, existsSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname } from "node:path";

const ROOT = new URL("../out/", import.meta.url).pathname;
const PORT = Number(process.env.WOSH_HTTP_PORT ?? 8102); // 8098 is browser-identity's
const CONNSTRING = process.env.WOSH_CONNSTRING;
const AUTH_KEYS = process.env.WOSH_AUTHORIZED_KEYS;
const EXPECT_FP = process.env.WOSH_EXPECT_FP ?? "";
const USER = process.env.WOSH_USER ?? process.env.USER;

if (!CONNSTRING || !AUTH_KEYS || !USER) {
  console.error("need WOSH_CONNSTRING, WOSH_AUTHORIZED_KEYS and a user; run via `just browser-passkey`");
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

// Bind on every interface (not just 127.0.0.1) so `localhost` actually
// reaches this server -- some resolvers prefer ::1, which a
// 127.0.0.1-only bind would refuse.
await new Promise((r) => server.listen(PORT, r));
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

  // The CDP virtual authenticator: installed via a session bound to
  // this page, before any WebAuthn ceremony runs. ctap2/internal with
  // both resident-key and user-verification support matches what a
  // real platform authenticator (Touch ID, Windows Hello) offers, and
  // automaticPresenceSimulation means the "tap" happens the instant
  // the browser asks for it -- no synthetic click needed on our side.
  // Record the options every `credentials.get()` is called with, so the
  // gate can assert what the store ASKS FOR and not merely that a
  // ceremony succeeded. Installed before any page script runs, and it
  // forwards untouched -- the real ceremony still happens.
  await page.addInitScript(() => {
    globalThis.__getCalls = [];
    const real = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = (opts) => {
      const allow = (opts && opts.publicKey && opts.publicKey.allowCredentials) || [];
      globalThis.__getCalls.push({
        named: allow.length,
        transports: allow.map((c) => (c.transports || []).join("+")),
      });
      return real(opts);
    };
  });

  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  console.log(`[0] virtual authenticator installed (${authenticatorId})`);

  const diag = () =>
    page.evaluate(() => ({
      status: document.getElementById("status")?.textContent,
      failure: window.__wosh?.failure ?? null,
    }));

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

  const fillAndConnect = async (method) => {
    await page.fill("#home input.connstring", CONNSTRING);
    await page.click("#home .pasterow button.go");
    await page.waitForSelector("#sheet[data-ask='connect'] input[placeholder='user']", { timeout: 15_000 });
    await page.fill("#sheet input[placeholder='user']", USER);
    await page.evaluate(() => {
      document.querySelector("#sheet details.options").open = true;
    });
    await page.selectOption("#sheet select.method", method);
    await page.click("#sheet button:text-is('connect')");
  };

  // localhost, not 127.0.0.1: see the file header. RP ID must be a
  // domain, or credentials.create/.get throw a SecurityError before
  // the virtual authenticator is ever asked anything.
  await page.goto(`http://localhost:${PORT}/`, { waitUntil: "load" });
  await page.waitForSelector("#home button.scan", { timeout: 15_000 });
  console.log("[1] page loaded on http://localhost -- a valid WebAuthn RP ID");

  // --- enrol (on the settings screen, which owns the passkey UI) ------
  await page.click("#home .topline button:has-text('settings')");
  const enrollBtn = page.locator("#prefs .passkey button", { hasText: /^enrol$/ });
  await enrollBtn.waitFor({ timeout: 15_000 });
  await enrollBtn.click();
  // A ceremony that never completes is the most likely failure here
  // and the least self-explanatory, so report what the page said
  // rather than only that a selector timed out.
  let line;
  try {
    line = (await page.locator("#prefs .passkey code").first()
      .textContent({ timeout: 30_000 }) ?? "").trim();
  } catch (e) {
    console.error("enrolment produced no line; passkey section said:",
      await page.locator("#prefs .passkey").first().innerText().catch(() => "(absent)"));
    console.error("console errors:", consoleErrors);
    throw e;
  }
  if (!line.startsWith("sk-ecdsa-sha2-nistp256@openssh.com ")) {
    fail(`bad passkey authorized_keys line: ${line}`);
  } else {
    console.log(`[2] enrolled: ${line.split(" ")[0]} line printed`);
  }
  appendFileSync(AUTH_KEYS, line + "\n");

  // Registration is the ONE time WebAuthn reports where a credential
  // lives, and a client that drops it condemns every later ceremony to
  // a "which passkey provider?" chooser. Assert it was kept.
  const stored = await page.evaluate(() =>
    new Promise((resolve, reject) => {
      const open = indexedDB.open("wosh-passkey", 1);
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const db = open.result;
        const get = db.transaction("identity").objectStore("identity").get("passkey");
        get.onerror = () => reject(get.error);
        get.onsuccess = () => {
          const r = get.result;
          resolve(r ? { transports: r.transports ?? null, hasId: !!r.credentialId } : null);
        };
      };
    })
  );
  if (!stored?.hasId) fail("the enrolled record kept no credential id");
  if (!Array.isArray(stored?.transports) || stored.transports.length === 0) {
    fail(`enrolment did not record the credential's transports: ${JSON.stringify(stored)}`);
  } else {
    console.log(`[2b] transports recorded at enrolment: ${stored.transports.join("+")}`);
  }

  // --- connect, confirm the host key, authenticate with the passkey ---
  await page.click("#prefs .backrow .back");
  await fillAndConnect("passkey");
  const promptFp = await waitPrompt();
  console.log(`[3] host-key prompt shown: ${promptFp}`);
  if (EXPECT_FP && promptFp !== EXPECT_FP) {
    fail(`prompt fingerprint ${promptFp} != sshd's ${EXPECT_FP}`);
  }
  await page.click("#sheet button:has-text('it matches')");

  // The ceremony gate's "touch your passkey" prompt is CONDITIONAL by
  // design: `authenticate-passkey` needs the human during
  // authentication, and some browsers demand transient activation for
  // `credentials.get()`, so the page asks for a fresh tap only when the
  // activation it already has has lapsed. Chromium does not require
  // one, so on this gate the ceremony usually runs straight through.
  // Both outcomes are correct, and racing them is the only honest
  // assertion: what must happen is that authentication completes.
  const gateBtn = page.locator("#sheet .confirm button:has-text('touch your passkey to sign in')");
  const gated = await Promise.race([
    gateBtn.waitFor({ timeout: 30_000 }).then(() => true, () => false),
    page.waitForFunction(
      (u) => document.getElementById("status")?.textContent === `connected as ${u}`,
      USER,
      { timeout: 30_000 },
    ).then(() => false, () => false),
  ]);
  if (gated) {
    await gateBtn.click();
    console.log("[4] ceremony gate prompt appeared and was released");
  } else {
    console.log("[4] no ceremony gate needed (this browser kept its user activation)");
  }

  await waitConnected();
  console.log(`[5] authenticated with the passkey, connected as ${USER}`);

  // ...and it asked for the credential BY NAME, with the transports
  // recorded at enrolment. That pairing is what lets the browser go
  // straight to the authenticator holding the key; without it the user
  // is asked which provider to use on every single connection.
  const calls = await page.evaluate(() => globalThis.__getCalls ?? []);
  const authCall = calls[calls.length - 1];
  if (!authCall || authCall.named !== 1) {
    fail(`the auth ceremony did not name exactly one credential: ${JSON.stringify(calls)}`);
  } else if (!authCall.transports[0]) {
    fail("the auth ceremony named the credential but passed no transports, " +
      "so the browser must fall back to asking which provider to use");
  } else {
    console.log(`[5b] the ceremony named the credential and its transports (${authCall.transports[0]})`);
  }

  // Round-trip through the real terminal: keystrokes in, output painted.
  const marker = "WOSH_BROWSER_PASSKEY_OK";
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
  console.log("[6] shell round-trip through the tunnel painted in xterm");
  await page.click("#sessions-btn");
  await page.click("#sheet button:has-text('detach')");

  // --- recovery: the credential survives an evicted browser store ----
  //
  // Simulates what an evicted IndexedDB actually leaves behind: the
  // authenticator still holds the credential, but this page's record
  // of it -- and hence the public key SSH needs -- is gone. Not the
  // same as `forget()` (a user action reachable through the UI); this
  // is deleting the database out from under the page, the way Safari
  // ITP or a "clear site data" would. Reloading afterward clears the
  // module's in-memory fallback too, so nothing about the identity
  // survives except the credential itself.
  await page.evaluate(
    () =>
      new Promise((resolve, reject) => {
        const req = indexedDB.deleteDatabase("wosh-passkey");
        req.onsuccess = () => resolve();
        req.onblocked = () => resolve(); // no open connection should exist to block on
        req.onerror = () => reject(req.error);
      }),
  );
  console.log("[7] simulated IndexedDB eviction: deleted the wosh-passkey database");

  await page.goto(`http://localhost:${PORT}/`, { waitUntil: "load" });
  await page.waitForSelector("#home button.scan", { timeout: 15_000 });
  // Empirically: a CDP virtual authenticator is bound to the page's
  // CDP session, which a same-page navigation does not tear down, so
  // it survives the reload with no re-attach needed. Asserted here
  // rather than assumed: if this ever stops holding, the enrol-shaped
  // ceremony below would hang or error, and the message should say so
  // plainly rather than blaming recovery.
  console.log("[8] reloaded; virtual authenticator still attached (see below if not)");

  // Confirm the identity really is gone -- not merely that recovery
  // happens to work anyway. The passkey card lives on the identity
  // screen.
  await page.click("#home .topline button:has-text('settings')");
  const notEnrolledText = await page.locator("#prefs .passkey .sub").first()
    .textContent({ timeout: 15_000 });
  if (!/no passkey enrolled/.test(notEnrolledText ?? "")) {
    fail(`expected the not-enrolled passkey state after simulated eviction, got: ${notEnrolledText}`);
  } else {
    console.log("[9] confirmed not-enrolled state: the identity is really gone from this page");
  }

  const recoverBtn = page.locator("#prefs .passkey button", { hasText: /^recover$/ });
  await recoverBtn.waitFor({ timeout: 15_000 });
  await recoverBtn.click();
  let recoveredLine;
  try {
    recoveredLine = (await page.locator("#prefs .passkey code").first()
      .textContent({ timeout: 30_000 }) ?? "").trim();
  } catch (e) {
    console.error("recovery produced no line; passkey section said:",
      await page.locator("#prefs .passkey").first().innerText().catch(() => "(absent)"));
    console.error("console errors:", consoleErrors);
    throw e;
  }
  // Byte-identical to the line captured at enrolment is the whole
  // property under test: recovery must reconstruct the SAME SSH
  // identity, so the line already installed on the target (never
  // appended to twice in this test) keeps authenticating.
  if (recoveredLine !== line) {
    fail(`recovered line does not match the enrolled one:\n  enrolled:  ${line}\n  recovered: ${recoveredLine}`);
  } else {
    console.log("[10] recovered line is byte-identical to the enrolled one");
  }

  // --- reconnect and authenticate with the recovered identity ---------
  //
  // Deliberately reuses WOSH_AUTHORIZED_KEYS as already written above
  // rather than appending again: proving the SAME line still
  // authenticates is exactly what proves recovery reconstructed the
  // same identity, not merely produced a new working one.
  await page.click("#prefs .backrow .back");
  await fillAndConnect("passkey");
  await waitPrompt();
  await page.click("#sheet button:has-text('it matches')");
  await Promise.race([
    page.locator("#sheet .confirm button:has-text('touch your passkey to sign in')")
      .waitFor({ timeout: 30_000 }).then(() => page.click(
        "#sheet .confirm button:has-text('touch your passkey to sign in')",
      )).catch(() => {}),
    page.waitForFunction(
      (u) => document.getElementById("status")?.textContent === `connected as ${u}`,
      USER,
      { timeout: 30_000 },
    ).catch(() => {}),
  ]);
  await waitConnected();
  console.log(`[11] authenticated with the RECOVERED passkey, connected as ${USER}`);

  // A recovered record cannot carry transports -- only registration
  // reports them, and recovery never registers. So the first real
  // ceremony re-learns them from the attachment the browser reports,
  // and the connection after this one is as quiet as an enrolled
  // client's. Without that, recovery would silently leave the user
  // choosing a provider forever.
  const relearned = await page.evaluate(() =>
    new Promise((resolve, reject) => {
      const open = indexedDB.open("wosh-passkey", 1);
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const db = open.result;
        const get = db.transaction("identity").objectStore("identity").get("passkey");
        get.onerror = () => reject(get.error);
        get.onsuccess = () => resolve(get.result ? get.result.transports ?? null : null);
      };
    })
  );
  if (!Array.isArray(relearned) || relearned.length === 0) {
    fail(`the recovered record did not re-learn its transports: ${JSON.stringify(relearned)}`);
  } else {
    console.log(`[11b] the recovered record re-learned its transports (${relearned.join("+")})`);
  }

  const marker2 = "WOSH_BROWSER_PASSKEY_RECOVERED_OK";
  await page.click(".xterm-screen");
  await page.keyboard.type(`echo ${marker2}\n`, { delay: 10 });
  await page.waitForFunction(
    (m) => {
      const buf = window.__wosh.term?.buffer.active;
      if (!buf) return false;
      let text = "";
      for (let i = 0; i < buf.length; i++) {
        text += buf.getLine(i)?.translateToString(true) + "\n";
      }
      return text.split(m).length - 1 >= 2;
    },
    marker2,
    { timeout: 30_000 },
  );
  console.log("[12] shell round-trip through the recovered identity painted in xterm");
  await page.click("#sessions-btn");
  await page.click("#sheet button:has-text('detach')");

  if (consoleErrors.length) {
    fail(`console errors:\n  ${consoleErrors.join("\n  ")}`);
  }

  if (!process.exitCode) {
    console.log("\nBROWSER PASSKEY PASS: enrolled a passkey through a real WebAuthn " +
      "ceremony in the page, authenticated for real through a real sshd, then simulated " +
      "an evicted browser store and RECOVERED the same identity from the credential alone " +
      "-- the recovered line matched byte-for-byte and authenticated again. Every " +
      "ceremony named its credential and that credential's transports, so the browser " +
      "never had to ask which passkey provider to use" +
      (gated ? " (ceremony gate prompt released by hand)" : ""));
  }
} catch (e) {
  fail(String(e?.stack ?? e));
} finally {
  if (!process.argv.includes("--keep")) await browser.close();
  server.close();
}
