// wosh browser client: xterm.js in front of the SSH client component,
// runtime-linked by deltic (./dist/deltic.js, built by `just web-bundle`).
//
// The page is deliberately thin. Everything protocol-shaped -- parsing
// the connection string, dialing iroh, the SSH transport, the host-key
// gate, authentication, the pty -- lives inside the component behind
// `wosh:terminal`. The page feeds keystrokes, paints output, reports
// resizes, and renders the human decisions: whether the host key is
// the expected one, which credential to offer, and the answers to
// whatever the server asks (a password, or keyboard-interactive
// prompt batches -- one inline UI serves both).
//
// Every component export is Promise-shaped under deltic (including the
// ones the WIT declares as plain functions), so the output pump is a
// single async loop with ONE drainer -- two concurrent drains could
// interleave screen bytes out of order.

import { initMobile, transformInput } from "./mobile.mjs";
import { OverlayAddon } from "./overlay.mjs";

const DIST = {
  translator: "./dist/deltic-translator-shim.wasm",
  client: "./dist/wosh-ssh-client.wasm",
};

const statusEl = () => document.getElementById("status");
const status = (msg) => {
  statusEl().textContent = msg;
};

// Test hook, also the single place a failure is recorded.
window.__wosh = { failure: null, paintStats: null };

const fatal = (msg) => {
  status(`FAILED: ${msg}`);
  window.__wosh.failure = String(msg);
  throw new Error(msg);
};

// --- terminal ---------------------------------------------------------------
const term = new Terminal({
  fontSize: 14,
  cursorBlink: true,
  scrollback: 1000,
});
const fit = new FitAddon.FitAddon();
term.loadAddon(fit);
const overlay = new OverlayAddon();
term.loadAddon(overlay);
term.open(document.getElementById("term"));
fit.fit(); // synchronous: connect reads term.cols/rows immediately
term.focus();
// Test hook: the browser e2e gate reads the screen through the buffer
// API, because the canvas renderer leaves nothing scrapeable in the DOM.
window.__wosh.term = term;

// Refits beyond the first belong to the observer: everything that moves
// the terminal's BOX funnels through it -- the boot panel rendering
// (async, grows #panel), the extra-keys bar filling in, mobile.mjs
// resizing to the visual viewport, plain window resizes. A one-shot
// startup fit goes stale on the first of those.
new ResizeObserver(() => fit.fit()).observe(document.getElementById("term"));
addEventListener("resize", () => fit.fit()); // zoom edge cases; harmless overlap
initMobile(term); // soft-keyboard viewport glue + extra-keys bar
term.onResize(({ cols, rows }) => overlay.showOverlay(`${cols}×${rows}`, 500));

// --- painting ---------------------------------------------------------------
// rAF-coalesced writes, flushed rather than shed: pty output is a byte
// stream the remote believes arrived, so dropping is never correct.
// rAF starves in background tabs while the pump keeps draining on
// throttled timers, so a timer bounds the queue and hiding the tab
// flushes synchronously.
let chunks = [];
let rafId = null;
let flushTimer = null;
const paintStats = { peak: 0, flushes: 0, timerFlushes: 0 };
window.__wosh.paintStats = paintStats;

const flush = (viaTimer = false) => {
  if (rafId !== null) cancelAnimationFrame(rafId);
  if (flushTimer !== null) clearTimeout(flushTimer);
  rafId = null;
  flushTimer = null;
  paintStats.flushes++;
  if (viaTimer) paintStats.timerFlushes++;
  const batch = chunks;
  chunks = [];
  for (const c of batch) term.write(c);
};

const paint = (out) => {
  if (!out || !out.length) return;
  chunks.push(out);
  if (chunks.length > paintStats.peak) paintStats.peak = chunks.length;
  if (rafId === null) {
    rafId = requestAnimationFrame(() => flush());
    flushTimer = setTimeout(() => flush(true), 250);
  }
};

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden" && chunks.length) flush(true);
});

// A sleep the input path can cut short, so a keystroke's echo paints
// without waiting out the poll interval.
let wake = null;
const sleep = (ms) =>
  new Promise((resolve) => {
    const t = setTimeout(() => {
      wake = null;
      resolve();
    }, ms);
    wake = () => {
      clearTimeout(t);
      wake = null;
      resolve();
    };
  });
const wakeNow = () => wake?.();

// --- component --------------------------------------------------------------
let terminalApi = null;
let currentSession = null;

async function api() {
  if (!terminalApi) {
    const { loadClient } = await import(new URL("./dist/deltic.js", import.meta.url));
    status("loading the client component…");
    terminalApi = await loadClient(DIST.client, DIST.translator);
  }
  return terminalApi;
}

/**
 * Which credential kinds the loaded component actually supports.
 *
 * Publickey auth (and the WebCrypto identity behind it) is part of the
 * target interface but not yet implemented by every build, so the page
 * feature-detects rather than assuming: an older component still drives
 * a perfectly good password session.
 */
export async function capabilities() {
  const t = await api();
  // Resource methods live on the Session class deltic builds; if the
  // prototype is not inspectable, assume support -- the page and the
  // component ship together in one precache.
  const proto = t.Session?.prototype;
  return {
    publickey: typeof t.identityOpenssh === "function",
    password: true,
    keyboardInteractive: !proto || typeof proto.pendingPrompts === "function",
  };
}

/**
 * This browser's SSH identity as an `authorized_keys` line. The private
 * half is a non-extractable WebCrypto key: the component can sign with
 * it, nothing can export it. It persists -- the pair lives in IndexedDB
 * behind the component's `identity-store` import (identity-store.ts) --
 * so the same line keeps working across page loads.
 */
export async function identity() {
  const t = await api();
  if (typeof t.identityOpenssh !== "function") {
    throw new Error("this build of the client component has no WebCrypto identity yet");
  }
  return await t.identityOpenssh();
}

// Input wiring is re-established per session and the old handlers
// disposed, so a superseded session's handlers cannot keep feeding a
// dead object.
let wired = null;
const wireInput = (session, fail) => {
  wired?.data.dispose();
  wired?.resize.dispose();
  wired = {
    data: term.onData((s) => {
      if (currentSession !== session || window.__wosh.failure) return;
      // transformInput applies mobile.mjs's sticky Ctrl/Alt (identity
      // unless armed).
      session
        .writeInput(new TextEncoder().encode(transformInput(s)))
        .then(wakeNow, fail);
    }),
    resize: term.onResize(({ cols, rows }) => {
      if (currentSession !== session) return;
      session.resize(cols, rows).catch(fail);
    }),
  };
};

// A lifted WIT variant is `{ kind, value? }` (deltic embedder contract,
// A10). STRICT on purpose: this page once read `.tag` from an older
// convention, every status quietly became "unknown", and the host-key
// prompt was skipped -- the failure mode must be loud, never a default.
const statusOf = (s) => {
  const kind = s?.kind;
  if (typeof kind !== "string") {
    throw new Error(`unrecognized session status shape: ${JSON.stringify(s)}`);
  }
  return kind;
};

/** Poll `status` until it leaves `connecting`, or time out. */
async function settle(session, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const st = await session.status();
    const tag = statusOf(st);
    if (tag !== "connecting") return st;
    if (Date.now() > deadline) throw new Error("timed out during connect");
    await sleep(50);
  }
}

/**
 * Connect and run the session. `ui` supplies the human decisions:
 *
 *   confirmHostKey(fingerprint, connstring) -> boolean
 *     (may resolve without interaction ONLY for a fingerprint the user
 *     previously approved and asked to remember; see boot.mjs)
 *   getCredential()            -> {kind: "publickey"}
 *                               | {kind: "password", password?}
 *                               | {kind: "keyboard-interactive"}
 *   collectPrompts(batch)      -> string[] (one answer per prompt;
 *                                 batch is {instruction, prompts:
 *                                 [{text, echo}]}, echo=false meaning
 *                                 mask the input)
 *
 * A password credential normally arrives WITHOUT the password: it is
 * collected through `collectPrompts` right here, after the host key is
 * confirmed -- the same inline UI keyboard-interactive uses, instead
 * of a standing text input. A caller that already holds the password
 * may still supply it.
 */
export async function connect({ connstring, user, ui }) {
  const t = await api();
  status("dialing over iroh…");

  // deltic maps a WIT resource to a PascalCase class, with the WIT
  // static as a static method on it.
  const session = await t.Session.connect(connstring, user, term.cols, term.rows);
  currentSession = session;

  let st = await settle(session);
  if (statusOf(st) === "closed") fatal(`connect: ${st.value ?? "closed"}`);

  // --- the host-key gate: nothing has been sent to the server yet ---
  //
  // The gate is NOT optional (TOFU): every fresh session must surface
  // the fingerprint and get an interactive yes before any credential
  // is offered. A status other than host-key-check here means this
  // page no longer understands the component's state machine, and the
  // only safe response is to refuse to proceed. The component enforces
  // the same rule on its side (authenticate-* fails before confirm),
  // so a bug in either layer fails closed rather than skipping the
  // human.
  if (statusOf(st) !== "host-key-check") {
    fatal(`expected the host-key gate, got status "${statusOf(st)}"`);
  }
  const fp = await session.hostKeyFingerprint();
  status("waiting for host key confirmation");
  // The connstring rides along so the ui can key its pin store by the
  // listener identity actually being dialed (not whatever is in the
  // form NOW).
  const ok = await ui.confirmHostKey(fp ?? "(unavailable)", connstring);
  await session.confirmHostKey(!!ok);
  if (!ok) {
    status("host key rejected; nothing was sent");
    currentSession = null;
    return null;
  }

  // --- credentials --------------------------------------------------
  status("authenticating…");
  const cred = await ui.getCredential();
  try {
    if (cred.kind === "password") {
      const password = typeof cred.password === "string"
        ? cred.password
        : (await ui.collectPrompts({
            instruction: "",
            prompts: [{ text: `password for ${user}: `, echo: false }],
          }))[0] ?? "";
      // `authenticate-password` is the target name; older builds expose
      // the password path as plain `authenticate`.
      await (session.authenticatePassword
        ? session.authenticatePassword(password)
        : session.authenticate(password));
    } else if (cred.kind === "keyboard-interactive") {
      await session.authenticateInteractive();
    } else {
      await session.authenticatePublickey();
    }
  } catch (e) {
    // A WIT err from authenticate-* is a ComponentException whose
    // payload IS the error string (result<_, string> in return
    // position, embedder contract §"Error model").
    fatal(`authentication: ${typeof e?.payload === "string" ? e.payload : e.message ?? e}`);
  }

  // Keyboard-interactive is server-driven: poll for prompt batches and
  // hand each to the panel until authentication settles one way or the
  // other. (No deadline -- a human is typing; the ssh transport itself
  // closes the session if the server goes away.)
  if (cred.kind === "keyboard-interactive") {
    for (;;) {
      const st = await session.status();
      const tag = statusOf(st);
      if (tag === "ready") break;
      if (tag === "closed") fatal(`authentication: ${st.value ?? "closed"}`);
      if (tag === "auth-prompts") {
        const batch = await session.pendingPrompts();
        if (batch) {
          status("the server asks:");
          const answers = await ui.collectPrompts(batch);
          await session.answerPrompts(answers);
          status("authenticating…");
          continue;
        }
      }
      await sleep(50);
    }
  }

  status(`connected as ${user}`);
  term.focus();
  wireInput(session, (e) => sessionEnded(session, `input: ${e.message ?? e}`));

  // The single output drainer for this session.
  (async () => {
    try {
      for (;;) {
        if (currentSession !== session) return; // superseded
        paint(await session.drainOutput());
        if (await session.exited()) {
          const code = await session.exitStatus();
          sessionEnded(session, code === undefined ? "session ended" : `exited (${code})`);
          return;
        }
        await sleep(8);
      }
    } catch (e) {
      sessionEnded(session, `pump: ${e.message ?? e}`);
    }
  })();

  return session;
}

function sessionEnded(session, why) {
  if (currentSession !== session) return;
  currentSession = null;
  flush(true);
  status(why);
}

/** Tear the session down and close the iroh connection. */
export async function detach() {
  const s = currentSession;
  if (!s) return;
  currentSession = null;
  try {
    await s.detach();
  } finally {
    status("detached");
  }
}
