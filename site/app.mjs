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

import { autofocusTerminal, initMobile, transformInput } from "./mobile.mjs";
import { initLifecycle } from "./lifecycle.mjs";
import { linkHandler } from "./links.mjs";
import { markSessionEnd, markSessionStart } from "./separator.mjs";
import { OverlayAddon } from "./overlay.mjs";
import * as bufferStore from "./buffer-store.mjs";

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
  // The unicode-11 addon registers through `term.unicode`, which xterm
  // gates behind this flag (a stability marker, not a feature toggle).
  allowProposedApi: true,
});
const fit = new FitAddon.FitAddon();
term.loadAddon(fit);
const overlay = new OverlayAddon();
term.loadAddon(overlay);
term.open(document.getElementById("term"));
fit.fit(); // synchronous: connect reads term.cols/rows immediately

// --- the rest of the addon family --------------------------------------
// All progressive enhancement, each behind its own try: a device that
// refuses one (no WebGL, no clipboard permission) still gets a fully
// working terminal, and the console says what degraded. What activated
// is recorded on the test hook, because several of these are exactly
// one easily-lost script tag or builder call, and only a gate that can
// SEE them keeps them wired (host-test/browser-links.mjs).
// A module-level handle to the serialize addon, set inside the guard
// below (null if it never loaded -- a stale precache without the
// script tag, same degrade-silently posture as every other addon
// here). Held outside the IIFE because the persistence cadence in
// connect() below needs to call serialize() on it directly.
let serializeAddon = null;

window.__wosh.addons = (() => {
  const active = {
    unicode: null, clipboard: null, links: false, image: null, webgl: false, serialize: false,
  };
  const enhance = (what, load) => {
    try {
      load();
    } catch (e) {
      console.warn(`wosh: ${what} unavailable`, e);
    }
  };
  // Width tables for Unicode 11: emoji and modern CJK render two cells
  // wide, matching what the remote pty computed. Without this, any
  // prompt with an emoji in it smears every redraw one cell left.
  enhance("unicode 11 widths", () => {
    term.loadAddon(new Unicode11Addon.Unicode11Addon());
    term.unicode.activeVersion = "11";
    active.unicode = term.unicode.activeVersion;
  });
  // OSC 52 clipboard, WRITE-ONLY. This is how tmux's set-clipboard and
  // vim/nvim yanks reach the system clipboard through an SSH session.
  // The read half is refused outright -- answered empty, not prompted:
  // a remote host querying the local clipboard is an exfiltration
  // primitive, and this page's posture is that the remote shell is not
  // trusted with anything it did not produce.
  enhance("clipboard (OSC 52)", () => {
    const writeOnly = {
      async readText() {
        return "";
      },
      async writeText(_selection, text) {
        try {
          await navigator.clipboard.writeText(text);
        } catch {
          /* no permission, or no user activation: the yank just does not land */
        }
      },
    };
    term.loadAddon(new ClipboardAddon.ClipboardAddon(undefined, writeOnly));
    active.clipboard = "write-only";
  });
  // Web links, single tap, behind the confirmation dialog links.mjs
  // owns (which is what makes single-tap safe; see that file).
  enhance("web links", () => {
    const handler = linkHandler(document.getElementById("linkdialog"), {
      refocus: () => autofocusTerminal(term),
    });
    term.loadAddon(new WebLinksAddon.WebLinksAddon(handler));
    active.links = true;
  });
  // Inline images (sixel + iTerm IIP). The addon object rides the test
  // hook: its storageUsage is the only outside evidence a sixel landed.
  enhance("inline images", () => {
    const image = new ImageAddon.ImageAddon();
    term.loadAddon(image);
    active.image = image;
  });
  // The WebGL renderer, last: it needs the opened terminal, and on a
  // lost context it disposes itself, which falls the terminal back to
  // the DOM renderer -- slower, never wrong.
  enhance("webgl renderer", () => {
    const webgl = new WebglAddon.WebglAddon();
    webgl.onContextLoss(() => webgl.dispose());
    term.loadAddon(webgl);
    active.webgl = true;
  });
  // Buffer serialization: reconstructs scrollback + colors from a dump
  // (site/buffer-store.mjs), so a reattach or reload does not open
  // onto a blank screen. `typeof` guard same as every other addon here
  // -- a stale service-worker precache missing the script tag degrades
  // to "no restore, no periodic save", not a broken page.
  enhance("scrollback serialization", () => {
    serializeAddon = new SerializeAddon.SerializeAddon();
    term.loadAddon(serializeAddon);
    active.serialize = true;
  });
  return active;
})();

autofocusTerminal(term); // not on a phone: see mobile.mjs (focus != keyboard)
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

// Whether ANYTHING has painted yet this page load, and whether output
// has arrived since the last periodic scrollback save. Both flip in
// paint() -- the one chokepoint every byte, from every session,
// crosses on its way to the screen -- rather than being duplicated at
// each call site.
let everPainted = false;
let dirtySincePersist = false;

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
  everPainted = true;
  dirtySincePersist = true;
  chunks.push(out);
  if (chunks.length > paintStats.peak) paintStats.peak = chunks.length;
  if (rafId === null) {
    rafId = requestAnimationFrame(() => flush());
    flushTimer = setTimeout(() => flush(true), 250);
  }
};

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

// Whose content the terminal is currently showing, for the saves
// below. One page has ONE terminal, and serialize() captures the whole
// buffer -- so the moment bytes attributable to two different
// persistence keys (two hosts, or two accounts on one host) have
// landed on the same screen, saving that buffer under either key would
// file one host's scrollback in the other's slot. The honest response
// is to stop persisting for the rest of the page load, not to guess.
// `null` = nothing claimed yet; a key (or UNKEYED, for a session that
// persists nothing) = sole owner so far; `false` = mixed, saves off.
const UNKEYED = Symbol("unkeyed");
let terminalOwner = null;
const claimTerminal = (key) => {
  const k = key || UNKEYED;
  if (terminalOwner === null) terminalOwner = k;
  else if (terminalOwner !== k) terminalOwner = false;
};

/**
 * Write a serialize() dump straight to the terminal -- reconstructing
 * scrollback, colors and cursor in one term.write -- but ONLY when
 * nothing has painted yet this page load, and only once. `everPainted`
 * is the pristine check: an in-page reconnect (a `lost` session
 * auto-redialing, or a manual reconnect without a reload) already has
 * the REAL scrollback sitting on screen, produced by whatever the
 * previous session actually ran -- writing a stale dump over that
 * would be a lie, not a restore. A fresh page load is the only moment
 * this is honest: there is nothing on screen yet to contradict.
 * The dump claims the terminal for `key` (see claimTerminal): restored
 * content is content, and it belongs to the key it was saved under.
 * Returns whether it restored, so the caller can decide whether to
 * print the "restored scrollback from…" note.
 */
let restored = false;
async function restoreScrollback(text, key) {
  if (everPainted || restored || !text) return false;
  restored = true;
  claimTerminal(key);
  await new Promise((resolve) => term.write(text, resolve));
  // Sanitize MODES after the content, unconditionally. Dumps saved
  // before SCROLLBACK_SERIALIZE_OPTIONS existed replay whatever
  // terminal modes were live at save time -- a tmux session with
  // `mouse on` (or vim/htop inside it) restores mouse tracking into a
  // page whose NEW session may never enable it, and from then on every
  // touch, wheel and click is typed into the pty as escape-sequence
  // junk instead of scrolling: the session reads as "unresponsive
  // until reload". The reset also covers any dump the exclusions ever
  // miss. Written after the dump and before the live session's first
  // output, so whatever the attaching program actually wants it sets
  // itself, on a known-clean slate.
  await new Promise((resolve) => term.write(SCROLLBACK_MODE_RESET, resolve));

  await parkBelowContent(term);
  return true;
}

/**
 * Move the cursor below every non-blank line, so whatever is written
 * next APPENDS instead of overwriting.
 *
 * Needed after restoring a dump: a serialize() dump ends by restoring
 * the cursor to where it WAS, and that is not necessarily after the
 * last line of content -- a full-screen redraw (what dtach's `-r winch`
 * asks the program for) leaves it high on the screen with content
 * below it. Everything the page appends next (the seam note, the
 * session bookend, the new session's first output) then lands ON
 * restored lines, leaving their tails sticking out beside it. Observed
 * exactly that: "[wosh] restored scrollback from 2 h ago" with the tail
 * of a banner line beside it, and the start rule drawn across another.
 *
 * Exported for the gate that pins this (browser-links).
 */
export async function parkBelowContent(term) {
  const buf = term.buffer.active;
  let last = -1;
  for (let i = 0; i < buf.length; i++) {
    if ((buf.getLine(i)?.translateToString(true) ?? "").trim()) last = i;
  }
  // Newlines rather than absolute positioning: at the bottom of the
  // buffer they scroll, which is what "append below the history" has to
  // mean once the history already fills the screen.
  const below = last + 1 - (buf.baseY + buf.cursorY);
  await new Promise((resolve) =>
    term.write(below > 0 ? "\r\n".repeat(below) : "\r", resolve));
}

/**
 * What restoreScrollback writes after a dump: every mode the serialize
 * addon knows how to emit, forced back to its default. Content is the
 * only thing a restore is FOR; modes belong to the live session.
 * Exported for the gate that pins this contract (browser-links).
 */
export const SCROLLBACK_MODE_RESET =
  "\x1b[?1049l" + // back to the normal screen; alt-screen content is not scrollback
  "\x1b[?9l\x1b[?1000l\x1b[?1002l\x1b[?1003l" + // every mouse-tracking flavor off
  "\x1b[?1004l" + // focus reporting off
  "\x1b[?2004l" + // bracketed paste off
  "\x1b[?1l\x1b>" + // cursor keys and keypad back to normal
  "\x1b[4l" + // insert mode off
  "\x1b[?6l" + // origin mode off
  "\x1b[?45l" + // reverse-wraparound off
  "\x1b[?7h"; // autowrap back on (the one default-true mode serialize touches)

/**
 * Serialize options for the persisted dump: content only.
 *
 * Modes are excluded because restoring them is never right: the next
 * session's program re-establishes exactly the modes it wants (a tmux
 * attach sends its whole init), so a restored mode is either redundant
 * or -- when the new session wants it OFF -- an input-corrupting lie;
 * mouse tracking was the observed case. The alternate buffer is
 * excluded because it defeats the feature: tmux holds the outer
 * terminal in the alt screen, so an unexcluded dump restores INTO the
 * alt buffer, where there is no scrollback to show and the seam notes
 * land on the wrong screen. Exported for the same gate.
 */
export const SCROLLBACK_SERIALIZE_OPTIONS = Object.freeze({
  excludeModes: true,
  excludeAltBuffer: true,
});

// A cap on the serialized dump this persists, not a ration: IndexedDB
// quotas are opaque -- they vary per browser, per origin, and per how
// full the device already is -- and there is no reliable way to ask
// "how much is left" before writing. A runaway buffer (someone `cat`ed
// a very large file) must not wedge the 8ms output pump serializing an
// ever-larger dump on every tick; skipping the save is the safe
// failure, not growing the cap.
const SCROLLBACK_SAVE_CAP = 768 * 1024;

/**
 * Serialize the terminal and save it under `key`, fire-and-forget.
 * Silently a no-op without a key (persistence off for this session) or
 * without the addon (a stale precache missing the script tag -- see
 * the addon family block). Errors are swallowed after one warning:
 * scrollback persistence is a nicety, never something worth surfacing
 * to the person trying to use the terminal.
 */
/**
 * Whether a dump of `t` is worth persisting right now: not while the
 * ALTERNATE screen is active. Full-screen programs -- tmux and screen
 * always, vim or htop under any shell -- own that screen and repaint
 * it themselves on the next attach; what they show is not scrollback,
 * and serialize() excludes it anyway (SCROLLBACK_SERIALIZE_OPTIONS).
 * A save taken then would just re-write the STALE normal buffer --
 * and, worse, overwrite a genuinely valuable dump from an earlier
 * plain-shell or dtach session under the same (host, user) key with
 * whatever banner happened to precede tmux. Waiting until the
 * alternate screen closes means the dump is always the most recent
 * moment the normal buffer was the real story. Exported for the
 * browser-links gate that pins this.
 */
export const dumpWorthSaving = (t) => t.buffer.active.type !== "alternate";

async function saveScrollback(key) {
  if (!key || !serializeAddon) return;
  // Ownership gate (see claimTerminal): save only a buffer whose
  // content is attributable to THIS key alone. A page that has shown
  // another key's bytes -- an earlier session to a different host, or
  // a restored dump for one -- must not persist the mixture anywhere.
  if (terminalOwner !== key) return;
  if (!dumpWorthSaving(term)) return;
  try {
    const buf = serializeAddon.serialize(SCROLLBACK_SERIALIZE_OPTIONS);
    if (buf.length > SCROLLBACK_SAVE_CAP) return;
    await bufferStore.put(key, buf);
  } catch (e) {
    console.warn("wosh: could not save scrollback", e);
  }
}

// --- component --------------------------------------------------------------
// Memoized as a PROMISE, not a value: the boot-time capabilities probe
// and an early connect click can overlap, and caching the resolved API
// would let the second caller start a second instantiation. Every
// status this loader sets it also leaves -- the boot probe finishes
// without another status write, so a stale "loading…" would sit on
// screen forever (it did).
let clientLoad = null;
let currentSession = null;
// The persistence key (boot.mjs's `${endpointId} ${user}`) for whatever
// session is current, or null when this session isn't persisting
// scrollback at all. Mirrors currentSession so the lifecycle flush
// below -- which only ever sees "whatever the current session is" --
// knows what to save without connect() re-registering a callback per
// session.
let currentPersistKey = null;

// The page going away and coming back is a session event, not just a
// painting one: see lifecycle.mjs. The flush stays on the moment it
// always had -- the last frame before the page stops getting them.
initLifecycle(() => currentSession, () => {
  if (chunks.length) flush(true);
  // Same moment, same reasoning: the last frame before the page stops
  // being scheduled is also the last chance to persist what is on
  // screen before an iOS suspend or a tab close.
  saveScrollback(currentPersistKey);
});

function api() {
  clientLoad ??= (async () => {
    const { loadClient } = await import(new URL("./dist/deltic.js", import.meta.url));
    status("loading the client…");
    try {
      const t = await loadClient(DIST.client, DIST.translator);
      status("ready");
      return t;
    } catch (e) {
      // Leave the cache empty so a later call retries (a transient
      // fetch failure should not brick the page until a reload).
      clientLoad = null;
      status("failed to load the client");
      throw e;
    }
  })();
  return clientLoad;
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
    auto: !proto || typeof proto.authenticateAuto === "function",
    publickey: typeof t.identityOpenssh === "function",
    password: true,
    keyboardInteractive: !proto || typeof proto.pendingPrompts === "function",
    // Two independent things must both be true: the component build
    // must export the passkey surface (an older precache may not),
    // and the platform must actually support WebAuthn at all (some
    // browsers, and non-secure-context http serving, do not expose
    // PublicKeyCredential).
    passkey: typeof t.enrollPasskey === "function" && !!globalThis.PublicKeyCredential,
    // NOTE the absence of a probe for on-connect commands (the
    // trailing `option<string>` terminal.wit's `connect` grew): a
    // parameter is not an export, so there is nothing reliable to
    // inspect -- deltic builds `Session.connect` at runtime and its
    // JS arity does not reflect the WIT signature (measured: the
    // real class reported 0). An arity probe here disabled the
    // feature for every real page while guarding a state the
    // service worker's version-keyed ATOMIC precache (sw.js) makes
    // unreachable: one deploy is one complete cache, so a new page
    // never runs against an old component. Presence checks like the
    // ones above stay; signature checks are not a thing this page
    // can do honestly.
    // One-shot commands on a second channel of the live connection
    // (terminal.wit's `probe`), which is how the page can ask a target
    // what session managers it has and what sessions are on it without
    // touching the pty. Same assume-when-uninspectable philosophy as
    // keyboardInteractive above: a prototype we cannot read belongs to
    // a component that shipped with this page.
    probe: !proto || typeof proto.probe === "function",
  };
}

/**
 * Run one short command on the target, on a SECOND channel of the live
 * authenticated connection: no pty, output unmangled, nothing typed
 * into whatever the user is doing in the terminal. Returns
 * `{ code, text }` -- or `null`, never a throw, because a probe is a
 * QUESTION the page asks on its own initiative, and nothing the user
 * asked for may break because one went unanswered.
 */
export async function probeSession(command) {
  const s = currentSession;
  if (!s) return null; // nothing live to ask: not connected, or just ended
  if (typeof s.probe !== "function") return null; // stale precache: old component, new page
  try {
    const r = await s.probe(command);
    // A lifted record is an object with camelCase fields; `exit-status`
    // is an option, so it is the bare number or undefined (deltic
    // embedder contract), and `output` arrives as a Uint8Array or a
    // plain array of bytes depending on the lifting path.
    const bytes = r?.output instanceof Uint8Array
      ? r.output
      : new Uint8Array(r?.output ?? []);
    return {
      code: r?.exitStatus ?? null,
      text: new TextDecoder().decode(bytes),
    };
  } catch {
    // A failed or timed-out probe (the component gives up after ~15s),
    // a channel the server refused, a session that died underneath:
    // all the same answer, which is "no answer".
    return null;
  }
}

/**
 * Type a session manager's detach keys into the pty and wait, briefly,
 * to see whether the session actually goes away -- a clean manager
 * detach closes the SSH channel, which is the only observable
 * difference between "the tool understood the keys" and "the tool has
 * them remapped and just received junk". Returns whether the session
 * ended within `graceMs`; a false means the caller should fall back to
 * a hard detach.
 */
export async function sendDetachKeys(keys, graceMs = 2000) {
  const s = currentSession;
  if (!s || typeof s.writeInput !== "function") return false;
  try {
    await s.writeInput(new TextEncoder().encode(keys));
  } catch {
    return false;
  }
  const deadline = Date.now() + graceMs;
  for (;;) {
    // Identity guard: a supersession (or an end the pump already
    // noticed) replaces currentSession, and polling the session we no
    // longer own would answer a question about somebody else's.
    if (currentSession !== s) return true;
    try {
      if (await s.exited()) return true;
    } catch {
      return false; // cannot tell: let the hard detach be sure
    }
    if (Date.now() >= deadline) return false;
    await new Promise((r) => setTimeout(r, 100));
  }
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

/**
 * This client's enrolled PASSKEY identity as an `authorized_keys` line
 * (`sk-ecdsa-sha2-nistp256@openssh.com ...`), or `null` when none is
 * enrolled. Mirrors `identity()`, but the private half never exists in
 * this component or this page -- it lives in the platform
 * authenticator (see site/passkey-store.ts).
 */
export async function passkeyIdentity() {
  const t = await api();
  if (typeof t.passkeyOpenssh !== "function") {
    throw new Error("this build of the client component has no passkey support yet");
  }
  const line = await t.passkeyOpenssh();
  // A lifted WIT `option` is the bare value, or `undefined` for none
  // (deltic embedder contract, values.ts): the `{kind, value}` spelling
  // is only for an option nested directly inside another option, which
  // this is not. Normalised to null so callers can test one falsy
  // shape.
  return line ?? null;
}

/**
 * Run a WebAuthn registration ceremony and enrol its result as this
 * client's passkey identity, replacing any previous one. Returns the
 * new `authorized_keys` line. The user is asked to approve the
 * ceremony; a refusal or timeout surfaces as a rejected promise.
 */
export async function enrollPasskey() {
  const t = await api();
  return await t.enrollPasskey();
}

/**
 * Recover this client's passkey identity from the credential itself --
 * for when the browser storage that described it is gone (evicted,
 * cleared, a different profile) but the passkey still exists. Asks
 * the authenticator to sign twice (the same passkey both times) and
 * works the public half out of the two signatures. Returns the new
 * `authorized_keys` line, identical to the one from when it was first
 * enrolled.
 */
export async function recoverPasskey() {
  const t = await api();
  return await t.recoverPasskey();
}

/**
 * Adopt a passkey identity enrolled on another device, from the
 * `authorized_keys` line it printed there. The passkey itself must
 * already be reachable from this device (a synced passkey) -- this
 * only supplies the public half the assertion ceremony cannot return.
 */
export async function adoptPasskey(line) {
  const t = await api();
  return await t.adoptPasskey(line);
}

/**
 * Stop offering the enrolled passkey. The credential itself survives
 * in the authenticator; only this client forgets it.
 */
export async function forgetPasskey() {
  const t = await api();
  return await t.forgetPasskey();
}

/**
 * Install the pre-assertion ceremony gate (site/passkey-store.ts's
 * `setCeremonyGate`): called before a WebAuthn `get()` that might lack
 * a live user gesture (the server's demand for a signature during
 * `authenticate-passkey` arrives while the page is polling, not while
 * the user is clicking anything). `fn` is an async callback that
 * should resolve once the user has made a fresh gesture (e.g. tapped
 * a "touch your passkey" prompt); pass `undefined` to clear it.
 *
 * Routed through the bundled deltic module rather than imported
 * directly, because passkey-store.ts is TypeScript bundled by `just
 * web-bundle` -- boot.mjs, loaded unbundled by the browser, cannot
 * import a .ts file directly.
 */
export async function installPasskeyCeremonyGate(fn) {
  const { setCeremonyGate } = await import(new URL("./dist/deltic.js", import.meta.url));
  setCeremonyGate(fn);
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
/**
 * One call into the client component at a time.
 *
 * deltic enforces the component model's reentrance rule at the host
 * boundary, and under load the enforcement is reachable: flood the
 * terminal with output while keystrokes go the other way, and a
 * `write-input` can arrive while the pump's `drain-output` still has
 * the instance entered -- the call traps `cannot enter component
 * instance N (reentrance forbidden)`, and A TRAP POISONS THE INSTANCE:
 * every later call fails the same way and the session is
 * unrecoverable. Reproduced live with `seq 1 400000` plus concurrent
 * writes; xterm does it with no typing at all, because it auto-answers
 * the cursor-position queries full-screen programs emit (ESC[6n ->
 * onData -> write-input) while their output is still flooding in.
 *
 * So the page single-files itself: every quick session call rides one
 * promise chain, so no two of ours are ever inside the instance at
 * once. The chain ignores its members' failures (each caller still
 * sees its own); ordering is preserved, which for write-input is a
 * feature -- keystrokes stay in the order they were typed.
 *
 * `suspend` and `wake` ride the same gate as everything else. The one
 * reason not to gate them -- `wake` used to hold its host call open
 * for the length of a transport resume, which would have stalled every
 * queued keystroke behind it -- is fixed at the source: the guest now
 * SPAWNS the resume and returns, so wake is as quick as the rest.
 */
const GATED = [
  "status", "linkState", "closeKind", "hostKeyFingerprint",
  "confirmHostKey", "authenticatePassword", "authenticatePublickey",
  "authenticatePasskey", "authenticateInteractive", "authenticateAuto",
  "pendingPrompts", "answerPrompts", "writeInput", "resize",
  "drainOutput", "exited", "exitStatus", "detach", "suspend", "wake",
  "authenticate", // the pre-split spelling older component builds export
];
function serializeSession(session) {
  let chain = Promise.resolve();
  const wrapped = {};
  // The death path's escape hatch: sessionEnded must ask close-kind
  // withOUT the gate. On a poisoned instance every gated call queues
  // behind the retries already in the chain (15s each), which would
  // hold the session-ended event -- and the automatic reconnect behind
  // it -- for minutes. The raw call fails in microseconds instead,
  // which is an answer too.
  if (typeof session.closeKind === "function") {
    wrapped.closeKindRaw = session.closeKind.bind(session);
  }
  // `probe` is deliberately NOT in the chain above. It is a WIT `async
  // func` that waits on the target to finish running a command -- up to
  // fifteen seconds -- and the guest is not INSIDE the instance for any
  // of that wait (it awaits; the component model lets the instance be
  // re-entered meanwhile). Queueing it would therefore buy nothing
  // against reentrance while parking every keystroke and every drain
  // behind a command someone typed nothing to see. It still goes
  // through enterPatiently, which is the part that actually guards the
  // door: a probe that starts while the instance is momentarily busy
  // retries instead of poisoning it.
  if (typeof session.probe === "function") {
    const probe = session.probe.bind(session);
    wrapped.probe = (...args) => enterPatiently(() => probe(...args));
  }
  for (const name of GATED) {
    if (typeof session[name] !== "function") continue; // older component builds
    const method = session[name].bind(session);
    wrapped[name] = (...args) => {
      const run = chain.then(() => enterPatiently(() => method(...args)));
      chain = run.then(
        () => {},
        () => {}, // a failed call must not jam the calls behind it
      );
      return run;
    };
  }
  return wrapped;
}

/**
 * Call, and if the instance was momentarily busy, call again.
 *
 * Serializing our own calls is necessary but not sufficient: a call's
 * promise can resolve a beat before the instance is actually LEFT (the
 * guest returns its value and then runs a short tail), so the next
 * call -- ours, properly queued -- can still land in the closing door.
 * The entry check throws before anything enters, so nothing is
 * poisoned and the call is safely repeatable: the door was closing,
 * not broken. Bounded, so a genuinely wedged instance still surfaces
 * as the error it is rather than as an infinite quiet retry.
 */
async function enterPatiently(call, budgetMs = 15_000) {
  const deadline = Date.now() + budgetMs;
  let delay = 5;
  for (;;) {
    try {
      return await call();
    } catch (e) {
      const msg = String(e?.message ?? e);
      if (!msg.includes("reentrance forbidden") || Date.now() > deadline) throw e;
      // Time-based, not attempt-based: under a sustained flood the
      // guest's own tasks keep the instance busy in long stretches,
      // and a fixed handful of quick retries loses to them. Fifteen
      // seconds is far beyond any burst the reader can sustain
      // (drain empties the buffer it fills), and a genuinely wedged
      // instance still surfaces within one human sigh.
      //
      // A plain private timer: the module-level `sleep` shares its
      // wake slot with the pump, and concurrent sleeps would clobber
      // each other's shortcut.
      await new Promise((r) => setTimeout(r, delay));
      delay = Math.min(delay * 2, 50);
    }
  }
}

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
 *   getCredential()            -> {kind: "auto"}
 *                               | {kind: "publickey"}
 *                               | {kind: "passkey"}
 *                               | {kind: "password", password?}
 *                               | {kind: "keyboard-interactive"}
 *   collectPrompts(batch)      -> string[] (one answer per prompt;
 *                                 batch is {instruction, prompts:
 *                                 [{text, echo}]}, echo=false meaning
 *                                 mask the input) | null (the user
 *                                 cancelled: the attempt is torn down)
 *
 * `command`, when a non-empty string, is run on the target INSTEAD of
 * a plain login shell (an SSH exec request). Empty or absent means the
 * ordinary shell. Nothing here interprets it: it is the target's shell
 * that parses the line.
 *
 * `persistKey`, when present, turns on periodic scrollback persistence
 * for this session (site/buffer-store.mjs, keyed by boot.mjs as
 * `${endpointId} ${user}`): the output pump below saves a serialize()
 * dump every ~10s while there is new output to save, plus once at the
 * lifecycle flush moment and once when the session ends. Absent means
 * no saving at all -- the caller's opt-out (the session fold's toggle).
 *
 * An auto credential offers every method and lets the server steer
 * (publickey first, silently, when the browser's key is installed);
 * whatever needs typing arrives as prompt batches below.
 *
 * A password credential normally arrives WITHOUT the password: it is
 * collected through `collectPrompts` right here, after the host key is
 * confirmed -- the same inline UI keyboard-interactive uses, instead
 * of a standing text input. A caller that already holds the password
 * may still supply it.
 */
/**
 * The one server-side reason a passkey fails that no error message
 * explains, spelled out where the user will see it.
 *
 * OpenSSH has verified browser-webauthn signatures since 8.4, but only
 * 10.3 and later accept the algorithm without being told to. Older
 * servers refuse the OFFER -- before any signature is examined -- so
 * what comes back is an unremarkable "no supported methods remain"
 * with nothing pointing at the cause. Rather than guess (the client
 * cannot tell this apart from a key that is simply not installed),
 * this appends the check worth making first, and only when the passkey
 * was the credential actually asked for. Auto is deliberately excluded:
 * it falls back to the browser key inside the same connection, so a
 * failure there is almost never about the passkey algorithm.
 */
function passkeyHint(cred, reason) {
  if (cred?.kind !== "passkey") return "";
  // No pattern match on the reason: this is only ever called from the
  // loop that waits for the authentication outcome, so a `closed`
  // there is an authentication failure by construction. An earlier
  // version matched the wording of the error, and stopped firing the
  // moment that wording was improved -- exactly when the hint was
  // wanted most.
  return "\n\nIf the passkey line is installed and this still fails, check the server: " +
    "OpenSSH before 10.3 needs " +
    "`PubkeyAcceptedAlgorithms +webauthn-sk-ecdsa-sha2-nistp256@openssh.com` " +
    "in sshd_config to accept a browser passkey at all.";
}

export async function connect({ connstring, user, command, ui, persistKey, restore }) {
  const t = await api();
  status("dialing over iroh…");

  // deltic maps a WIT resource to a PascalCase class, with the WIT
  // static as a static method on it. The trailing argument is
  // terminal.wit's `option<string>` command: a WIT `option` is lowered
  // from the bare value or `undefined` (deltic embedder contract, and
  // see the note in passkeyIdentity above), so an empty field must
  // become `undefined` here -- an empty STRING would ask the target to
  // exec nothing at all instead of running a plain shell.
  const session = serializeSession(
    await t.Session.connect(
      connstring, user, term.cols, term.rows, command || undefined),
  );
  // Supersede: from here the new session owns the page. The one it
  // replaces is DETACHED, not merely forgotten -- an orphaned session
  // keeps its SSH login and iroh connection alive on the target until
  // the tab closes, invisible to the user who thinks they reconnected.
  const prior = currentSession;
  currentSession = session;
  currentPersistKey = persistKey || null;
  if (prior) {
    prior.detach().catch(() => {});
    // The superseded session's closing bookend, drawn now: its pump
    // stopped painting the moment `currentSession` moved on, so the
    // timeline would otherwise show its output running straight into
    // the new session's opening rule.
    await markSessionEnd(term, "detached");
  }

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
      let password = cred.password;
      if (typeof password !== "string") {
        const answers = await ui.collectPrompts({
          instruction: "",
          prompts: [{ text: `password for ${user}: `, echo: false }],
        });
        if (!answers) {
          await session.detach();
          currentSession = null;
          fatal("authentication cancelled");
        }
        password = answers[0] ?? "";
      }
      // `authenticate-password` is the target name; older builds expose
      // the password path as plain `authenticate`.
      await (session.authenticatePassword
        ? session.authenticatePassword(password)
        : session.authenticate(password));
    } else if (cred.kind === "keyboard-interactive") {
      await session.authenticateInteractive();
    } else if (cred.kind === "auto") {
      await session.authenticateAuto();
    } else if (cred.kind === "passkey") {
      // Unlike every other method, the ceremony itself happens DURING
      // this call: the server's demand for a signature is what
      // triggers the authenticator prompt (terminal.wit's
      // `authenticate-passkey` doc comment). The page's ceremony gate
      // (site/passkey-store.ts's `setCeremonyGate`, installed by
      // boot.mjs) is what supplies a user gesture if the browser
      // requires one here.
      await session.authenticatePasskey();
    } else {
      await session.authenticatePublickey();
    }
  } catch (e) {
    // A WIT err from authenticate-* is a ComponentException whose
    // payload IS the error string (result<_, string> in return
    // position, embedder contract §"Error model").
    fatal(`authentication: ${typeof e?.payload === "string" ? e.payload : e.message ?? e}`);
  }

  // Authentication is latch-then-poll for EVERY method (terminal.wit):
  // the authenticate-* call above only recorded the credential. Poll
  // until the server settles it one way or the other -- claiming
  // "connected" before that is a lie the next status would retract.
  // Prompt-driven methods surface server-paced batches along the way:
  // keyboard-interactive always, auto whenever the server steers
  // somewhere interactive (its password round is a one-prompt batch);
  // password/publickey never produce a batch, so for them this loop is
  // pure outcome-waiting. (No deadline -- a human may be typing; the
  // ssh transport itself closes the session if the server goes away.)
  for (;;) {
    const st = await session.status();
    const tag = statusOf(st);
    if (tag === "ready") break;
    if (tag === "closed") fatal(`authentication: ${st.value ?? "closed"}${passkeyHint(cred, st.value)}`);
    if (tag === "auth-prompts") {
      const batch = await session.pendingPrompts();
      if (batch) {
        status("the server asks:");
        const answers = await ui.collectPrompts(batch);
        if (!answers) {
          // The user bailed on a batch they cannot answer (a missing
          // OTP, a mistyped user). Tear the attempt down instead of
          // leaving authentication parked forever.
          await session.detach();
          currentSession = null;
          fatal("authentication cancelled");
        }
        await session.answerPrompts(answers);
        status("authenticating…");
        continue;
      }
    }
    await sleep(50);
  }

  status(`connected as ${user}`);
  // Reattach continuity: the saved dump (prefetched by boot.mjs,
  // `{buf, label}`) goes on screen only NOW, with the session
  // established and nothing painted yet. Restoring before the dial --
  // as this first shipped -- left another host's scrollback stranded
  // on a blank page whenever the attempt failed or was cancelled, with
  // the one-shot latch spent; and a later connect elsewhere would then
  // have persisted that leftover under its own key. The pristine check
  // inside restoreScrollback still governs: an in-page reconnect keeps
  // its real scrollback and this is a no-op. Ordering: the dump and
  // its seam note are OLD content, so they land above the opening
  // bookend, and the new session starts below both.
  if (restore && (await restoreScrollback(restore.buf, persistKey))) {
    note(`restored scrollback from ${restore.label}`);
  }
  // The opening bookend (separator.mjs), first session included.
  // Awaited BEFORE the pump exists: nothing of this session may land
  // above its own start rule.
  await markSessionStart(term, user);
  autofocusTerminal(term); // ditto: a phone gets the keyboard by tapping
  wireInput(session, (e) => sessionEnded(session, `input: ${e.message ?? e}`));

  // The single output drainer for this session.
  //
  // `status` deliberately stays `ready` through a transport resume
  // (terminal.wit's `link-state` doc): the SSH session IS still alive,
  // just not receiving bytes, and claiming `closed` would be a lie the
  // page could not take back. `link-state` is the only place the page
  // learns the transport died and is being silently redialed, so the
  // pump polls it -- coarsely, since it is not needed at output cadence.
  let lastLinkState = null;
  let linkPollTick = 0;
  // When the pump started -- the session reached ready just above, so
  // this is as close to "the remote side is up" as the page can see.
  // The page around this one (boot.mjs) reads the resulting uptime to
  // tell a command that died on the spot -- typically a session
  // manager that is not installed on the target -- apart from one a
  // human used and then left.
  const readyAt = Date.now();
  // ~10s cadence for the periodic scrollback save, tracked against the
  // same 8ms pump tick the link-state poll uses -- another timer would
  // just be one more thing to cancel on supersession.
  let lastPersistAt = Date.now();
  (async () => {
    try {
      for (;;) {
        if (currentSession !== session) return; // superseded
        const out = await session.drainOutput();
        // First bytes claim the screen for this session's key -- or
        // taint it, when another key's content is already there (see
        // claimTerminal). Claimed on OUTPUT rather than on connect: a
        // session that never printed anything put nothing on screen,
        // and must not spoil the buffer for whoever connects next.
        if (out?.length) claimTerminal(persistKey);
        paint(out);
        if (await session.exited()) {
          const code = await session.exitStatus();
          sessionEnded(
            session,
            code === undefined ? "session ended" : `exited (${code})`,
            { code, uptimeMs: Date.now() - readyAt },
          );
          return;
        }
        // Only when there is a key AND something new to save: an idle
        // session (nothing typed, nothing printed) has nothing worth
        // re-writing every ten seconds. The currentSession check
        // matters too: a superseded pump can reach here once more
        // between its awaits and the loop-top check, and by then the
        // screen already carries the NEW session's bytes -- saving
        // them under this pump's old key would be the cross-key
        // mix-up the ownership gate exists to stop.
        if (persistKey && currentSession === session &&
            dirtySincePersist && Date.now() - lastPersistAt >= 10_000) {
          lastPersistAt = Date.now();
          dirtySincePersist = false;
          saveScrollback(persistKey);
        }
        // Every 32nd iteration of an 8ms sleep is ~every 250ms -- often
        // enough to feel live, rare enough not to matter for cost.
        if (typeof session.linkState === "function" && ++linkPollTick % 32 === 0) {
          try {
            const raw = await session.linkState();
            const ls = typeof raw === "string" ? raw : raw?.kind;
            if (ls && ls !== lastLinkState) {
              lastLinkState = ls;
              if (ls === "reconnecting" || ls === "stalled") {
                status("reconnecting…");
              } else if (ls === "attached") {
                status(`connected as ${user}`);
              }
              // For the chrome around the terminal (boot.mjs): the
              // header's transport dot tracks this without parsing the
              // status line's prose.
              window.dispatchEvent(new CustomEvent("wosh:link-state", { detail: { kind: ls } }));
            }
          } catch {
            // A torn-down session mid-poll is not a pump failure --
            // drain/exited above already own that error path.
          }
        }
        await sleep(8);
      }
    } catch (e) {
      sessionEnded(session, `pump: ${e.message ?? e}`);
    }
  })();

  return session;
}

function sessionEnded(session, why, extra) {
  if (currentSession !== session) return;
  const persistKey = currentPersistKey;
  currentSession = null;
  currentPersistKey = null;
  flush(true);
  // Final save: the session is going away (the pump's own periodic
  // save might be up to ~10s stale), and this is the last on-screen
  // state a subsequent reattach could hope to restore.
  saveScrollback(persistKey);
  status(why);
  // For the shell around the terminal (boot.mjs): the session this
  // page was showing is gone, bring the connect panel back. The event
  // carries `kind` (terminal.wit's `close-kind`) best-effort, so
  // boot.mjs can decide about automatic reconnection without parsing
  // this `why` string -- fetched in a fire-and-forget tail so a slow
  // or failing `close-kind` call never delays the synchronous cleanup
  // above. `code`/`uptimeMs` ride along where they are known (the exit
  // path, and only there -- a pump or input failure knows neither),
  // for the same reason: an on-connect command that exits 127 within a
  // second is a missing tool, and boot.mjs can say so instead of
  // silently redialing into the same failure.
  const { code, uptimeMs } = extra ?? {};
  (async () => {
    let kind;
    try {
      // The RAW close-kind (see serializeSession): on a poisoned
      // instance the gated one would queue behind minutes of retries.
      const ck = session.closeKindRaw ?? session.closeKind;
      if (typeof ck === "function") {
        const raw = await ck();
        kind = typeof raw === "string" ? raw : raw?.kind;
      }
    } catch {
      kind = undefined;
    }
    // A poisoned component instance answers EVERY call with the
    // reentrance refusal -- close-kind included, so `kind` comes back
    // undefined exactly when the session died of the poison. The
    // session state on the LISTENER is fine (it parks, exactly as for
    // a dropped transport); only this page's instance is beyond use --
    // so the instance is DISCARDED: clientLoad is the memoized
    // instantiation, and without this reset the automatic reconnect
    // would dial through the same poisoned component and fail forever.
    // A fresh instantiation keeps the browser's identity (IndexedDB)
    // and the host-key pins (localStorage), so the reconnect is
    // silent where it would have been silent before.
    if (kind === undefined && /reentrance forbidden/.test(why ?? "")) {
      kind = "lost";
      clientLoad = null;
    }

    // The closing bookend, labeled by HOW it ended -- and labeled
    // AFTER the poison classification above, so a poisoned death
    // reads "session lost" (it is about to be silently redialed),
    // not "session ended". This is the moment the client knows the
    // session cannot come back (a resumable outage never reaches
    // here), and the pump above has already stopped, so the rule
    // lands after the session's last output. Drawn before the event:
    // an auto-reconnect's new session must open below this session's
    // close.
    const what = kind === "lost" ? "session lost"
      : kind === "failed" ? "session failed"
      : "session ended";
    await markSessionEnd(term, what).catch(() => {});
    window.dispatchEvent(
      new CustomEvent("wosh:session-ended", { detail: { why, kind, code, uptimeMs } }),
    );
  })();
}

/**
 * The page's own annotation into the scrollback -- dim and prefixed so
 * it reads as distinct from anything the pty sent, e.g. the divider
 * printed across an automatic reconnect (boot.mjs).
 */
export const note = (text) => {
  term.write(`\r\n\x1b[2m[wosh] ${text}\x1b[0m\r\n`);
};

/** Tear the session down and close the iroh connection. */
export async function detach() {
  const s = currentSession;
  if (!s) return;
  currentSession = null;
  try {
    await s.detach();
  } finally {
    status("detached");
    // A deliberate detach is a confirmed end like any other; the
    // timeline says so.
    await markSessionEnd(term, "detached").catch(() => {});
  }
}
