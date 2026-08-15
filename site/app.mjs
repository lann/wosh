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
function restoreScrollback(text, key) {
  if (everPainted || restored || !text) return false;
  restored = true;
  claimTerminal(key);
  term.write(text);
  return true;
}

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
async function saveScrollback(key) {
  if (!key || !serializeAddon) return;
  // Ownership gate (see claimTerminal): save only a buffer whose
  // content is attributable to THIS key alone. A page that has shown
  // another key's bytes -- an earlier session to a different host, or
  // a restored dump for one -- must not persist the mixture anywhere.
  if (terminalOwner !== key) return;
  try {
    const buf = serializeAddon.serialize();
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
    status("loading the client component…");
    try {
      const t = await loadClient(DIST.client, DIST.translator);
      status("client component ready");
      return t;
    } catch (e) {
      // Leave the cache empty so a later call retries (a transient
      // fetch failure should not brick the page until a reload).
      clientLoad = null;
      status("failed to load the client component");
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
    // On-connect commands (terminal.wit's `connect` grew a trailing
    // `option<string>`): detected off the static's arity, and ASSUMED
    // when the static is not inspectable at all -- same philosophy as
    // the fields above. The page and the component ship together in
    // one precache, so the only way these disagree is a stale service
    // worker serving a new page against an old wasm; that mix is what
    // this probe guards, not a supported configuration.
    execCommand: typeof t.Session?.connect !== "function" || t.Session.connect.length >= 5,
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
  const session = await t.Session.connect(
    connstring, user, term.cols, term.rows, command || undefined);
  // Supersede: from here the new session owns the page. The one it
  // replaces is DETACHED, not merely forgotten -- an orphaned session
  // keeps its SSH login and iroh connection alive on the target until
  // the tab closes, invisible to the user who thinks they reconnected.
  const prior = currentSession;
  currentSession = session;
  currentPersistKey = persistKey || null;
  if (prior) prior.detach().catch(() => {});

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
  // its real scrollback and this is a no-op.
  if (restore && restoreScrollback(restore.buf, persistKey)) {
    note(`restored scrollback from ${restore.label}`);
  }
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
      if (typeof session.closeKind === "function") {
        const raw = await session.closeKind();
        kind = typeof raw === "string" ? raw : raw?.kind;
      }
    } catch {
      kind = undefined;
    }
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
  }
}
