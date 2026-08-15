// The connect panel: read the connection string, collect a user name,
// show the host key for confirmation, and offer a credential.
//
// Two durable things live behind this panel, both narrow on purpose.
// The browser's SSH identity lives behind the component's
// `identity-store` import (site/identity-store.ts): a non-extractable
// WebCrypto pair in IndexedDB, so the key line shown here keeps
// working across visits. And this panel itself persists exactly one
// thing, only with the user's explicit opt-in (a checkbox on the
// fingerprint prompt): the host-key pin store -- approved SSH
// fingerprints keyed by the listener's endpoint id, so a returning
// visitor skips the prompt when the same listener presents the same
// host key, and gets a loud warning when it presents a DIFFERENT one.
// TOFU floor: an unrecognized fingerprint is always confirmed
// interactively; the store can only ever suppress the prompt for a
// fingerprint a human explicitly approved here before. main's
// equivalent carried saved proxies, passkey registration, PRF-wrapped
// key escrow and its own IndexedDB identity -- none of which applies
// here: authentication is SSH's own.

import {
  identity,
  detach,
  capabilities,
  passkeyIdentity,
  enrollPasskey,
  adoptPasskey,
  recoverPasskey,
  forgetPasskey,
  installPasskeyCeremonyGate,
  note,
} from "./app.mjs";
import { scanQr } from "./qr.mjs";
import * as bufferStore from "./buffer-store.mjs";

const el = (tag, props = {}, ...children) => {
  const node = Object.assign(document.createElement(tag), props);
  for (const c of children) node.append(c);
  return node;
};

/**
 * The connection string out of a URL fragment. Percent-decoded when it
 * decodes -- a connstring is base64url and so never contains `%`, so a
 * malformed escape means the fragment was never encoded to begin with,
 * and the raw text is the better guess.
 */
function fragmentValue(hash) {
  const frag = (hash || "").replace(/^#/, "");
  if (!frag) return "";
  try {
    return decodeURIComponent(frag).trim();
  } catch {
    return frag.trim();
  }
}

/**
 * The connection string travels in the URL fragment, so it stays out of
 * request logs and Referer headers. Accepts a bare string too, for
 * manual paste.
 */
export function connstringFromLocation(loc = location) {
  return fragmentValue(loc.hash);
}

/**
 * What the user typed, as a connection string. The thing an operator
 * hands out is the whole QR LINK, and that is what gets pasted or
 * shared -- so anything that parses as a URL contributes its fragment
 * instead of its text. Safe against a bare connstring: base64url has
 * no `:`, so `new URL` always rejects one. A URL with no fragment is
 * returned verbatim, so the error the user gets names what they
 * actually pasted rather than an empty field.
 */
export function connstringFrom(raw) {
  const s = (raw ?? "").trim();
  if (s.startsWith("#")) return fragmentValue(s); // the fragment alone, `#` and all
  let url;
  try {
    url = new URL(s);
  } catch {
    return s;
  }
  return fragmentValue(url.hash) || s;
}

// --- the host-key pin store -------------------------------------------------
//
// Keyed by the listener's endpoint id -- its Ed25519 iroh pubkey, the
// one identity iroh itself authenticates during the dial, persistent
// across listener restarts since the listener stores its key on disk.
// The value is the SSH host-key fingerprint the user approved. Note the
// key is the PROXY's identity and the value is the SSH SERVER's: the
// pin says "behind the listener I approved, I saw this host key", and
// any change in that pairing gets the loud warning below.

const PINS_KEY = "wosh.hostkeys.v1";

// --- the scrollback toggle ---------------------------------------------
//
// A single global on/off, not per-connection: the same person either
// wants this device keeping a local copy of what terminals showed, or
// doesn't. DEFAULT ON, because the failure mode of "off" (a reattach
// opens onto a blank screen while dtach or abduco has kept the actual
// session running) is exactly the confusing-looking-broken state this
// whole feature exists to avoid, and the toggle is right here with its
// own explanation for the person who would rather not have it.
const SCROLLBACK_KEY = "wosh.scrollback.v1";

function scrollbackEnabled() {
  try {
    return localStorage.getItem(SCROLLBACK_KEY) !== "off";
  } catch {
    return true; // no storage: harmless default, nothing persists anyway
  }
}

function setScrollbackEnabled(on) {
  try {
    localStorage.setItem(SCROLLBACK_KEY, on ? "on" : "off");
  } catch {
    // Storage refused: the checkbox still reflects the choice for this
    // visit; it just won't stick past a reload.
  }
}

/**
 * The listener's endpoint id (raw Ed25519 pubkey, hex) out of a
 * connection string; null if it cannot be extracted. Duplicates ONLY
 * the fixed prefix shared by every format version (connstring/src/
 * lib.rs: version byte, then 32 raw pubkey bytes -- v2 and v3 keep the
 * pubkey as the FIRST postcard field precisely so this prefix never
 * moves), and refuses versions it doesn't know, so a format change
 * degrades to "no pinning" -- more prompting, never less.
 */
export function endpointIdOf(connstring) {
  try {
    const bin = atob(connstring.trim().replace(/-/g, "+").replace(/_/g, "/"));
    const version = bin.charCodeAt(0);
    if (bin.length < 34 || version < 1 || version > 3) return null;
    let hex = "";
    for (let i = 1; i < 33; i++) hex += bin.charCodeAt(i).toString(16).padStart(2, "0");
    return hex;
  } catch {
    return null;
  }
}

/** The pin map, `{ [endpointIdHex]: { fp, at } }`; {} when unavailable. */
function loadPins() {
  try {
    const pins = JSON.parse(localStorage.getItem(PINS_KEY) ?? "{}");
    return pins && typeof pins === "object" ? pins : {};
  } catch {
    return {}; // no storage (private mode) or corrupt JSON: stay stateless
  }
}

function savePin(endpointId, fp) {
  try {
    const pins = loadPins();
    pins[endpointId] = { fp, at: new Date().toISOString() };
    localStorage.setItem(PINS_KEY, JSON.stringify(pins));
  } catch {
    // Storage refused (private mode, quota): the approval still stands
    // for this session; the user is simply prompted again next time.
  }
}

// --- connection history -----------------------------------------------------
//
// What a returning visitor needs to reconnect: the listener's endpoint
// id, the relay it homes on, and the user name. DELIBERATELY NOT the
// pairing token: history rebuilds a TOKENLESS connection string, and
// reconnecting works anyway because this device's pairing enrollment
// (its persistent iroh identity) already vouches for it -- which is
// also why history is worthless to copy off the device. Host keys are
// the pin store's business, not history's; the two share only the
// endpoint-id key.

const HISTORY_KEY = "wosh.history.v1";
const HISTORY_CAP = 20;

/// Mirrors WELL_KNOWN_RELAYS in connstring/src/lib.rs (append-only,
/// indices never reused) -- needed to DECODE a v2/v3 connstring whose
/// relay rides as a table index. The tokenless connstrings this page
/// ENCODES always spell the URL out: correct either way, and it keeps
/// this copy of the table decode-only.
const WELL_KNOWN_RELAYS = [
  "https://use1-1.relay.n0.iroh.link",
  "https://usw1-1.relay.n0.iroh.link",
  "https://euc1-1.relay.n0.iroh.link",
  "https://aps1-1.relay.n0.iroh.link",
];

/**
 * Decode the fields history needs -- `{ id, relay }` -- from a v1, v2
 * or v3 connection string; null when it doesn't parse. A fuller sibling
 * of `endpointIdOf` (which stays prefix-only: pins never need the
 * relay).
 */
export function connstringDetails(connstring) {
  try {
    const bin = atob(connstring.trim().replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    if (bytes.length < 34) return null;
    let hex = "";
    for (let i = 1; i < 33; i++) hex += bytes[i].toString(16).padStart(2, "0");

    if (bytes[0] === 1) {
      // v1: flags byte, optional 16-byte token, relay to the end.
      const hasToken = (bytes[33] & 1) !== 0;
      const relayStart = 34 + (hasToken ? 16 : 0);
      const relay = new TextDecoder().decode(bytes.subarray(relayStart));
      return relay ? { id: hex, relay } : null;
    }
    if (bytes[0] === 2 || bytes[0] === 3) {
      // v2/v3 postcard payload (identical; the version marks how the
      // token is proven, not how the blob is laid out): relay enum
      // right after the pubkey.
      let off = 33;
      const varint = () => {
        let v = 0, shift = 0;
        for (;;) {
          const b = bytes[off++];
          v += (b & 0x7f) * 2 ** shift;
          if ((b & 0x80) === 0) return v;
          shift += 7;
        }
      };
      const disc = varint();
      if (disc === 0) {
        const len = varint();
        const relay = new TextDecoder().decode(bytes.subarray(off, off + len));
        return relay ? { id: hex, relay } : null;
      }
      if (disc === 1) {
        const relay = WELL_KNOWN_RELAYS[varint()];
        return relay ? { id: hex, relay } : null;
      }
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * A v3 connection string carrying NO pairing token: version byte,
 * pubkey, relay spelled out (`Url` variant -- the well-known-index
 * encoding is an optimization this producer skips), `none` token.
 * What a history entry dials with; enrollment stands in for the token.
 */
export function tokenlessConnstring(idHex, relay) {
  const relayBytes = new TextEncoder().encode(relay);
  const bytes = [3];
  for (let i = 0; i < 64; i += 2) bytes.push(parseInt(idHex.slice(i, i + 2), 16));
  bytes.push(0); // Relay::Url
  // postcard varint length; relays are short but encode properly.
  let len = relayBytes.length;
  while (len >= 0x80) {
    bytes.push((len & 0x7f) | 0x80);
    len >>= 7;
  }
  bytes.push(len);
  bytes.push(...relayBytes);
  bytes.push(0); // token: None
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * MRU list of `{ id, relay, user, at }`, each optionally carrying
 * `command` (the on-connect command last used for it) and
 * `autoResume`; [] when unavailable. Entries written before those
 * fields existed simply lack them, and an absent `command` means a
 * plain shell -- so old history keeps working untouched.
 */
function loadHistory() {
  try {
    const h = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
    if (!Array.isArray(h)) return [];
    // The new fields flow outward into an input value and a connect
    // parameter, so a corrupted store (hand-edited, or an old bug's
    // leavings) is coerced here at the ONE reader instead of
    // type-checked at every use: a non-string command is no command,
    // a non-true autoResume is absent (never written as false, so an
    // untouched entry round-trips byte-identical).
    const entries = h.filter((e) => e && typeof e === "object");
    for (const e of entries) {
      if (typeof e.command !== "string" || !e.command) delete e.command;
      if (e.autoResume !== true) delete e.autoResume;
    }
    return entries;
  } catch {
    return [];
  }
}

function saveHistory(entries) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, HISTORY_CAP)));
  } catch {
    // Storage refused: this visit just isn't remembered.
  }
}

/**
 * Insert-or-bump, deduped by (endpoint id, user) -- deliberately NOT
 * by the command: the same account on the same target is one
 * connection whose on-connect command was changed, not two.
 * `command`/`autoResume` are left off the record entirely when unset,
 * so an entry for a plain shell looks exactly like a pre-command one.
 */
function recordConnection(id, relay, user, command, autoResume) {
  const rest = loadHistory().filter((e) => !(e.id === id && e.user === user));
  const entry = { id, relay, user, at: new Date().toISOString() };
  if (command) entry.command = command;
  if (autoResume) entry.autoResume = true;
  saveHistory([entry, ...rest]);
}

/** Drop the remembered on-connect command from one history entry. */
function clearStoredCommand(id, user) {
  saveHistory(loadHistory().map((e) => {
    if (!(e.id === id && e.user === user)) return e;
    const { command, ...rest } = e;
    return rest;
  }));
}

function removeConnection(id, user) {
  saveHistory(loadHistory().filter((e) => !(e.id === id && e.user === user)));
}

/** "2 min ago" -- coarse on purpose; the exact time is in the tooltip. */
function relTime(iso) {
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 172800) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

/// `panel` is a <dialog>: the connect form is a MODAL, so a live
/// session gets the whole viewport. It opens itself whenever there is
/// no session to look at (page load, session end, detach), stays open
/// through the host-key prompt and any auth prompt batches, and closes
/// on a successful connect. The always-visible #bar carries the status
/// line, the detach button, and the button that reopens this dialog.
export async function initBoot(panel, { onConnect }) {
  const notice = el("div", { className: "notice" });
  const keyRow = el("div", { className: "key" });

  const csInput = el("input", {
    className: "connstring",
    placeholder: "connection string or link (from the listener's QR)",
    value: connstringFromLocation(),
  });
  // Next to the field, because it fills the field: the listener's QR
  // encodes the connect link, so a scan is just a paste that the
  // camera performs. Always present, even where the camera cannot
  // work: pressing it then explains why (the usual reason is a page
  // served over plain http, which is exactly how someone ends up
  // trying to scan from a phone), and that beats a button that
  // silently is not there.
  // An icon, not a label: the button sits beside the field it fills
  // and the glyph says QR better than the words did. The words remain
  // for assistive tech and for anyone hovering.
  const scanBtn = el("button", {
    className: "scan",
    title: "scan the listener's QR code with this device's camera",
  });
  scanBtn.setAttribute("aria-label", "scan QR");
  scanBtn.innerHTML =
    '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M3 3h8v8H3V3zm2 2v4h4V5H5zm8-2h8v8h-8V3zm2 2v4h4V5h-4zM3 13h8v8H3v-8zm2 2v4h4v-4H5zm8-2h3v3h-3v-3zm5 0h3v3h-3v-3zm-5 5h3v3h-3v-3zm5 0h3v3h-3v-3z"/></svg>';
  const scanRow = el("div", { className: "csrow" }, csInput, scanBtn);
  // The camera preview lands here, directly under the field it fills.
  const scanHost = el("div");
  const userInput = el("input", {
    size: 16,
    placeholder: "user",
    value: "",
  });
  const method = el("select");
  method.append(
    el("option", { value: "auto", textContent: "automatic (server chooses)" }),
    el("option", { value: "publickey", textContent: "publickey (this browser's key)" }),
    el("option", { value: "passkey", textContent: "passkey" }),
    el("option", { value: "password", textContent: "password" }),
    el("option", { value: "keyboard-interactive", textContent: "keyboard-interactive (OTP/2FA)" }),
  );

  const connectBtn = el("button", { textContent: "connect" });
  const showKeyBtn = el("button", { textContent: "show this browser's public key" });
  const closeBtn = el("button", { className: "close", textContent: "×", title: "close" });

  // --- passkey section: enrol / adopt / forget ---------------------------
  //
  // Offered only once capabilities() confirms both the component build
  // and the platform support it (see below). What is shown is always
  // an ordinary `authorized_keys` line -- the same kind already
  // displayed above for the browser's own WebCrypto key -- because
  // that is the whole truth here: nothing is installed on the target
  // beyond that line. OpenSSH has verified these since 8.4, though
  // only 10.3 and later accept the algorithm without an sshd_config
  // line -- which is why the enrolled view says so rather than
  // promising it always just works.
  const passkeySection = el("div", { className: "passkey" });
  const passkeyStatus = el("div", { className: "sub" });
  const enrollBtn = el("button", { textContent: "enrol" });
  const forgetBtn = el("button", { textContent: "forget" });
  const adoptInput = el("input", {
    size: 40,
    placeholder: "paste the authorized_keys line from another device",
  });
  const adoptBtn = el("button", { textContent: "adopt" });
  const recoverBtn = el("button", { textContent: "recover" });
  // adopt needs a paste first, so its button REVEALS the field rather
  // than acting: the ellipsis is that promise. Wired once; the row is
  // re-appended by every render with its hidden state intact.
  const adoptRevealBtn = el("button", { textContent: "adopt…" });
  const adoptRow = el("div", { className: "row", hidden: true }, adoptInput, adoptBtn);
  adoptRevealBtn.addEventListener("click", () => {
    adoptRow.hidden = !adoptRow.hidden;
    if (!adoptRow.hidden) adoptInput.focus();
  });

  /// A "?" that reveals its explanation inline, on demand. Touch has
  /// no hover, so a title attribute reaches nobody there; and rendering
  /// guidance permanently is how this panel got crowded to begin with.
  const helpToggle = (text) => {
    const body = el("div", { className: "sub help-body", textContent: text, hidden: true });
    const btn = el("button", { className: "help", textContent: "?", title: "explain" });
    btn.setAttribute("aria-label", "explain");
    btn.addEventListener("click", () => {
      body.hidden = !body.hidden;
    });
    return { btn, body };
  };

  // --- the session fold: what to run on connect --------------------------
  //
  // An SSH exec request instead of a plain shell. The point is not
  // "run a command" in the abstract -- it is create-or-attach session
  // managers, where the SAME command both starts the session the first
  // time and reattaches to it afterwards, so the work on the target
  // outlives this tab rather than only this transport. (Transport
  // deaths were already invisible: the component redials underneath a
  // live session. A closed tab is a different loss, and only the
  // target can survive it.)
  //
  // Presets, not magic: each is an ordinary command line the target's
  // shell parses, shown in full in the field so nothing is hidden from
  // the person who has to debug it on the other side.
  const COMMAND_PRESETS = {
    dtach: 'mkdir -p "$HOME/.wosh" && exec dtach -A "$HOME/.wosh/main.dtach" -r winch "$SHELL"',
    abduco: 'exec abduco -A wosh "$SHELL"',
    tmux: "exec tmux new-session -A -D -s wosh",
    screen: "exec screen -D -R -S wosh",
  };
  const presetSelect = el("select", { className: "preset" });
  presetSelect.append(
    el("option", { value: "", textContent: "plain shell" }),
    el("option", { value: "dtach", textContent: "dtach" }),
    el("option", { value: "abduco", textContent: "abduco" }),
    el("option", { value: "tmux", textContent: "tmux" }),
    el("option", { value: "screen", textContent: "screen" }),
    el("option", { value: "custom", textContent: "custom…" }),
  );
  const commandInput = el("input", {
    className: "command",
    size: 40,
    placeholder: "command to run instead of a shell",
  });
  // The field is the truth; the select is a view of it. Anything that
  // writes the field (a preset, a history tap, a resume) calls this,
  // so a hand-edited preset line honestly reads back as "custom…"
  // instead of still claiming to be the preset it no longer is.
  const syncPresetFromCommand = () => {
    const value = commandInput.value.trim();
    if (!value) return void (presetSelect.value = "");
    const hit = Object.keys(COMMAND_PRESETS).find((k) => COMMAND_PRESETS[k] === value);
    presetSelect.value = hit ?? "custom";
  };
  presetSelect.addEventListener("change", () => {
    const v = presetSelect.value;
    if (v === "custom") return; // the field is already whatever it was
    commandInput.value = COMMAND_PRESETS[v] ?? ""; // "" == plain shell
  });
  commandInput.addEventListener("input", syncPresetFromCommand);

  const commandHelp = helpToggle(
    "This runs on the target instead of a login shell. With a create-or-attach " +
      "session manager the same line both starts the session and reattaches to it, " +
      "so a later connect lands in the SAME session and the work survives closing " +
      "this tab. The tool has to be installed on the target already -- nothing is " +
      "installed for you. dtach and abduco keep no copy of the screen contents, so a " +
      "reattach starts blank until the program running inside redraws (tmux and " +
      "screen do keep one). And on a systemd host configured with " +
      "KillUserProcesses=yes, a detached session is killed when you log out unless " +
      "`loginctl enable-linger <user>` has been run for that account.",
  );
  // Shown only if the loaded component predates the command argument;
  // worded like the publickey-absent case below, and for the same
  // reason: say what degraded rather than silently offering a control
  // that cannot work.
  const execNote = el("div", {
    className: "sub",
    hidden: true,
    textContent:
      "this build of the client component has no on-connect command yet; " +
      "connecting still opens a plain shell",
  });

  // Escape hatch that does NOT cost the setting: one connect without
  // the command (to fix a session manager that is now refusing to
  // start, say), with the remembered line still there afterwards.
  const onceShell = el("input", { type: "checkbox", id: "plain-shell-once" });
  const autoResumeBox = el("input", { type: "checkbox", id: "auto-resume" });

  // "keep scrollback on this device": a local copy of what the
  // terminal showed, restored on the next load or reattach so a
  // session manager that keeps no screen state of its own (dtach,
  // abduco) -- or one that keeps only the visible screen (tmux,
  // screen) -- doesn't hand back a blank terminal for work that is
  // still running. Unticking calls wipe() immediately: the setting and
  // the data leave together, rather than the data quietly outliving
  // the toggle that was supposed to govern it.
  const scrollbackBox = el("input", {
    type: "checkbox",
    id: "keep-scrollback",
    checked: scrollbackEnabled(),
  });
  scrollbackBox.addEventListener("change", () => {
    setScrollbackEnabled(scrollbackBox.checked);
    if (!scrollbackBox.checked) {
      bufferStore.wipe().catch((e) => console.warn("wosh: could not wipe scrollback", e));
    }
  });
  const scrollbackHelp = helpToggle(
    "This device keeps a local copy of what the terminal showed (the actual " +
      "contents, not just that a session existed), so a reattach can put it back " +
      "on screen right away instead of starting blank -- dtach and abduco keep no " +
      "screen state of their own, and even tmux and screen only keep what was " +
      "visible, not the scrollback above it. Stored only in this browser, only for " +
      "this site, same as the host-key approvals above. Turning this off deletes " +
      "what is stored.",
  );

  // Connection history: tap to reconnect. Rendered only when there is
  // something to show; the whole section disappears otherwise.
  const historySection = el("div", { className: "history" });
  const rememberConn = el("input", {
    type: "checkbox",
    id: "remember-connection",
    checked: true,
  });

  // The always-visible bar (index.html) keeps only the status line
  // and the button that opens this dialog; everything that ACTS on
  // the session lives in the dialog itself. Detach in particular is
  // destructive-adjacent -- one stray tap on a phone's cramped bar
  // ended sessions people meant to keep -- so it sits behind the
  // deliberate step of opening settings, next to connect: the two
  // session verbs in one place.
  const settingsBtn = document.getElementById("settings-btn");
  const detachBtn = el("button", { textContent: "detach", hidden: true });

  // Transient asks -- the host-key confirmation, prompt batches, the
  // passkey ceremony button -- and the notice line land HERE, directly
  // under the connect button. They used to append to the panel's END,
  // below the passkey material: on a phone that put the one row that
  // needed an answer below the fold, and the page looked hung on
  // "authenticating…" while its question sat unseen.
  const promptArea = el("div", { className: "prompts" });
  promptArea.append(notice);
  const ask = (row) => promptArea.prepend(row);

  // Everything about HOW to authenticate -- the method override, the
  // browser key, the passkey -- lives behind one fold. It is all
  // setup: needed when installing a key on a new target or forcing a
  // method while debugging, and not at all on the ordinary connect.
  // One fold rather than two, because the previous pair earned its
  // keep badly: a "method" fold whose summary repeated the select's
  // own label was the same content twice, once static.
  const authDetails = el("details", { className: "auth" },
    el("summary", { textContent: "auth settings" }),
    el("div", { className: "row" },
      el("label", { textContent: "method" }), method),
    el("div", { className: "field" }, el("span", { textContent: "browser key" })),
    el("div", { className: "row" }, showKeyBtn),
    keyRow,
    passkeySection);

  // The session fold: everything about WHAT the connect runs, kept out
  // of the ordinary path for the same reason auth settings are -- the
  // common connect answers none of these questions, and the answers
  // persist per connection in history anyway.
  const sessionDetails = el("details", { className: "sessioncfg" },
    el("summary", { textContent: "session" }),
    el("div", { className: "row" },
      el("label", { textContent: "run on connect" }), presetSelect, commandHelp.btn),
    el("div", { className: "row" }, commandInput),
    commandHelp.body,
    execNote,
    el("div", { className: "row" },
      onceShell,
      el("label", {
        htmlFor: "plain-shell-once",
        textContent: " plain shell just this once",
        title: "the next connect sends no command; the remembered one stays",
      })),
    el("div", { className: "row" },
      autoResumeBox,
      el("label", {
        htmlFor: "auto-resume",
        textContent: " reconnect automatically when this page opens",
      })),
    el("div", { className: "row" },
      scrollbackBox,
      el("label", {
        htmlFor: "keep-scrollback",
        textContent: " keep scrollback on this device",
      }),
      scrollbackHelp.btn),
    scrollbackHelp.body);

  panel.append(
    el("div", { className: "title" }, el("span", { textContent: "wosh" }), closeBtn),
    historySection,
    el("div", { className: "field", textContent: "connection string" }),
    scanRow,
    scanHost,
    el("div", { className: "row" },
      el("label", { textContent: "user" }), userInput),
    el("div", { className: "row" }, connectBtn, detachBtn),
    promptArea,
    el("div", { className: "row remember" },
      rememberConn,
      el("label", {
        htmlFor: "remember-connection",
        textContent: " remember this connection",
        title: "history keeps the endpoint id, relay and user name -- the pairing token is never saved",
      })),
    authDetails,
    sessionDetails,
  );

  /// Destructive history buttons arm on the first click (label turns
  /// into a question, briefly) and act on the second: a same-size
  /// in-place confirmation, instead of a native confirm() breaking the
  /// dialog's flow. Disarms itself after a beat.
  const armTwoStep = (btn, armedLabel, act) => {
    const idle = btn.textContent;
    let timer = null;
    btn.addEventListener("click", () => {
      if (btn.classList.contains("armed")) {
        clearTimeout(timer);
        // Disarm BEFORE acting: these buttons outlive their renders
        // (forget is re-appended after enrol), and a button that acted
        // while still wearing the armed state would fire again on one
        // accidental tap the next time it appears.
        btn.classList.remove("armed");
        btn.textContent = idle;
        act();
        return;
      }
      btn.classList.add("armed");
      btn.textContent = armedLabel;
      timer = setTimeout(() => {
        btn.classList.remove("armed");
        btn.textContent = idle;
      }, 3000);
    });
  };

  /// Rebuild the recent-connections section from storage. Each row is
  /// a button (tap = fill the form with a TOKENLESS connstring and
  /// connect); the relay and full endpoint id deliberately live in the
  /// hover detail (title), not the row text -- they are diagnostics,
  /// not identity. The pin badge marks the taps that will be
  /// promptless.
  const renderHistory = () => {
    historySection.replaceChildren();
    const entries = loadHistory();
    if (entries.length === 0) return;
    const pins = loadPins();
    const clearBtn = el("button", { className: "subtle", textContent: "clear" });
    armTwoStep(clearBtn, "forget all?", () => {
      saveHistory([]);
      renderHistory();
    });
    historySection.append(
      el("div", { className: "field histhead" },
        el("span", { textContent: "recent" }), clearBtn),
    );
    for (const entry of entries) {
      const detail = `relay ${entry.relay}\nendpoint ${entry.id}\nlast connected ${entry.at}`;
      const row = el("button", { className: "histrow", title: detail });
      const sub = [relTime(entry.at)];
      if (pins[entry.id]?.fp) sub.push("key pinned");
      if (entry.command) sub.push("runs a command");
      row.append(
        el("div", { textContent: `${entry.user}@${entry.id.slice(0, 8)}…` }),
        el("div", { className: "sub", textContent: sub.join(" · ") }),
      );
      row.addEventListener("click", () => {
        csInput.value = tokenlessConnstring(entry.id, entry.relay);
        userInput.value = entry.user;
        // The session fold follows the entry, so a tap replays what
        // this connection actually ran last time -- including the
        // absence of a command, which is why this assigns
        // unconditionally rather than only when one is present.
        commandInput.value = entry.command ?? "";
        syncPresetFromCommand();
        autoResumeBox.checked = !!entry.autoResume;
        doConnect();
      });
      const del = el("button", {
        className: "subtle",
        textContent: "×",
        title: "forget this connection (host-key pins are separate)",
      });
      armTwoStep(del, "forget?", () => {
        removeConnection(entry.id, entry.user);
        renderHistory();
      });
      historySection.append(el("div", { className: "histline" }, row, del));
    }
  };

  const openPanel = () => {
    if (!panel.open) panel.showModal();
    // Focus what the user actually has to type: the QR link prefills
    // the connstring, so usually that is the user field.
    (csInput.value.trim() ? userInput : csInput).focus();
  };
  // Esc (and the × button) close the dialog -- fine with a session to
  // return to, and harmless without one (#bar's button reopens it) --
  // but NOT mid-connect: a hidden host-key or OTP prompt looks exactly
  // like a hang.
  panel.addEventListener("cancel", (e) => {
    if (connectBtn.disabled) e.preventDefault();
  });
  closeBtn.addEventListener("click", () => {
    if (!connectBtn.disabled) panel.close();
  });
  settingsBtn.addEventListener("click", openPanel);

  // Scanning: the QR carries the connect LINK, so a successful scan is
  // a paste the camera performed -- connstringFrom reduces it to the
  // fragment exactly as a hand-pasted link would be. The preview owns
  // the only cancel button (the scan button stays disabled meanwhile),
  // and the panel closing under a live scan aborts it: a camera left
  // running behind a closed dialog is a light with no explanation.
  let scanAbort = null;
  panel.addEventListener("close", () => scanAbort?.abort());
  scanBtn.addEventListener("click", async () => {
    if (scanAbort) return;
    notice.textContent = "";
    scanAbort = new AbortController();
    scanBtn.disabled = true;
    try {
      const text = await scanQr(scanHost, { signal: scanAbort.signal });
      if (text !== null) {
        csInput.value = connstringFrom(text);
        (userInput.value.trim() ? connectBtn : userInput).focus();
      }
    } catch (e) {
      notice.textContent = `${e.message ?? e}`;
    } finally {
      scanAbort = null;
      scanBtn.disabled = false;
    }
  });

  // The session is gone: surface why, restore the bar to its idle
  // shape, and bring the connect form back.
  const sessionOver = (why) => {
    detachBtn.hidden = true;
    settingsBtn.textContent = "connect…";
    if (why) notice.textContent = why;
    openPanel();
  };

  // In-memory only (never the pin/history store): the last endpoint
  // and user actually dialed, so a `lost` session can be redialed
  // without asking the user to retype anything. Set unconditionally in
  // doConnect -- independent of the "remember this connection"
  // checkbox, which governs persistent history, not this.
  let lastConnected = null;
  // One silent reconnect per minute: a session that keeps dying gets a
  // human decision instead of silently churning fresh shells. Each
  // automatic reconnect is a NEW session (a new shell), so silent
  // churn is invisible lost work, not a convenience.
  let lastAutoAt = 0;

  /**
   * Attempt a silent, same-parameters reconnect after a session was
   * lost (terminal.wit's `close-kind` -- `lost` is the one kind the
   * WIT enum exists to mark as reasonable to retry automatically,
   * precisely so this decision needs no reason-string parsing).
   * Returns whether a new session was actually established.
   */
  const autoReconnect = async (why) => {
    if (!lastConnected) return false;
    // password / keyboard-interactive need a human to type something;
    // those fall through to the dialog like any other reconnect.
    if (!["auto", "publickey", "passkey"].includes(method.value)) return false;
    // An unpinned host key would render the confirm prompt into a
    // CLOSED dialog -- indistinguishable from a hang. Only reconnect
    // silently onto a key this browser has already pinned.
    const id = endpointIdOf(lastConnected.connstring);
    if (!id || !loadPins()[id]?.fp) return false;
    // With an on-connect command the reconnect REATTACHES: the shell
    // and its work are on the target, so a redial costs nothing but a
    // dial. The rate limit is then only a guard against battery-burning
    // churn, not against silently losing a shell -- so it can be much
    // shorter. Without a command every automatic reconnect is a NEW
    // shell, and the minute stands.
    const command = lastConnected.command;
    if (Date.now() - lastAutoAt < (command ? 15_000 : 60_000)) return false;
    lastAutoAt = Date.now();
    // EXACT copy on the no-command path: host-test/browser-fallthrough
    // greps the scrollback for "starting a new session".
    note(command ? `${why} — reattaching…` : `${why} — starting a new session…`);
    csInput.value = lastConnected.connstring;
    userInput.value = lastConnected.user;
    // A passkey (or auto steered to one) may trigger an authenticator
    // ceremony here, with the dialog CLOSED: the ceremony gate below
    // opens it for the ask and closes it after -- a reconnect that
    // needs a human is not the silent kind.
    // The command travels as an OVERRIDE rather than through the
    // field: replaying "no command" (a "just this once" connect) must
    // not erase the line the user still has remembered.
    const s = await doConnect({ command: command ?? "" });
    return !!s;
  };

  /// The two things that can be said about an `ended` session that ran
  /// a command, rendered as offers rather than actions: `ended` is a
  /// deliberate act on the other side (a typed exit, a detach
  /// keystroke), so redialing automatically would fight the human who
  /// just left. Both paths go through sessionOver, so the panel is
  /// open and nobody is stranded on a dead screen either way.
  const commandSessionEnded = ({ why, code, uptimeMs }) => {
    const command = lastConnected.command;
    // The program 127 is about is almost never the FIRST word of the
    // command: the presets open with `mkdir -p … && exec dtach …`, and
    // "command not found" is the shell failing on the program it was
    // finally asked to run. So: last `&&`/`||`/`;` segment, minus a
    // leading `exec` and any VAR=value prefixes. A heuristic, but one
    // that names dtach for the dtach preset instead of blaming mkdir.
    const lastSegment = command.split(/&&|\|\||;/).pop() ?? "";
    const tool =
      lastSegment
        .trim()
        .split(/\s+/)
        .filter((w) => w !== "exec" && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(w))[0] ??
      command.trim().split(/\s+/)[0];
    const reconnect = (row, opts) => () => {
      row.remove();
      doConnect(opts);
    };

    if (code === 127 && uptimeMs < 5000) {
      // 127 within seconds of starting is the shell saying "command
      // not found" and nothing else happening: the session manager is
      // simply not on the target. Naming the likely cause beats an
      // "exited (127)" the user has to decode, and both ways out are
      // one tap.
      sessionOver(
        `${why}: \`${tool}\` does not seem to be installed on the target ` +
          "(the command exited 127 immediately). install it there -- the dtach, " +
          "abduco, tmux and screen packages are named after the tools -- or connect " +
          "with a plain shell.",
      );
      const row = el("div", { className: "confirm" });
      const once = el("button", { textContent: "connect with a plain shell" });
      const always = el("button", { textContent: "always use a plain shell here" });
      row.append(once, " ", always);
      // once: this connect only; the remembered command is untouched.
      once.addEventListener("click", reconnect(row, { command: "" }));
      always.addEventListener("click", () => {
        const details = connstringDetails(lastConnected.connstring);
        if (details) clearStoredCommand(details.id, lastConnected.user);
        commandInput.value = "";
        syncPresetFromCommand();
        renderHistory();
        row.remove();
        doConnect();
      });
      ask(row);
      return;
    }

    // Anything else: the command is gone from THIS connection, but a
    // session manager it started is very likely still running on the
    // target -- which is the entire point of running one. Truthful
    // hedge ("may"): a plain `exit` inside the manager ends it for
    // good, and this side cannot tell the two apart.
    sessionOver(
      `${why} — session ended or detached; the session manager may still be ` +
        "running on the target.",
    );
    const row = el("div", { className: "confirm" });
    const again = el("button", { textContent: "reattach" });
    row.append(again);
    again.addEventListener("click", reconnect(row, { command }));
    ask(row);
  };

  window.addEventListener("wosh:session-ended", async (e) => {
    const { why, kind, code, uptimeMs } = e.detail ?? {};
    if (kind === "lost") {
      try {
        if (await autoReconnect(why ?? "connection lost")) return;
      } catch {
        // fall through to the dialog
      }
      return void sessionOver(why);
    }
    // Only when this page actually asked for a command: without one
    // there is nothing to reattach to and nothing 127 could be about.
    if (kind === "ended" && lastConnected?.command) {
      return void commandSessionEnded({ why: why ?? "session ended", code, uptimeMs });
    }
    sessionOver(why);
  });

  // Method support depends on the loaded component; ask it rather
  // than assume. Probing also forces the component to load, so the
  // panel reflects reality before the user commits to anything.
  // Removing the first option promotes the next one to selected, so an
  // older component degrades to the best explicit method it has.
  (async () => {
    try {
      const caps = await capabilities();
      const drop = (v) => {
        for (const opt of [...method.options]) {
          if (opt.value === v) opt.remove();
        }
      };
      if (!caps.auto) drop("auto");
      if (!caps.publickey) {
        drop("publickey");
        showKeyBtn.disabled = true;
        notice.textContent =
          "this build of the client component has no publickey (WebCrypto) " +
          "auth yet; password and keyboard-interactive still work";
      }
      if (!caps.keyboardInteractive) drop("keyboard-interactive");
      if (!caps.execCommand) {
        // A stale precache: new page, old component. The controls stay
        // visible (so the setting they describe is still legible) but
        // cannot be armed into a promise this build cannot keep.
        presetSelect.disabled = true;
        commandInput.disabled = true;
        execNote.hidden = false;
      }
      if (!caps.passkey) {
        drop("passkey");
      } else {
        passkeySection.hidden = false;
        renderPasskey();
      }
    } catch (e) {
      notice.textContent = `could not load the client component: ${e.message ?? e}`;
    }
  })();

  // The public half is safe to show and is what the user installs on
  // the target host -- once: it persists across visits. The private
  // half never leaves the authenticator.
  showKeyBtn.addEventListener("click", async () => {
    keyRow.textContent = "loading…";
    try {
      const line = await identity();
      keyRow.textContent = "";
      keyRow.append(
        el("div", { textContent: "add this to ~/.ssh/authorized_keys on the target host:" }),
        el("code", { textContent: line }),
      );
    } catch (e) {
      keyRow.textContent = `could not obtain an identity: ${e.message ?? e}`;
    }
  });

  // The passkey section: hidden until capabilities() confirms support
  // (see above), then kept in sync with whatever is currently
  // enrolled. Truthful copy throughout: this is an ordinary
  // authorized_keys line, nothing more is installed on the target.
  passkeySection.hidden = true;
  const renderPasskey = async () => {
    passkeySection.replaceChildren();
    let line = null;
    try {
      line = await passkeyIdentity();
    } catch (e) {
      passkeyStatus.textContent = `could not read the passkey identity: ${e.message ?? e}`;
    }
    passkeySection.append(
      el("div", { className: "field" }, el("span", { textContent: "passkey" })),
    );
    if (line) {
      const help = helpToggle(
        "Nothing else is installed on the target. OpenSSH 10.3 and later accept " +
          "this line as-is; on 8.4 through 10.2 the server also needs " +
          "PubkeyAcceptedAlgorithms +webauthn-sk-ecdsa-sha2-nistp256@openssh.com " +
          "in sshd_config, or it refuses the key before ever checking a signature.",
      );
      passkeySection.append(
        el("div", {
          textContent:
            "enrolled -- add this line to ~/.ssh/authorized_keys on the target host:",
        }),
        el("code", { textContent: line }),
        el("div", { className: "row" }, forgetBtn, help.btn),
        help.body,
      );
    } else {
      // Three verbs side by side; the guidance for choosing between
      // them behind the "?". adopt… reveals its paste field on demand.
      const help = helpToggle(
        "enrol asks your platform authenticator to create a passkey, then prints an " +
          "ordinary authorized_keys line to install on the target. adopt brings in a " +
          "passkey already enrolled on another device, from the line it printed there " +
          "(one touch). recover works the public key back out of the passkey itself -- " +
          "no line, no target, no other device -- but asks for two touches of the same " +
          "passkey. Prefer adopt when the line is to hand.",
      );
      adoptRow.hidden = true; // fresh render, folded reveal
      passkeySection.append(
        el("div", { className: "sub", textContent: "no passkey enrolled" }),
        el("div", { className: "row" }, enrollBtn, adoptRevealBtn, recoverBtn, help.btn),
        adoptRow,
        help.body,
      );
    }
    passkeySection.append(passkeyStatus);
  };

  enrollBtn.addEventListener("click", async () => {
    passkeyStatus.textContent = "touch your passkey to create it…";
    try {
      await enrollPasskey();
      passkeyStatus.textContent = "";
      await renderPasskey();
    } catch (e) {
      passkeyStatus.textContent = `enrol failed: ${e.message ?? e}`;
    }
  });

  adoptBtn.addEventListener("click", async () => {
    const line = adoptInput.value.trim();
    if (!line) {
      passkeyStatus.textContent = "paste an authorized_keys line first";
      return;
    }
    passkeyStatus.textContent = "touch the passkey to confirm…";
    try {
      await adoptPasskey(line);
      passkeyStatus.textContent = "";
      await renderPasskey();
    } catch (e) {
      passkeyStatus.textContent = `adopt failed: ${e.message ?? e}`;
    }
  });

  // recover-passkey runs from a real button press, so it already has
  // user activation of its own -- it does NOT go through the
  // installPasskeyCeremonyGate below, which exists for
  // authenticate-passkey's server-triggered ceremony instead.
  recoverBtn.addEventListener("click", async () => {
    passkeyStatus.textContent = "touch the passkey twice to recover it…";
    try {
      await recoverPasskey();
      passkeyStatus.textContent = "";
      await renderPasskey();
    } catch (e) {
      passkeyStatus.textContent = `recover failed: ${e.message ?? e}`;
    }
  });

  // Two-step, same idiom as the history rows' forget button: the
  // credential survives in the authenticator either way, but this
  // client will stop offering it, so a confirming tap guards against
  // an accidental click locking someone out mid-session.
  armTwoStep(forgetBtn, "forget?", async () => {
    try {
      await forgetPasskey();
      await renderPasskey();
    } catch (e) {
      passkeyStatus.textContent = `forget failed: ${e.message ?? e}`;
    }
  });

  // The ceremony gate: authenticate-passkey needs a live user gesture
  // to run its WebAuthn assertion, but the server's demand for a
  // signature arrives while this page is polling status in the
  // background, with none in scope. This small in-panel prompt is
  // that gesture -- installed once, used by every passkey attempt.
  //
  // At most one prompt exists at a time, and a superseded one is
  // withdrawn rather than left on screen: the attempt that asked for it
  // is already gone, so a stale "the server is asking" row would be
  // inviting a tap that resolves nothing.
  let pendingCeremony = null;
  const withdrawCeremony = () => {
    pendingCeremony?.remove();
    pendingCeremony = null;
  };
  installPasskeyCeremonyGate(() =>
    new Promise((resolve, reject) => {
      withdrawCeremony();
      // The ask can arrive with the dialog CLOSED: auto-reconnect
      // after a lost session redials without opening it, and a passkey
      // (or auto steering to one) then needs a gesture mid-connect. A
      // row appended into a closed <dialog> is not rendered at all, so
      // the attempt would park forever behind a question nobody could
      // see. Open the dialog for the ask, and put it back once the
      // tap answers it -- a reconnect that needs a human is not the
      // silent kind, and pretending otherwise looks like a hang.
      const openedForThis = !panel.open;
      if (openedForThis) panel.showModal();
      const row = el("div", { className: "confirm" });
      const btn = el("button", { textContent: "touch your passkey to sign in" });
      const cancelBtn = el("button", { textContent: "cancel" });
      row.append(el("div", { textContent: "the server is asking for your passkey:" }), btn, " ", cancelBtn);
      ask(row);
      pendingCeremony = row;
      btn.addEventListener("click", () => {
        withdrawCeremony();
        // Only the door this ask opened: a ceremony raised into an
        // already-open panel (a manual connect) leaves it exactly as
        // it found it.
        if (openedForThis && panel.open) panel.close();
        resolve();
      });
      // The way out. Esc is deliberately blocked mid-connect (a hidden
      // prompt looks like a hang), so without this a seized screen
      // could only be answered with a touch. Rejecting fails the
      // assertion, which fails the attempt, legibly -- and the panel
      // stays open, because that is where the failure will be told.
      cancelBtn.addEventListener("click", () => {
        withdrawCeremony();
        reject(new Error("passkey sign-in declined"));
      });
    })
  ).catch((e) => console.warn("wosh: could not install the passkey ceremony gate", e));

  // The human decisions, rendered inline in the panel.
  const ui = {
    confirmHostKey(fingerprint, connstring = csInput.value) {
      const endpointId = endpointIdOf(connstringFrom(connstring));
      const pinned = endpointId ? loadPins()[endpointId] : undefined;

      // The pinning payoff: this listener presented exactly the
      // fingerprint the user approved-and-saved before. Note it and
      // proceed without a prompt.
      if (pinned && pinned.fp === fingerprint) {
        notice.textContent =
          `host key matches the approval saved in this browser on ${String(pinned.at).slice(0, 10)}`;
        return Promise.resolve(true);
      }

      return new Promise((resolve) => {
        const row = el("div", { className: "confirm" });
        if (pinned) {
          // Same listener identity, different SSH host key: the one
          // situation that deserves alarm, and the reason the store
          // is keyed by endpoint id rather than being a bare
          // fingerprint set.
          row.append(
            el("div", {
              className: "warn",
              textContent:
                "WARNING: this listener's SSH host key has CHANGED from the one you approved here.",
            }),
            el("div", {
              className: "warn",
              textContent:
                "That can mean the target machine was reinstalled -- or that the connection " +
                "is being intercepted. Do not approve unless the operator confirms the new fingerprint.",
            }),
            el("div", {}, "approved before: ", el("code", { textContent: pinned.fp })),
            el("div", {}, "presented now: ", el("code", { textContent: fingerprint })),
          );
        } else {
          row.append(
            el("div", { textContent: "the server presented this host key:" }),
            el("code", { textContent: fingerprint }),
            el("div", { textContent: "does it match what the operator published?" }),
          );
        }
        const yes = el("button", { textContent: "yes, connect" });
        const no = el("button", { textContent: "no" });
        // Opt-in (default off): approving never writes anything unless
        // this is checked. Offered only when the connstring yielded a
        // usable endpoint id to key the pin on.
        const remember = el("input", { type: "checkbox", id: "remember-hostkey" });
        if (endpointId) {
          row.append(
            el("div", {},
              remember,
              el("label", {
                htmlFor: "remember-hostkey",
                textContent: " remember this approval in this browser",
              })),
          );
        }
        row.append(yes, " ", no);
        ask(row);
        const done = (accepted) => {
          if (accepted && endpointId && remember.checked) savePin(endpointId, fingerprint);
          row.remove();
          resolve(accepted);
        };
        yes.addEventListener("click", () => done(true));
        no.addEventListener("click", () => done(false));
      });
    },
    getCredential() {
      // No password here: the password method collects it through
      // `collectPrompts` at the moment auth runs -- after the host key
      // is confirmed, in the same inline UI keyboard-interactive uses,
      // and never parked in a long-lived DOM input. Auto carries no
      // secret either: the component asks (through the same UI) only
      // if the server steers somewhere that needs typing.
      if (method.value === "auto") {
        return { kind: "auto" };
      }
      if (method.value === "password") {
        return { kind: "password" };
      }
      if (method.value === "keyboard-interactive") {
        return { kind: "keyboard-interactive" };
      }
      if (method.value === "passkey") {
        return { kind: "passkey" };
      }
      return { kind: "publickey" };
    },
    // One keyboard-interactive batch: instruction text, then an input
    // per prompt -- masked unless the server said echo. Resolves with
    // the answers, in order -- or null if the user cancels (no OTP to
    // give, wrong account): the caller tears the attempt down rather
    // than leaving authentication parked forever.
    collectPrompts(batch) {
      return new Promise((resolve) => {
        const row = el("div", { className: "confirm" });
        if (batch.instruction) {
          row.append(el("div", { textContent: batch.instruction }));
        }
        const inputs = (batch.prompts ?? []).map((p) => {
          const input = el("input", {
            size: 24,
            type: p.echo ? "text" : "password",
          });
          row.append(el("div", { className: "row" },
            el("label", { textContent: p.text }), input));
          return input;
        });
        const answerBtn = el("button", { textContent: "answer" });
        const cancelBtn = el("button", { textContent: "cancel" });
        row.append(el("div", { className: "row" }, answerBtn, cancelBtn));
        ask(row);
        inputs[0]?.focus();
        const done = (answers) => {
          row.remove();
          resolve(answers);
        };
        answerBtn.addEventListener("click", () => done(inputs.map((i) => i.value)));
        cancelBtn.addEventListener("click", () => done(null));
        row.addEventListener("keydown", (e) => {
          if (e.key === "Enter") done(inputs.map((i) => i.value));
        });
      });
    },
  };

  /**
   * Dial what the form says. `opts.command` OVERRIDES the field for
   * this attempt only (an automatic reattach replaying exactly what
   * ran, a "plain shell" offer after a failure): `""` means explicitly
   * no command, and leaving it out means "whatever the fold says".
   */
  const doConnect = async (opts = {}) => {
    notice.textContent = "";
    // A pasted QR link becomes its fragment here, and the field is
    // rewritten to match: what the user sees is what gets dialed (and
    // what the host-key prompt keys its pin on).
    const connstring = connstringFrom(csInput.value);
    if (connstring !== csInput.value) csInput.value = connstring;
    const user = userInput.value.trim();
    if (!connstring) return void (notice.textContent = "a connection string is required");
    if (!user) return void (notice.textContent = "a user name is required");
    // What the connection REMEMBERS (the field) and what this attempt
    // RUNS can differ: that difference is exactly what "just this
    // once" and the plain-shell offers are.
    const persistentCommand = commandInput.value.trim();
    const effectiveCommand =
      opts.command !== undefined ? opts.command : (onceShell.checked ? "" : persistentCommand);
    connectBtn.disabled = true;

    // Scrollback restore + persistence key, best-effort: this is a
    // nicety on top of connecting, and the connect path owns the
    // user's patience -- nothing here may turn into a reason a session
    // fails to open. `endpointIdOf` returning null (an unrecognized
    // connstring version) simply means no key, so no restore and no
    // persistence for this attempt, same as the toggle being off.
    // The dump is only PREFETCHED here; app.mjs paints it once the
    // session is actually up. Painting it before the dial stranded
    // another host's scrollback on screen whenever the attempt failed,
    // and spent the one-shot restore latch on nothing.
    let scrollbackKey;
    let scrollbackRestore;
    try {
      if (scrollbackEnabled()) {
        const id = endpointIdOf(connstring);
        if (id) {
          scrollbackKey = `${id} ${user}`;
          const saved = await bufferStore.get(scrollbackKey);
          if (saved?.buf) {
            scrollbackRestore = {
              buf: saved.buf,
              label: relTime(new Date(saved.at).toISOString()),
            };
          }
        }
      }
    } catch (e) {
      console.warn("wosh: scrollback restore skipped", e);
    }

    try {
      const session = await onConnect({
        connstring,
        user,
        command: effectiveCommand || undefined,
        ui,
        persistKey: scrollbackKey,
        restore: scrollbackRestore,
      });
      if (session) {
        // In-memory, unconditional (not gated on rememberConn): the
        // one thing autoReconnect needs to redial these exact
        // parameters after a `lost` close-kind. The EFFECTIVE command,
        // so a redial replays what actually ran rather than what is
        // merely remembered.
        lastConnected = { connstring, user, command: effectiveCommand || undefined };
        // History bookkeeping, only for connects that actually reached
        // a session: failed dials and rejected host keys are not
        // "connections". Checked (the default) records or bumps the
        // entry; unchecked records nothing and touches nothing --
        // forgetting is the history rows' own, confirmed, affordance.
        const details = connstringDetails(connstring);
        if (details && rememberConn.checked) {
          // The PERSISTENT command here: a one-off plain shell must
          // not quietly become the new setting.
          recordConnection(details.id, details.relay, user,
            persistentCommand, autoResumeBox.checked);
          renderHistory();
        }
        // Out of the way: the session owns the screen now. The bar's
        // buttons take over (detach, and reopening this dialog).
        detachBtn.hidden = false;
        settingsBtn.textContent = "settings";
        panel.close();
      } else if (!notice.textContent) {
        // connect() resolved null without throwing (the user rejected
        // the host key): the status line has the story; mirror it here
        // where the user is looking.
        notice.textContent = document.getElementById("status")?.textContent ?? "not connected";
      }
      return session ?? null;
    } catch (e) {
      notice.textContent = `${e.message ?? e}`;
      return null;
    } finally {
      connectBtn.disabled = false;
      // "just this once" spends itself on the attempt, not on the
      // success: a failed one-off plain shell that stayed armed would
      // silently suppress the command on the NEXT connect too.
      onceShell.checked = false;
      // An attempt that died mid-ceremony leaves nothing to tap: the
      // signature it was asking for belongs to a session that is gone.
      withdrawCeremony();
    }
  };

  // The click handler drops its event: doConnect's first argument is
  // an options object, and a MouseEvent has no `command`, but passing
  // one is the kind of accident worth not leaving available.
  connectBtn.addEventListener("click", () => doConnect());

  // Enter in either field connects -- scoped to THESE fields: the
  // prompt-batch rows manage their own Enter.
  for (const input of [csInput, userInput]) {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !connectBtn.disabled) doConnect();
    });
  }
  detachBtn.addEventListener("click", async () => {
    await detach();
    sessionOver("detached");
  });

  renderHistory();
  openPanel();

  // One-tap resume on load. The offer is only made where it can be
  // KEPT silently and where landing back is worth something: no
  // connstring in the URL (a link is a deliberate destination and wins
  // over history), the most recent connection asked for it, it runs a
  // command (so the reconnect reattaches to work that is still there
  // -- resuming into a brand-new shell is not a resume), and its host
  // key is pinned (an unpinned key needs the TOFU prompt, which is
  // never auto-answered).
  //
  // Gesture safety: nothing here implies the connect will be
  // non-interactive. The method select defaults to `auto`, which is
  // non-interactive when the browser key or a pinned passkey suffices;
  // a passkey may still raise its authenticator ceremony, and that is
  // the ceremony gate's business (it opens the dialog for the ask and
  // puts it back) -- not a reason to refuse to start. The countdown
  // itself is the consent: it is visible, it is cancellable, and
  // cancelling leaves the panel exactly as it is today.
  try {
    const entry = connstringFromLocation() ? null : loadHistory()[0];
    if (entry?.autoResume && entry.command && loadPins()[entry.id]?.fp) {
      const row = el("div", { className: "confirm" });
      const cancelBtn = el("button", { textContent: "cancel" });
      row.append(
        el("div", { textContent: `resuming ${entry.user}@${entry.id.slice(0, 8)}…` }),
        cancelBtn,
      );
      ask(row);
      const timer = setTimeout(() => {
        row.remove();
        csInput.value = tokenlessConnstring(entry.id, entry.relay);
        userInput.value = entry.user;
        commandInput.value = entry.command;
        syncPresetFromCommand();
        autoResumeBox.checked = true;
        // Errors are already the panel's story (doConnect writes the
        // notice and stays open): never a dead end.
        doConnect();
      }, 1500);
      cancelBtn.addEventListener("click", () => {
        clearTimeout(timer);
        row.remove();
      });
    }
  } catch {
    // Unreadable storage, an entry that cannot be re-encoded: the
    // ordinary panel is the fallback, and it is already on screen.
  }

  return { connect: doConnect, ui };
}
