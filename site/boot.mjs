// The chrome outside the terminal: a home screen of connection cards,
// one ask at a time in a bottom sheet, and two rare screens (identity,
// settings). Mobile is the design priority; every surface answers one
// question:
//
//   #home      which machine?           (cards; scan/paste to add one)
//   #sheet     the current question     (host key, prompts, ceremony,
//                                        the connect form, the session
//                                        sheet, card menus)
//   #identity  how do keys get installed?
//   #prefs     the three global toggles
//
// The sheet is the load-bearing idea: every question the page can ask
// rides ONE <dialog>, one at a time, with nothing else tappable behind
// it. That is what makes the old failure modes unrepresentable -- a
// prompt row could not be buried below the fold, could not survive its
// session as an answerable zombie, and could not share the screen with
// a history row that dials a different machine mid-auth. Superseding
// an ask (a new one, a new attempt, the session ending) resolves the
// old one with null, which every caller treats as its cancel path.
//
// Two durable things live behind this chrome, both narrow on purpose.
// The browser's SSH identity lives behind the component's
// `identity-store` import (site/identity-store.ts): a non-extractable
// WebCrypto pair in IndexedDB, so the key line shown on #identity
// keeps working across visits. And the host-key pin store -- approved
// SSH fingerprints keyed by the listener's endpoint id, written only
// with the user's explicit opt-in on the confirmation sheet, listed
// and revocable on #identity. TOFU floor: an unrecognized fingerprint
// is always confirmed interactively; the store can only ever suppress
// the prompt for a fingerprint a human explicitly approved before.

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
  probeSession,
  sendDetachKeys,
} from "./app.mjs";
import {
  PRESETS,
  presetById,
  matchCommand,
  validName,
  detectCommand,
  parseDetect,
} from "./sessions.mjs";
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

/** Drop one approval; the next connect to it gets the TOFU prompt again. */
function removePin(endpointId) {
  try {
    const pins = loadPins();
    delete pins[endpointId];
    localStorage.setItem(PINS_KEY, JSON.stringify(pins));
  } catch {
    // Storage refused: nothing to remove from, or nothing sticks.
  }
}

// --- global preferences -------------------------------------------------

// A single global on/off, not per-connection: the same person either
// wants this device keeping a local copy of what terminals showed, or
// doesn't. DEFAULT ON, because the failure mode of "off" (a reattach
// opens onto a blank screen while dtach or abduco has kept the actual
// session running) is exactly the confusing-looking-broken state this
// whole feature exists to avoid; #prefs carries the explanation and
// the off switch.
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

// The link-open policy. links.mjs owns the enforcement (and the value
// convention: "open" means confirmed-once, open http(s) links without
// asking); #prefs is the place the choice can be REVOKED -- the link
// dialog can only ever turn it on.
const LINKS_KEY = "wosh.links.v1";

function linksDirect() {
  try {
    return localStorage.getItem(LINKS_KEY) === "open";
  } catch {
    return false;
  }
}

function setLinksDirect(on) {
  try {
    if (on) localStorage.setItem(LINKS_KEY, "open");
    else localStorage.removeItem(LINKS_KEY);
  } catch {
    // Storage refused: every link asks, which is the safe side.
  }
}

// Whether successful connects are recorded as cards at all. Global,
// default on; the per-card forget remains the surgical tool.
const REMEMBER_KEY = "wosh.remember.v1";

function rememberEnabled() {
  try {
    return localStorage.getItem(REMEMBER_KEY) !== "off";
  } catch {
    return true;
  }
}

function setRememberEnabled(on) {
  try {
    localStorage.setItem(REMEMBER_KEY, on ? "on" : "off");
  } catch {
    // Storage refused: the toggle just does not stick.
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
 * The listener's machine-readable refusal code for "this listener does
 * not recognise this device".
 *
 * CONTRACT: `REFUSE_PAIRING` in tunnel/src/lib.rs. It reaches this
 * file inside wosh-client's `listener refused the connection:
 * {reason}`, followed by `": "` and a human sentence. Match the CODE,
 * never the sentence -- the sentence is prose and may be improved (see
 * the `passkeyHint` comment in site/app.mjs for what matching wording
 * cost us last time).
 */
export const REFUSE_PAIRING = "pairing-required";

/**
 * The shared body of this file's v3 encoders: version byte, pubkey,
 * relay spelled out (`Relay::Url` -- the well-known-index encoding is
 * an optimization this producer skips), then the token option.
 *
 * CONTRACT: connstring/src/lib.rs's `WireV2` is the decoder these
 * bytes must satisfy, and this is the ONE place this file has to agree
 * with it. The postcard details that matter: an enum variant is a
 * varint discriminant (`Relay::Url` = 0), a String is a varint length
 * then its bytes, and an `Option` is a `0` byte for `None` or a `1`
 * byte followed by the payload for `Some` -- where a `[u8; 16]` token
 * is a FIXED-size array, so its 16 bytes ride raw with NO length
 * prefix in front of them.
 *
 * `tokenBytes` is null for `None`, or the 16 raw token bytes.
 */
function v3Connstring(idHex, relay, tokenBytes) {
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
  if (tokenBytes) {
    bytes.push(1); // token: Some
    bytes.push(...tokenBytes); // fixed 16 bytes, no length prefix
  } else {
    bytes.push(0); // token: None
  }
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * A v3 connection string carrying NO pairing token.
 * What a card dials with; enrollment stands in for the token.
 */
export function tokenlessConnstring(idHex, relay) {
  return v3Connstring(idHex, relay, null);
}

/**
 * The same string WITH a pairing token. What the re-pair sheet rebuilds
 * when a saved card's enrollment is gone: the card already knows the
 * endpoint and the relay, so the token is the only missing piece.
 */
export function tokenedConnstring(idHex, relay, tokenBytes) {
  return v3Connstring(idHex, relay, tokenBytes);
}

/**
 * The alphabet a pairing token is written in: RFC 4648 base32 with `I`
 * replaced by `9`.
 *
 * CONTRACT: `TOKEN_SYMBOLS` in connstring/src/lib.rs. That one
 * substitution is what makes the encoding safe to type: in the
 * standard alphabet both `I` and `L` are symbols, so the cluster a
 * reader cannot tell apart -- `i I l L 1` -- spans two values and any
 * fold has to corrupt one of them. With `I` gone the cluster collapses
 * to `L`, case folding is unconditional, and `9` shares a shape only
 * with `g`.
 */
const TOKEN_ALPHABET = "ABCDEFGH9JKLMNOPQRSTUVWXYZ234567";

/**
 * A pairing token as a person retypes it -> its 16 bytes, or null.
 * Mirrors `token_decode` in connstring/src/lib.rs, fold included:
 * separators dropped, case folded unconditionally, and every shape
 * with one possible meaning resolved (`0`->`O`, `i I l 1`->`L`,
 * `8`->`B`).
 */
export function decodeToken(raw) {
  const folded = [...String(raw ?? "")]
    .filter((c) => !/[\s:_-]/.test(c))
    .map((c) => c.toUpperCase())
    .map((c) => (c === "0" ? "O" : c === "1" || c === "I" ? "L" : c === "8" ? "B" : c))
    .join("");
  if (folded.length !== 26) return null;
  const out = [];
  let acc = 0;
  let bits = 0;
  for (const c of folded) {
    const v = TOKEN_ALPHABET.indexOf(c);
    if (v < 0) return null;
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((acc >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  // 26 symbols carry 130 bits for a 128-bit token; the 2 left over must
  // be zero, or this is not something the listener ever printed.
  if (out.length !== 16 || (acc & ((1 << bits) - 1)) !== 0) return null;
  return out;
}


/**
 * MRU list of `{ id, relay, user, at }`, each optionally carrying
 * `name` (a human nickname for the card), `command` (the on-connect
 * command last used) and `autoResume`; [] when unavailable. Entries
 * written before those fields existed simply lack them, and an absent
 * `command` means a plain shell -- so old history keeps working
 * untouched.
 */
function loadHistory() {
  try {
    const h = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
    if (!Array.isArray(h)) return [];
    // The optional fields flow outward into command lines and card
    // labels, so a corrupted store (hand-edited, or an old bug's
    // leavings) is coerced here at the ONE reader instead of
    // type-checked at every use.
    const entries = h.filter((e) => e && typeof e === "object");
    for (const e of entries) {
      if (typeof e.command !== "string" || !e.command) delete e.command;
      if (typeof e.name !== "string" || !e.name.trim()) delete e.name;
      // A stored method must be one this page can offer; `auto` is
      // never stored, so anything else -- typos, retired methods --
      // coerces back to the auto default by absence.
      if (!METHODS.some(([v]) => v === e.method) || e.method === "auto") delete e.method;
      if (e.autoResume !== true) delete e.autoResume;
      // `tools` drives which presets are offered and which are marked
      // "not installed here", so a store that says anything other than
      // "a flat map of booleans" is dropped rather than coerced: a
      // half-believed detection result would disable a preset that
      // works, which is worse than having no detection at all.
      if (
        !e.tools || typeof e.tools !== "object" || Array.isArray(e.tools) ||
        Object.values(e.tools).some((v) => typeof v !== "boolean")
      ) {
        delete e.tools;
        delete e.toolsAt;
      }
      if (typeof e.toolsAt !== "number") delete e.toolsAt;
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
 * connection whose on-connect command was changed, not two. Fields the
 * bump does not own -- the nickname, the detection results -- are
 * PRESERVED from the old entry: reconnecting must never cost a card
 * its name.
 */
function recordConnection(id, relay, user, command, method, autoResume) {
  const prior = loadHistory().find((e) => e.id === id && e.user === user);
  const rest = loadHistory().filter((e) => !(e.id === id && e.user === user));
  const entry = { id, relay, user, at: new Date().toISOString() };
  if (prior?.name) entry.name = prior.name;
  if (prior?.tools) {
    entry.tools = prior.tools;
    if (typeof prior.toolsAt === "number") entry.toolsAt = prior.toolsAt;
  }
  if (command) entry.command = command;
  // The method that just WORKED is the connection's method; auto is
  // the default and rides as absence.
  if (method && method !== "auto") entry.method = method;
  if (autoResume === undefined ? prior?.autoResume === true : autoResume) entry.autoResume = true;
  saveHistory([entry, ...rest]);
}

/**
 * Merge `patch` into an EXISTING (id, user) entry, preserving every
 * other field. Deliberately does not create one: the writers here are
 * background observations about a connection (which session managers
 * the target has) and card-menu edits, and neither must resurrect a
 * connection the user chose not to remember.
 */
function updateConnection(id, user, patch) {
  const entries = loadHistory();
  const hit = entries.find((e) => e.id === id && e.user === user);
  if (!hit) return;
  Object.assign(hit, patch);
  saveHistory(entries);
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

/** The auth methods a connection can be told to use. `auto` is the
 * default and is never stored (an absent `method` means auto, the way
 * an absent `command` means a plain shell). */
const METHODS = [
  ["auto", "automatic (server chooses)"],
  ["publickey", "publickey (this browser's key)"],
  ["passkey", "passkey"],
  ["password", "password"],
  ["keyboard-interactive", "keyboard-interactive (OTP/2FA)"],
];

/** The card label for an entry: the nickname, or the id prefix. */
const labelOf = (entry) => entry?.name || `${entry?.id?.slice(0, 8) ?? "????????"}…`;

/// `chrome` is the overlay root (index.html's #chrome) holding the
/// three screens; the ask dialog (#sheet) and the header live outside
/// it and are looked up here. Returns `{ connect, ui }` for the page
/// and the gates.
export async function initBoot(chrome, { onConnect }) {
  const homeEl = chrome.querySelector("#home");
  const connectionEl = chrome.querySelector("#connection");
  const prefsEl = chrome.querySelector("#prefs");
  const sheet = document.getElementById("sheet");
  const dot = document.getElementById("dot");
  const who = document.getElementById("who");
  const sessionsBtn = document.getElementById("sessions-btn");

  // The bar's height, published for the session sheet to hang beneath
  // (see index.html). Measured rather than assumed: the bar grows with
  // the font, and the coarse-pointer rules make it taller on a phone.
  const publishBarHeight = () => {
    const bar = document.getElementById("bar");
    if (bar) {
      document.documentElement.style.setProperty("--bar-h", `${Math.round(bar.getBoundingClientRect().height)}px`);
    }
  };
  publishBarHeight();
  new ResizeObserver(publishBarHeight).observe(document.getElementById("bar"));

  // --- the sheet: one ask at a time --------------------------------------
  //
  // showSheet(builder) opens the dialog with the builder's content and
  // resolves with whatever the content passes to done(). Every way out
  // that is not an explicit done() -- Esc, a tap on the backdrop, a new
  // ask superseding this one, the session ending -- resolves null,
  // which every caller treats as its cancel path. One ask at a time is
  // the invariant that retired the old panel's failure modes (buried
  // prompts, zombie prompt rows, mid-auth taps on unrelated controls).
  let sheetResolve = null;

  const settleSheet = (value) => {
    const resolve = sheetResolve;
    sheetResolve = null;
    if (sheet.open) sheet.close();
    delete sheet.dataset.ask;
    delete sheet.dataset.connstring;
    resolve?.(value);
  };
  const withdrawSheet = () => {
    if (sheetResolve) settleSheet(null);
    else if (sheet.open) sheet.close();
  };
  const showSheet = (ask, build) => {
    withdrawSheet(); // supersede: the old ask resolves null first
    return new Promise((resolve) => {
      sheetResolve = resolve;
      // The x is the visible way out (backdrop taps and Esc do the
      // same); a drag handle would promise a gesture nothing implements.
      const closeX = el("button", { className: "close-x", textContent: "\u00d7", title: "close" });
      closeX.setAttribute("aria-label", "close");
      closeX.addEventListener("click", () => settleSheet(null));
      sheet.replaceChildren(closeX);
      sheet.dataset.ask = ask;
      build({
        append: (...nodes) => sheet.append(...nodes),
        done: (value) => settleSheet(value),
      });
      if (!sheet.open) sheet.showModal();
    });
  };
  // Esc routes through the same settle as everything else. Cancelling
  // an ask is always meaningful and always legible: a host-key ask
  // treats it as "don't connect", a prompt batch as cancelling the
  // attempt -- there is no state where dismissal must be refused, so
  // there is no blocked-Esc special case to look like a hang.
  sheet.addEventListener("cancel", (e) => {
    e.preventDefault();
    settleSheet(null);
  });
  // A tap outside the sheet's box is the backdrop, and means dismiss.
  sheet.addEventListener("pointerdown", (e) => {
    const r = sheet.getBoundingClientRect();
    const inside = e.clientX >= r.left && e.clientX <= r.right &&
      e.clientY >= r.top && e.clientY <= r.bottom;
    if (!inside) settleSheet(null);
  });

  // --- small shared widgets ----------------------------------------------

  /// Destructive buttons arm on the first tap (label turns into a
  /// question, briefly) and act on the second. Disarms itself after a
  /// beat.
  const armTwoStep = (btn, armedLabel, act) => {
    const idle = btn.textContent;
    let timer = null;
    btn.addEventListener("click", () => {
      if (btn.classList.contains("armed")) {
        clearTimeout(timer);
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

  /// A "?" that reveals its explanation inline, on demand. Touch has
  /// no hover, so a title attribute reaches nobody there.
  const helpToggle = (text) => {
    const body = el("div", { className: "help-body", textContent: text, hidden: true });
    const btn = el("button", { className: "help", textContent: "?", title: "explain" });
    btn.setAttribute("aria-label", "explain");
    btn.addEventListener("click", () => {
      body.hidden = !body.hidden;
    });
    return { btn, body };
  };

  /// Copy-to-clipboard with inline feedback: these lines exist to
  /// leave the device, and long-press selection of an 80-character
  /// token is a phone's worst input mode.
  const copyBtn = (text) => {
    const b = el("button", { className: "small", textContent: "copy" });
    b.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(typeof text === "function" ? text() : text);
        b.textContent = "copied";
      } catch {
        b.textContent = "copy failed";
      }
      setTimeout(() => (b.textContent = "copy"), 1500);
    });
    return b;
  };

  /// The auth-method select, offering what the loaded component can
  /// actually do (caps may still be null pre-probe: offer everything,
  /// the probe's re-render corrects screens that stay open).
  const methodSelect = () => {
    const select = el("select", { className: "method" });
    for (const [v, label] of METHODS) {
      if (caps) {
        if (v === "auto" && !caps.auto) continue;
        if (v === "publickey" && !caps.publickey) continue;
        if (v === "passkey" && !caps.passkey) continue;
        if (v === "keyboard-interactive" && !caps.keyboardInteractive) continue;
      }
      select.append(el("option", { value: v, textContent: label }));
    }
    return select;
  };

  /// The fingerprint block. The textContent is the EXACT fingerprint
  /// string -- humans compare it against what the listener printed and
  /// the gates compare it against what the component reported -- while
  /// the 4-character grouping that makes the comparison tractable is
  /// purely visual (margins on spans, no whitespace in the text).
  const fpBlock = (fingerprint, { old = false } = {}) => {
    const code = el("code", { className: `fp${old ? " old" : ""}` });
    const m = /^([A-Za-z0-9-]+:)(.*)$/.exec(fingerprint ?? "");
    const [prefix, rest] = m ? [m[1], m[2]] : ["", fingerprint ?? ""];
    if (prefix) code.append(el("span", { className: "g", textContent: prefix }));
    for (let i = 0; i < rest.length; i += 4) {
      code.append(el("span", { className: "g", textContent: rest.slice(i, i + 4) }));
    }
    return code;
  };

  // --- session state ------------------------------------------------------

  // In-memory only (never the pin/history store): the last endpoint
  // and user actually dialed, so a `lost` session can be redialed
  // without asking the user to retype anything.
  let lastConnected = null;
  // The method of the attempt in flight / most recent, for
  // ui.getCredential and the auto-reconnect eligibility check.
  let attemptMethod = "auto";
  // One dial at a time: a card tap landing while a connect is in
  // flight must not start a second, concurrent attempt.
  let dialing = false;
  // One silent reconnect per minute (15s when a command reattaches):
  // a session that keeps dying gets a human decision instead of
  // silently churning fresh shells.
  let lastAutoAt = 0;
  // When the session sheet last asked a manager to park the session
  // with its own keystroke; the pump notices the channel closing a
  // moment later and fires an ordinary `ended` event, which must not
  // turn into the reattach offer.
  let politeDetachAt = 0;
  // A transient line for #home (errors, "host key rejected…"),
  // re-rendered with the screen.
  let homeNotice = "";
  // Component capabilities, probed once; null until known.
  let caps = null;

  const setLive = (user, label) => {
    document.body.classList.add("live");
    dot.className = "ok";
    who.textContent = `${user}@${label}`;
  };
  const setIdle = () => {
    document.body.classList.remove("live");
    dot.className = "";
    who.textContent = "";
  };
  // The transport dot: green attached, amber while the component
  // silently redials (app.mjs relays link-state from its output pump).
  window.addEventListener("wosh:link-state", (e) => {
    if (!document.body.classList.contains("live")) return;
    const kind = e.detail?.kind;
    if (kind === "reconnecting" || kind === "stalled") dot.className = "warn";
    else if (kind === "attached") dot.className = "ok";
  });

  // --- screens -------------------------------------------------------------

  const showChrome = (which) => {
    chrome.hidden = false;
    for (const s of [homeEl, connectionEl, prefsEl]) s.classList.toggle("on", s.id === which);
    if (which === "home") renderHome();
    if (which === "connection") renderConnection();
    if (which === "prefs") renderPrefs();
  };
  const hideChrome = () => {
    chrome.hidden = true;
  };

  /// Back to #home with a line explaining why (a failed dial, a
  /// rejected host key, "detached"). The single idle-state funnel:
  /// every way a session ends and every way an attempt fails lands
  /// here, so the page can never strand a dead screen.
  const idleHome = (msg) => {
    setIdle();
    // Only clear the screen's question when no dial is in flight. A
    // session dying is not a reason to withdraw an ask that belongs to
    // the attempt REPLACING it -- and that ordering really happens: the
    // old session's `ended` event lands while its replacement is
    // already parked on a host-key confirmation. Withdrawing there left
    // the new attempt waiting on an answer to a question no longer on
    // screen, which is the one failure the one-ask-at-a-time model
    // exists to make impossible. A dial that fails clears its own ask
    // on the way in (doConnect withdraws first thing).
    if (!dialing) withdrawSheet();
    homeNotice = msg ?? "";
    showChrome("home");
  };

  /// The deploy identity for the footer of #home and #prefs: the git
  /// short hash + build time scripts/site-deploy-tree.sh substituted
  /// into index.html's metas -- the same version string that keys the
  /// service worker's cache, so what the footer says is what the cache
  /// holds. A raw site/ tree still carries the placeholders, and the
  /// footer says so instead of pretending.
  const buildInfo = () => {
    const read = (name) =>
      document.querySelector(`meta[name="${name}"]`)?.content ?? "";
    const version = read("wosh-version");
    const build = read("wosh-build");
    if (!version || version.startsWith("__WOSH_")) return "dev build";
    return `build ${build && !build.startsWith("__WOSH_") ? build : "?"} (${version})`;
  };
  const buildLine = () => el("div", { className: "buildinfo", textContent: buildInfo() });

  const QR_GLYPH =
    '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M3 3h8v8H3V3zm2 2v4h4V5H5zm8-2h8v8h-8V3zm2 2v4h4V5h-4zM3 13h8v8H3v-8zm2 2v4h4v-4H5zm8-2h3v3h-3v-3zm5 0h3v3h-3v-3zm-5 5h3v3h-3v-3zm5 0h3v3h-3v-3z"/></svg>';

  // The auto-resume countdown ticker, so a re-render or a cancel can
  // stop it. Armed once per page load (resumePending), and only when
  // the top card qualifies; any interaction elsewhere on the screen
  // cancels it -- the countdown is consent, and consent needs an easy
  // exit.
  let resumeTimer = null;
  let resumePending = !connstringFromLocation();
  const cancelResume = () => {
    if (resumeTimer !== null) clearInterval(resumeTimer);
    resumeTimer = null;
    resumePending = false;
  };

  /// Update #home's transient line in place (and remember it for the
  /// next render): notes like the pin-match line land while the screen
  /// may or may not be showing.
  const setHomeNotice = (text) => {
    homeNotice = text ?? "";
    const n = homeEl.querySelector(".notice");
    if (n) n.textContent = homeNotice;
  };

  // --- #home ---------------------------------------------------------------

  function renderHome() {
    if (resumeTimer !== null) {
      clearInterval(resumeTimer);
      resumeTimer = null;
    }
    homeEl.replaceChildren();
    const live = document.body.classList.contains("live");
    const entries = loadHistory();
    const pins = loadPins();

    const settingsLink = el("button", { className: "applink", textContent: "settings" });
    settingsLink.addEventListener("click", () => {
      cancelResume();
      prefsReturn = "home";
      showChrome("prefs");
    });
    homeEl.append(el("div", { className: "pad" },
      el("div", { className: "topline" },
        el("span", { className: "wordmark", textContent: "wosh" }), settingsLink)));

    const pad = el("div", { className: "pad", style: "padding-top: 0" });
    homeEl.append(pad);

    if (live) {
      // Reached mid-session (session sheet → "new connection…"): the
      // way back must be as plain as the way here.
      const back = el("button", { className: "secondary", textContent: "back to the session" });
      back.addEventListener("click", () => hideChrome());
      pad.append(back);
    }

    // The scan/paste pair: how a machine is added. Scan is the primary
    // -- the QR is the product's bootstrap -- and paste is the fallback
    // right under it.
    const addBlock = () => {
      const scan = el("button", { className: "primary scan" });
      scan.innerHTML = `${QR_GLYPH} scan the listener's QR`;
      scan.addEventListener("click", () => {
        cancelResume();
        scanFlow();
      });
      const paste = el("input", {
        type: "text",
        className: "connstring",
        placeholder: "or paste a wosh link",
      });
      const go = el("button", { className: "go", textContent: "→", title: "connect to the pasted link" });
      go.setAttribute("aria-label", "connect to the pasted link");
      const submit = () => {
        const cs = connstringFrom(paste.value);
        if (!cs) return;
        cancelResume();
        dialWithSheet(cs);
      };
      go.addEventListener("click", submit);
      paste.addEventListener("keydown", (e) => {
        if (e.key === "Enter") submit();
      });
      paste.addEventListener("focus", cancelResume);
      return el("div", {},
        el("div", { className: "scanrow" }, scan),
        el("div", { className: "pasterow" }, paste, go));
    };

    if (entries.length === 0 && !live) {
      // First run: one line of what this is, then the two ways in.
      const hero = el("div", { className: "hero" });
      const inner = el("div", { className: "inner" });
      hero.append(inner);
      inner.append(el("div", {
        className: "pitch",
        textContent: "a real SSH session in this browser, reaching a machine with no open ports.",
      }));
      inner.append(addBlock());
      inner.append(el("div", { className: "hint", textContent: "the listener prints both when it starts" }));
      inner.append(el("div", { className: "notice", textContent: homeNotice }));
      homeEl.append(hero);
    } else {
      if (entries.length) pad.append(el("div", { className: "label", textContent: "connections" }));
      let firstCard = null;
      for (const entry of entries) {
        const row = el("button", {
          className: "histrow",
          title: `relay ${entry.relay}\nendpoint ${entry.id}\nlast connected ${entry.at}`,
        });
        const sub = el("span", { className: "sub" });
        if (pins[entry.id]?.fp) sub.append(el("span", { className: "pill ok", textContent: "key pinned" }));
        if (entry.command) {
          const m = matchCommand(entry.command);
          sub.append(el("span", {
            className: "pill",
            textContent: m ? `${m.preset.id}: ${m.name}` : "runs a command",
          }));
        }
        if (entry.method) {
          sub.append(el("span", { className: "pill", textContent: entry.method }));
        }
        sub.append(relTime(entry.at));
        const body = el("span", { className: "body" },
          el("span", { className: "title", textContent: `${entry.user}@${labelOf(entry)}` }), sub);
        // A span, not a nested button (invalid HTML that Chromium
        // hoists out of the card): the card is the button, the ⋯ is a
        // click target inside it.
        const more = el("span", { className: "more", textContent: "⋯", title: "connection options" });
        more.setAttribute("role", "button");
        more.addEventListener("click", (e) => {
          e.stopPropagation();
          cancelResume();
          connectionFor = { id: entry.id, user: entry.user };
          showChrome("connection");
        });
        row.append(body, more);
        row.addEventListener("click", () => {
          cancelResume();
          dialFromEntry(entry);
        });
        pad.append(row);
        firstCard ??= row;
      }
      pad.append(el("div", { className: "label", textContent: "add a machine" }));
      pad.append(addBlock());
      pad.append(el("div", { className: "notice", textContent: homeNotice }));

      // One-tap resume, ON the card it resumes, with a REAL countdown:
      // visible seconds, a cancel beside it, and any interaction
      // elsewhere on the screen calls it off. Offered only where it can
      // be kept silently: the most recent connection asked for it
      // (autoResume), it runs a command (so the reconnect reattaches to
      // work that is still there), and its host key is pinned (an
      // unpinned key needs the TOFU ask, which is never auto-answered).
      const entry = entries[0];
      if (resumePending && !live && entry?.autoResume && entry.command && pins[entry.id]?.fp) {
        firstCard.classList.add("resuming");
        const t = el("span", { className: "t" });
        const fill = el("span", { className: "resume-fill" });
        const cancelB = el("button", { textContent: "cancel" });
        const rr = el("span", { className: "resume-row" },
          t, el("span", { className: "resume-track" }, fill), cancelB);
        firstCard.querySelector(".body").append(rr);
        let secs = 4;
        const paint = () => {
          t.textContent = `resuming in ${secs}s`;
          fill.style.width = `${((4 - secs) / 4) * 100}%`;
        };
        paint();
        resumeTimer = setInterval(() => {
          secs -= 1;
          if (secs > 0) return paint();
          cancelResume();
          dialFromEntry(entry);
        }, 1000);
        cancelB.addEventListener("click", (e) => {
          e.stopPropagation();
          cancelResume();
          firstCard.classList.remove("resuming");
          rr.remove();
        });
      }
    }
    homeEl.append(buildLine());
  }

  // --- #connection: per-connection settings -----------------------------
  //
  // Everything ABOUT one card, on its own screen (the old ⋯ menu-sheet
  // was a list of verbs pointing at more sheets; settings deserve a
  // settings screen). Edits write through to the stored entry as they
  // are made.

  // Which connection the screen shows, set by the card's ⋯ button.
  let connectionFor = null;

  function renderConnection() {
    connectionEl.replaceChildren();
    const entry = connectionFor
      ? loadHistory().find((e) => e.id === connectionFor.id && e.user === connectionFor.user)
      : null;
    if (!entry) return void showChrome("home"); // forgotten underneath us
    const back = el("button", { className: "back", textContent: "\u2039" });
    back.setAttribute("aria-label", "back");
    back.addEventListener("click", () => showChrome("home"));
    connectionEl.append(el("div", { className: "backrow" }, back,
      el("h1", { textContent: `${entry.user}@${labelOf(entry)}` })));

    // Nickname: written on change (blur/Enter), not per keystroke, so
    // typing is not fighting a re-render.
    const nickCard = el("div", { className: "idcard" });
    nickCard.append(el("h3", { textContent: "nickname" }));
    const nick = el("input", { type: "text", value: entry.name ?? "", placeholder: "a name for this card" });
    nick.style.fontFamily = "var(--sans)";
    nick.addEventListener("change", () => {
      updateConnection(entry.id, entry.user, { name: nick.value.trim() || undefined });
      renderConnection(); // the title above echoes it
    });
    nickCard.append(nick);
    connectionEl.append(nickCard);

    // Run on connect: the same preset/name/command trio the connect
    // sheet carries, writing through to the stored entry. The field is
    // the truth; the select and the name are a view of it.
    const cmdCard = el("div", { className: "idcard" });
    cmdCard.append(el("h3", { textContent: "run on connect" }));
    const notice = el("div", { className: "notice" });
    const preset = el("select", { className: "preset" });
    preset.append(el("option", { value: "", textContent: "plain shell" }));
    for (const p of PRESETS) {
      const missing = !!entry.tools && entry.tools[p.id] === false;
      preset.append(el("option", {
        value: p.id,
        textContent: missing ? `${p.label} — not installed here` : p.label,
        disabled: missing,
      }));
    }
    preset.append(el("option", { value: "custom", textContent: "custom…" }));
    const name = el("input", { type: "text", className: "sessname", placeholder: "main" });
    const command = el("input", {
      type: "text",
      className: "command",
      placeholder: "command to run instead of a shell",
      value: entry.command ?? "",
    });
    const nameOr = () => name.value.trim() || "main";
    const store = () => {
      const cmd = command.value.trim();
      if (cmd) updateConnection(entry.id, entry.user, { command: cmd });
      else clearStoredCommand(entry.id, entry.user);
    };
    const templateCommand = () => {
      const p = presetById(preset.value);
      if (!p) return;
      if (!validName(nameOr())) {
        notice.textContent = "a session name may only use letters, digits, - and _ (up to 32 characters)";
        return;
      }
      notice.textContent = "";
      command.value = p.command(nameOr());
      store();
    };
    const syncFromCommand = () => {
      const v = command.value.trim();
      if (!v) return void (preset.value = "");
      const hit = matchCommand(v);
      preset.value = hit ? hit.preset.id : "custom";
      if (hit) name.value = hit.name;
    };
    preset.addEventListener("change", () => {
      if (preset.value === "custom") return;
      if (!preset.value) {
        command.value = "";
        return void store();
      }
      templateCommand();
    });
    name.addEventListener("input", () => {
      if (presetById(preset.value)) templateCommand();
    });
    command.addEventListener("input", syncFromCommand);
    command.addEventListener("change", store);
    syncFromCommand();
    const plainOnce = el("button", { className: "small", textContent: "connect with a plain shell" });
    plainOnce.addEventListener("click", () => dialFromEntry(entry, { command: "" }));
    cmdCard.append(
      el("div", { className: "fieldlabel", textContent: "preset" }), preset,
      el("div", { className: "fieldlabel", textContent: "session name" }), name,
      el("div", { className: "fieldlabel", textContent: "command" }), command,
      notice,
      el("div", { className: "row" }, plainOnce),
    );
    connectionEl.append(cmdCard);

    // Auth: which method this connection dials with. Stored on the
    // entry; auto is the default and rides as absence.
    const authCard = el("div", { className: "idcard" });
    authCard.append(el("h3", { textContent: "auth method" }));
    const method = methodSelect();
    method.value = entry.method ?? "auto";
    method.addEventListener("change", () => {
      updateConnection(entry.id, entry.user, {
        method: method.value === "auto" ? undefined : method.value,
      });
    });
    authCard.append(method);
    connectionEl.append(authCard);

    const behaveCard = el("div", { className: "idcard" });
    const auto = el("input", { type: "checkbox", checked: entry.autoResume === true });
    auto.addEventListener("change", () => {
      updateConnection(entry.id, entry.user, { autoResume: auto.checked ? true : undefined });
    });
    behaveCard.append(el("label", { className: "check" }, auto,
      " reconnect automatically when this page opens"));
    connectionEl.append(behaveCard);

    // The facts the old card hid in a hover tooltip -- which no phone
    // ever showed anyone.
    const factsCard = el("div", { className: "idcard" });
    factsCard.append(el("h3", { textContent: "details" }));
    const pin = loadPins()[entry.id];
    factsCard.append(
      el("div", { className: "keyblock", textContent: `endpoint ${entry.id}\nrelay ${entry.relay}` }),
      el("div", {
        className: "sub",
        textContent: pin
          ? `host key pinned — approved ${String(pin.at).slice(0, 10)} (revocable under settings)`
          : "no host key pinned: the next connect asks for confirmation",
      }),
    );
    connectionEl.append(factsCard);

    const dangerCard = el("div", { className: "idcard" });
    const forget = el("button", { className: "small danger", textContent: "forget this connection…" });
    armTwoStep(forget, "forget it?", () => {
      removeConnection(entry.id, entry.user);
      showChrome("home");
    });
    dangerCard.append(el("div", { className: "row" }, forget));
    connectionEl.append(dangerCard);
  }

  // --- #prefs ---------------------------------------------------------------

  /// Where settings came from, so leaving it goes back there rather
  /// than always to the connection list: opened from a live session,
  /// the way out is that session.
  let prefsReturn = "home";

  function renderPrefs() {
    prefsEl.replaceChildren();
    const live = document.body.classList.contains("live");
    const toSession = live && prefsReturn === "session";
    const back = el("button", { className: "back", textContent: "‹" });
    back.setAttribute("aria-label", toSession ? "back to the session" : "back");
    back.addEventListener("click", () => {
      if (toSession) return hideChrome();
      showChrome("home");
    });
    prefsEl.append(el("div", { className: "backrow" }, back,
      el("h1", { textContent: toSession ? "settings & keys" : "settings" })));

    const prefRow = (id, checked, title, desc, onChange) => {
      const box = el("input", { type: "checkbox", id, checked });
      box.addEventListener("change", () => onChange(box.checked));
      return el("label", { className: "prefrow" }, box,
        el("span", { className: "body" },
          el("span", { className: "t", textContent: title }),
          el("div", { className: "d", textContent: desc })));
    };
    const card = el("div", { className: "idcard" });
    card.append(
      prefRow("pref-scrollback", scrollbackEnabled(), "keep scrollback on this device",
        "a local copy of what each terminal showed, so a reattach doesn't start " +
          "blank — dtach and abduco keep no screen state of their own, and tmux and " +
          "screen keep only the visible screen. stored only in this browser; " +
          "turning it off deletes what is stored.",
        (on) => {
          setScrollbackEnabled(on);
          if (!on) bufferStore.wipe().catch((e) => console.warn("wosh: could not wipe scrollback", e));
        }),
      prefRow("pref-links", linksDirect(), "open links without asking",
        "http(s) links painted in the terminal open on one tap instead of showing " +
          "a confirmation first.",
        setLinksDirect),
      prefRow("pref-remember", rememberEnabled(), "remember new connections",
        "endpoint id, relay and user name only — the pairing token is never saved.",
        setRememberEnabled),
    );
    prefsEl.append(card);

    // --- identity & keys: just more settings, so they live here -------

    // The browser's key: rendered on demand (the first press loads the
    // component), then shown with a copy button -- the line's entire
    // purpose is to leave this device.
    const keyCard = el("div", { className: "idcard" });
    keyCard.append(
      el("h3", { textContent: "this browser's key" }),
      el("p", {
        textContent: "a sign-in key minted in this browser. the private half is " +
          "non-extractable — wosh can sign with it, nothing can read it. install " +
          "the line once on each target:",
      }),
    );
    const keyRow = el("div", { className: "key" });
    const showBtn = el("button", { className: "small", textContent: "show this browser's public key" });
    showBtn.addEventListener("click", async () => {
      keyRow.textContent = "loading…";
      try {
        const line = await identity();
        keyRow.replaceChildren(
          el("code", { textContent: line }),
          el("div", { className: "row" }, copyBtn(line)),
        );
      } catch (e) {
        keyRow.textContent = `could not obtain an identity: ${e.message ?? e}`;
      }
    });
    keyCard.append(el("div", { className: "row" }, showBtn), keyRow);
    if (caps && !caps.publickey) {
      showBtn.disabled = true;
      keyCard.append(el("p", {
        textContent: "this build of the client component has no publickey (WebCrypto) " +
          "auth yet; password and keyboard-interactive still work",
      }));
    }
    prefsEl.append(keyCard);

    // The passkey: same visual register (an ordinary authorized_keys
    // line), plus its own enrol/adopt/recover/forget verbs. Hidden
    // until capabilities() confirms both the component build and the
    // platform support it.
    const passkeyCard = el("div", { className: "idcard passkey", hidden: true });
    prefsEl.append(passkeyCard);
    const renderPasskey = async () => {
      if (!caps?.passkey) return;
      passkeyCard.hidden = false;
      passkeyCard.replaceChildren(el("h3", { textContent: "passkey" }));
      const status = el("div", { className: "sub" });
      let line = null;
      try {
        line = await passkeyIdentity();
      } catch (e) {
        status.textContent = `could not read the passkey identity: ${e.message ?? e}`;
      }
      if (line) {
        const help = helpToggle(
          "Nothing else is installed on the target. OpenSSH 10.3 and later accept " +
            "this line as-is; on 8.4 through 10.2 the server also needs " +
            "PubkeyAcceptedAlgorithms +webauthn-sk-ecdsa-sha2-nistp256@openssh.com " +
            "in sshd_config, or it refuses the key before ever checking a signature.",
        );
        const forgetBtn = el("button", { className: "small danger", textContent: "forget…" });
        armTwoStep(forgetBtn, "forget it?", async () => {
          try {
            await forgetPasskey();
            await renderPasskey();
          } catch (e) {
            status.textContent = `forget failed: ${e.message ?? e}`;
          }
        });
        const actions = el("div", { className: "row" }, copyBtn(line), forgetBtn, help.btn);
        passkeyCard.append(
          el("p", { textContent: "enrolled — add this line to ~/.ssh/authorized_keys on the target host:" }),
          el("code", { textContent: line }),
          actions,
          help.body,
          status,
        );
      } else {
        const help = helpToggle(
          "enrol asks your platform authenticator to create a passkey, then prints an " +
            "ordinary authorized_keys line to install on the target. adopt brings in a " +
            "passkey already enrolled on another device, from the line it printed there " +
            "(one touch). recover works the public key back out of the passkey itself -- " +
            "no line, no target, no other device -- but asks for two touches of the same " +
            "passkey. Prefer adopt when the line is to hand.",
        );
        const enrollBtn = el("button", { className: "small", textContent: "enrol" });
        enrollBtn.addEventListener("click", async () => {
          status.textContent = "touch your passkey to create it…";
          try {
            await enrollPasskey();
            await renderPasskey();
          } catch (e) {
            status.textContent = `enrol failed: ${e.message ?? e}`;
          }
        });
        const adoptInput = el("input", {
          type: "text",
          placeholder: "paste the authorized_keys line from another device",
        });
        const adoptGo = el("button", { className: "small", textContent: "adopt" });
        adoptGo.addEventListener("click", async () => {
          const pasted = adoptInput.value.trim();
          if (!pasted) return void (status.textContent = "paste an authorized_keys line first");
          status.textContent = "touch the passkey to confirm…";
          try {
            await adoptPasskey(pasted);
            await renderPasskey();
          } catch (e) {
            status.textContent = `adopt failed: ${e.message ?? e}`;
          }
        });
        const adoptRow = el("div", { className: "row", hidden: true }, adoptInput, adoptGo);
        const adoptReveal = el("button", { className: "small", textContent: "adopt…" });
        adoptReveal.addEventListener("click", () => {
          adoptRow.hidden = !adoptRow.hidden;
          if (!adoptRow.hidden) adoptInput.focus();
        });
        const recoverBtn = el("button", { className: "small", textContent: "recover" });
        recoverBtn.addEventListener("click", async () => {
          status.textContent = "touch the passkey twice to recover it…";
          try {
            await recoverPasskey();
            await renderPasskey();
          } catch (e) {
            status.textContent = `recover failed: ${e.message ?? e}`;
          }
        });
        passkeyCard.append(
          el("div", { className: "sub", textContent: "no passkey enrolled" }),
          el("div", { className: "row" }, enrollBtn, adoptReveal, recoverBtn, help.btn),
          adoptRow,
          help.body,
          status,
        );
      }
    };
    renderPasskey().catch(() => {});

    // The pin store, visible: which machine keys this browser would
    // connect to without asking, and the way to take one back.
    const pinsCard = el("div", { className: "idcard pins" });
    pinsCard.append(
      el("h3", { textContent: "approved machine keys" }),
      el("p", {
        textContent: "host keys you told this browser to remember. forgetting one " +
          "brings the confirmation back on the next connect.",
      }),
    );
    const pins = loadPins();
    const names = new Map(loadHistory().map((e) => [e.id, e.name]));
    const ids = Object.keys(pins);
    if (ids.length === 0) {
      pinsCard.append(el("div", { className: "sub", textContent: "none yet" }));
    }
    for (const id of ids) {
      const nick = names.get(id);
      const label = `${nick ? `${nick} · ` : ""}${id.slice(0, 8)}…`;
      const forget = el("button", { className: "small danger", textContent: "forget…" });
      armTwoStep(forget, "forget it?", () => {
        removePin(id);
        renderPrefs();
      });
      pinsCard.append(el("div", { className: "pinrow" },
        el("span", { className: "id", textContent: label }),
        el("span", { className: "at", textContent: `approved ${String(pins[id].at).slice(0, 10)}` }),
        el("span", { className: "spacer" }),
        forget));
    }
    prefsEl.append(pinsCard);

    const wipeCard = el("div", { className: "idcard" });
    const forgetAll = el("button", { className: "small danger", textContent: "forget all connections…" });
    armTwoStep(forgetAll, "forget all?", () => {
      saveHistory([]);
      renderPrefs();
    });
    wipeCard.append(el("div", { className: "row" }, forgetAll));
    prefsEl.append(wipeCard, buildLine());
  }

  // --- the asks --------------------------------------------------------------

  /// The host-key gate's sheet. Resolves `{ ok, remember }`; dismissal
  /// is `{ ok: false }`. The changed-key variant inverts the ordinary
  /// emphasis -- the SAFE choice is the primary and the dangerous one
  /// is quiet, red, and takes two taps -- and never writes a pin: on
  /// the one alarming screen, re-approving a key is a deliberate
  /// follow-up (forget the old approval on #identity), not a ride-along
  /// checkbox.
  function hostKeyAsk(fingerprint, { pinned, target }) {
    return showSheet("hostkey", ({ append, done }) => {
      const wrap = el("div", { className: "confirm" });
      if (pinned) {
        wrap.append(
          el("h2", { className: "warn", textContent: "this machine's SSH host key has CHANGED" }),
          el("p", {
            textContent: "a reinstall looks like this — but so does an interception. " +
              "do not approve unless the operator confirms the new fingerprint.",
          }),
          el("div", { className: "fieldlabel", textContent: "approved before" }),
          fpBlock(pinned.fp, { old: true }),
          el("div", { className: "fieldlabel", textContent: "presented now" }),
          fpBlock(fingerprint),
        );
        const no = el("button", { className: "primary", textContent: "don't connect" });
        const yes = el("button", { className: "danger", textContent: "connect anyway" });
        no.addEventListener("click", () => done({ ok: false }));
        armTwoStep(yes, "really connect?", () => done({ ok: true, remember: false }));
        wrap.append(el("div", { className: "stack" }, no, yes));
      } else {
        wrap.append(
          el("h2", { textContent: "confirm this machine's key" }),
          // Honest provenance: the LISTENER never sees this key (it is
          // a dumb pipe; the fingerprint is verified end-to-end through
          // the tunnel), so there is nothing "printed next to the QR"
          // to compare against. The truth lives on the machine itself,
          // or with whoever operates it.
          el("p", {
            textContent: `first connection to ${target}. this is the SSH host key ` +
              "that machine presented — check it against the machine itself, or " +
              "against what its operator published:",
          }),
          fpBlock(fingerprint),
          // Two ways to check, both real. The listener prints this
          // same fingerprint when it observes the handshake it is
          // proxying -- but only when its own known_hosts corroborates
          // it, or when it is running on the target machine itself, so
          // "the listener said so" is never a claim it cannot back.
          el("div", {
            className: "hedge",
            textContent: "the listener prints this same line when it can vouch for it. " +
              "on the target: ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub — one line's " +
              "SHA256 must match this exactly",
          }),
        );
        // Opt-in (default off): approving never writes anything unless
        // this is checked.
        const remember = el("input", { type: "checkbox", id: "remember-hostkey" });
        wrap.append(el("label", { className: "check" }, remember, " remember this key in this browser"));
        const yes = el("button", { className: "primary", textContent: "it matches — connect" });
        const no = el("button", { className: "quiet", textContent: "don't connect" });
        yes.addEventListener("click", () => done({ ok: true, remember: remember.checked }));
        no.addEventListener("click", () => done({ ok: false }));
        wrap.append(el("div", { className: "stack" }, yes, no));
      }
      append(wrap);
    });
  }

  /// One keyboard-interactive batch: instruction text, then an input
  /// per prompt -- masked unless the server said echo. Resolves the
  /// answers in order, or null when cancelled (the caller tears the
  /// attempt down rather than leaving authentication parked forever).
  function promptsAsk(batch) {
    return showSheet("prompts", ({ append, done }) => {
      const wrap = el("div", { className: "confirm" });
      wrap.append(el("h2", { textContent: "the server asks" }));
      if (batch.instruction) wrap.append(el("p", { textContent: batch.instruction }));
      const inputs = (batch.prompts ?? []).map((p) => {
        const input = el("input", { type: p.echo ? "text" : "password" });
        wrap.append(el("div", { className: "fieldlabel", textContent: p.text }), input);
        return input;
      });
      const answer = el("button", { className: "primary", textContent: "answer" });
      const cancel = el("button", { className: "quiet", textContent: "cancel" });
      const submit = () => done(inputs.map((i) => i.value));
      answer.addEventListener("click", submit);
      cancel.addEventListener("click", () => done(null));
      wrap.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && e.target !== cancel) submit();
      });
      wrap.append(el("div", { className: "stack" }, answer, cancel));
      append(wrap);
      setTimeout(() => inputs[0]?.focus(), 0);
    });
  }

  // The ceremony gate: authenticate-passkey needs a live user gesture
  // for its WebAuthn assertion, but the server's demand for a signature
  // arrives while the page is polling in the background, with none in
  // scope. This sheet is that gesture. Cancelling (or the sheet being
  // superseded -- its attempt is gone) rejects, which fails the
  // assertion, which fails the attempt, legibly.
  installPasskeyCeremonyGate(() =>
    new Promise((resolve, reject) => {
      showSheet("ceremony", ({ append, done }) => {
        const wrap = el("div", { className: "confirm" });
        wrap.append(
          el("h2", { textContent: "passkey sign-in" }),
          el("p", { textContent: "the server is asking for your passkey:" }),
        );
        const go = el("button", { className: "primary", textContent: "touch your passkey to sign in" });
        const cancel = el("button", { className: "quiet", textContent: "cancel" });
        go.addEventListener("click", () => done(true));
        cancel.addEventListener("click", () => done(false));
        wrap.append(el("div", { className: "stack" }, go, cancel));
        append(wrap);
      }).then((v) => (v ? resolve() : reject(new Error("passkey sign-in declined"))));
    })
  ).catch((e) => console.warn("wosh: could not install the passkey ceremony gate", e));

  /// The connect form, as a sheet: who are you on that machine, plus
  /// the folded auth/session options. Resolves `{ user, method,
  /// command }` or null.
  function connectSheet({ connstring, error, prefill } = {}) {
    const details = connstringDetails(connstring);
    const id = endpointIdOf(connstring);
    const entry = id ? loadHistory().find((e) => e.id === id) : null;
    return showSheet("connect", ({ append, done }) => {
      // For the gates and the curious: what this sheet would dial.
      sheet.dataset.connstring = connstring;
      append(el("h2", { textContent: entry?.name ? `connect to ${entry.name}` : "new connection" }));
      append(el("div", {
        className: "target",
        textContent: details
          ? `${details.id.slice(0, 16)}… via ${details.relay}`
          : `${connstring.slice(0, 40)}${connstring.length > 40 ? "…" : ""}`,
      }));
      const notice = el("div", { className: "notice", textContent: error ?? "" });
      append(el("div", { className: "fieldlabel", textContent: "user on that machine" }));
      const user = el("input", { type: "text", placeholder: "user", value: prefill?.user ?? entry?.user ?? "" });
      append(user);

      // Everything about HOW to authenticate and WHAT to run, behind
      // one fold: needed when installing a key or setting up a session
      // manager, and not at all on the ordinary connect.
      const method = methodSelect();
      method.value = prefill?.method ?? entry?.method ?? "auto";

      const preset = el("select", { className: "preset" });
      preset.append(el("option", { value: "", textContent: "plain shell" }));
      for (const p of PRESETS) {
        // Detection results recorded for this connection mark the
        // presets the host is known NOT to have; absent data leaves
        // plain labels ("we never looked" must not read as "not
        // installed").
        const missing = !!entry?.tools && entry.tools[p.id] === false;
        preset.append(el("option", {
          value: p.id,
          textContent: missing ? `${p.label} — not installed here` : p.label,
          disabled: missing,
        }));
      }
      preset.append(el("option", { value: "custom", textContent: "custom…" }));
      const name = el("input", { type: "text", className: "sessname", placeholder: "main" });
      const command = el("input", {
        type: "text",
        className: "command",
        placeholder: "command to run instead of a shell",
        value: prefill?.command ?? entry?.command ?? "",
      });
      const cmdHelp = helpToggle(
        "This runs on the target instead of a login shell. With a create-or-attach " +
          "session manager the same line both starts the session and reattaches to it, " +
          "so a later connect lands in the SAME session and the work survives closing " +
          "this tab. The tool has to be installed on the target already -- nothing is " +
          "installed for you. dtach and abduco keep no copy of the screen contents; " +
          "tmux and screen keep the visible screen. On a systemd host with " +
          "KillUserProcesses=yes, run `loginctl enable-linger <user>` or a detached " +
          "session dies with the logout.",
      );
      const nameOr = () => name.value.trim() || "main";
      // preset + name -> the field. Refuses rather than quotes: the
      // name goes into a shell command line on the target, and
      // sessions.mjs's whitelist is what makes that safe.
      const templateCommand = () => {
        const p = presetById(preset.value);
        if (!p) return;
        if (!validName(nameOr())) {
          notice.textContent = "a session name may only use letters, digits, - and _ (up to 32 characters)";
          return;
        }
        notice.textContent = "";
        command.value = p.command(nameOr());
      };
      // The field is the truth; the select and the name are a view of
      // it, so a hand-edited preset line honestly reads back as
      // "custom…".
      const syncFromCommand = () => {
        const v = command.value.trim();
        if (!v) return void (preset.value = "");
        const hit = matchCommand(v);
        preset.value = hit ? hit.preset.id : "custom";
        if (hit) name.value = hit.name;
      };
      preset.addEventListener("change", () => {
        if (preset.value === "custom") return;
        if (!preset.value) return void (command.value = "");
        templateCommand();
      });
      name.addEventListener("input", () => {
        if (presetById(preset.value)) templateCommand();
      });
      command.addEventListener("input", syncFromCommand);
      syncFromCommand();

      append(el("details", { className: "options" },
        el("summary", { textContent: "auth & session options" }),
        el("div", { className: "fieldlabel", textContent: "auth method" }), method,
        el("div", { className: "fieldlabel", textContent: "run on connect" }), preset,
        el("div", { className: "fieldlabel", textContent: "session name" }), name,
        el("div", { className: "fieldlabel" }, "command ", cmdHelp.btn), command,
        cmdHelp.body));
      append(notice);

      const submit = () => {
        const u = user.value.trim();
        if (!u) return void (notice.textContent = "a user name is required");
        if (presetById(preset.value) && !validName(nameOr())) {
          return void (notice.textContent =
            "a session name may only use letters, digits, - and _ (up to 32 characters)");
        }
        done({ user: u, method: method.value, command: command.value.trim() });
      };
      user.addEventListener("keydown", (e) => {
        if (e.key === "Enter") submit();
      });
      const go = el("button", { className: "primary", textContent: "connect" });
      const cancel = el("button", { className: "quiet", textContent: "cancel" });
      go.addEventListener("click", submit);
      cancel.addEventListener("click", () => done(null));
      append(el("div", { className: "stack" }, go, cancel));
      setTimeout(() => (user.value ? go : user).focus(), 0);
    });
  }

  /// Camera scan in a sheet. Every way the sheet closes releases the
  /// camera; a decoded link flows into the connect sheet exactly as a
  /// paste would.
  async function scanFlow() {
    const controller = new AbortController();
    const text = await showSheet("scan", ({ append, done }) => {
      append(el("h2", { textContent: "scan the listener's QR" }));
      const host = el("div");
      append(host);
      scanQr(host, { signal: controller.signal }).then(
        (t) => done(t),
        (e) => {
          // Scanning could not start (no https, no camera, permission
          // denied): the sheet stays to say why -- a button that
          // silently does nothing teaches nobody.
          host.replaceChildren(el("p", { textContent: `${e.message ?? e}` }));
        },
      );
    });
    controller.abort();
    if (text) dialWithSheet(connstringFrom(text));
  }

  /// Mid-session actions, in thumb reach: what is running on this host
  /// (the picker), detach, and the way to the home screen.
  async function sessionSheet() {
    const lc = lastConnected;
    if (!lc) return;
    const details = connstringDetails(lc.connstring);
    const entry = details ? loadHistory().find((e) => e.id === details.id && e.user === lc.user) : null;
    const label = entry ? labelOf(entry) : `${details?.id.slice(0, 8) ?? "????????"}…`;
    const m = matchCommand(lc.command ?? "");
    const action = await showSheet("session", ({ append, done }) => {
      // No title: this sheet hangs from under the bar, which is already
      // showing `user@host` and the live link state. Repeating them here
      // in a different font was a second, staler copy of the one thing
      // the bar is for -- and it collided with the close button.
      if (m) {
        append(el("div", { className: "fieldlabel", textContent: `${m.preset.label} sessions on ${label}` }));
        const rowsHost = el("div", { className: "hedge", textContent: "listing sessions…" });
        append(rowsHost);
        // The list is a snapshot of the other side, asked over the
        // probe channel; best-effort, and it says so.
        (async () => {
          const result = await probeSession(m.preset.listCommand);
          if (sheet.dataset.ask !== "session") return; // superseded
          rowsHost.replaceChildren();
          rowsHost.className = "";
          if (!result) {
            rowsHost.append(el("div", { className: "hedge", textContent: "session list unavailable" }));
            return;
          }
          const rows = m.preset.parseList(result.text);
          if (rows.length === 0) {
            rowsHost.append(el("div", { className: "hedge", textContent: "no other sessions listed" }));
          }
          for (const row of rows) {
            const isCurrent = row.name === m.name;
            const bits = [];
            if (isCurrent) bits.push("this session");
            else if (row.attached === true) bits.push("attached elsewhere");
            if (row.at) bits.push(relTime(new Date(row.at).toISOString()));
            const line = el("div", { className: "sessrow" },
              el("span", { className: "name", textContent: row.name }),
              el("span", { className: "meta", textContent: bits.join(" · ") }),
              el("span", { className: "spacer" }));
            if (!isCurrent) {
              const b = el("button", { className: "small", textContent: "attach" });
              b.addEventListener("click", () => done({ kind: "attach", name: row.name }));
              line.append(b);
            }
            rowsHost.append(line);
          }
          if (m.preset.id === "dtach") {
            rowsHost.append(el("div", {
              className: "hedge",
              textContent: "these are the sockets in ~/.wosh: a socket does not say " +
                "whether anyone is attached, or whether the session behind it is still running",
            }));
          }
          const newName = el("input", { type: "text", placeholder: "name" });
          const newBtn = el("button", { className: "small", textContent: "new session" });
          const startNew = () => {
            const n = newName.value.trim();
            if (!validName(n)) {
              newName.setCustomValidity?.("letters, digits, - and _ only");
              return;
            }
            done({ kind: "attach", name: n });
          };
          newBtn.addEventListener("click", startNew);
          newName.addEventListener("keydown", (e) => {
            if (e.key === "Enter") startNew();
          });
          rowsHost.append(el("div", { className: "newrow" }, newName, newBtn));
        })();
      }
      const det = el("button", {
        className: "secondary",
        textContent: m ? `detach — keep it running on ${label}` : "detach",
      });
      det.addEventListener("click", () => done({ kind: "detach" }));
      // Settings, reachable WITHOUT ending or leaving the session --
      // installing this browser's key on the machine you are already
      // logged into is a thing you do from inside a session, not
      // before one.
      const set = el("button", { className: "quiet", textContent: "settings & keys" });
      set.addEventListener("click", () => done({ kind: "settings" }));
      const nc = el("button", { className: "quiet", textContent: "new connection…" });
      nc.addEventListener("click", () => done({ kind: "home" }));
      append(el("div", { className: "stack" }, det, set, nc));
    });
    if (!action) return;
    if (action.kind === "attach") {
      // Switching sessions IS a reconnect: same dial, same pinned host
      // key, a different create-or-attach line; the manager parks the
      // session being left exactly as on any other disconnect.
      doConnect({
        connstring: lc.connstring,
        user: lc.user,
        method: lc.method ?? "auto",
        command: m.preset.command(action.name),
      });
    } else if (action.kind === "detach") {
      politeDetach();
    } else if (action.kind === "settings") {
      prefsReturn = "session";
      showChrome("prefs");
    } else if (action.kind === "home") {
      showChrome("home");
    }
  }

  /// Detach, the polite way first: send the session manager's DEFAULT
  /// detach keys and see whether the session actually parks (the
  /// binding is remappable in all four tools, and a remapped target
  /// just receives junk -- so the hard detach stays as the fallback and
  /// is what makes trying this safe).
  async function politeDetach() {
    const m = matchCommand(lastConnected?.command ?? "");
    if (m) {
      politeDetachAt = Date.now();
      let parked = false;
      try {
        parked = await sendDetachKeys(m.preset.detachKeys, 2000);
      } catch {
        parked = false;
      }
      if (parked) return void idleHome("detached");
      politeDetachAt = 0;
    }
    await detach();
    idleHome("detached");
  }

  // --- connecting -------------------------------------------------------------

  /**
   * Dial. Returns `{ session }` on success, `{ error }` on a thrown
   * failure, `{}` when nothing was dialed (already dialing, or the
   * user rejected the host key -- #home tells that story). One dial at
   * a time; a new dial withdraws whatever ask is on screen.
   */
  async function doConnect({ connstring, user, method = "auto", command = "", quiet = false }) {
    if (dialing) return {};
    dialing = true;
    // A new connect supersedes any pending polite-detach context: the
    // latch exists to translate ONE deliberate detach's ended event.
    politeDetachAt = 0;
    withdrawSheet();
    hideChrome();
    attemptMethod = method;
    attemptUser = user;
    // Test hook (host-test/browser-e2e.mjs leg F): the connstring a
    // dial actually used -- how the gate proves a card dialed a
    // TOKENLESS rebuild rather than the original QR string.
    window.__woshDialed = connstring;
    try {
      // Scrollback restore + persistence key, best-effort: a nicety on
      // top of connecting; nothing here may become a reason a session
      // fails to open. The dump is only PREFETCHED here; app.mjs paints
      // it once the session is actually up.
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

      const session = await onConnect({
        connstring,
        user,
        command: command || undefined,
        ui,
        persistKey: scrollbackKey,
        restore: scrollbackRestore,
      });
      if (!session) {
        // connect() resolved null without throwing: the user rejected
        // the host key. The status line has the story; home mirrors it.
        if (!quiet) idleHome(document.getElementById("status")?.textContent ?? "not connected");
        return {};
      }
      lastConnected = { connstring, user, command: command || undefined, method };
      const details = connstringDetails(connstring);
      // History bookkeeping, only for connects that actually reached a
      // session, and only while the global remember toggle says so.
      // Fields the bump does not own (nickname, detection results,
      // autoResume) are preserved by recordConnection.
      if (details && rememberEnabled()) {
        recordConnection(details.id, details.relay, user, command, method, undefined);
      }
      const entry = details
        ? loadHistory().find((e) => e.id === details.id && e.user === user)
        : null;
      setLive(user, entry ? labelOf(entry) : (details ? `${details.id.slice(0, 8)}…` : "?"));
      hideChrome();
      setHomeNotice("");
      // Ask the target, in the background, which session managers it
      // has; the answer annotates this connection's presets and the
      // trouble sheet's recommendations.
      if (details) detectTools(details.id, user);
      return { session };
    } catch (e) {
      const msg = `${e.message ?? e}`;
      if (!quiet) {
        // "This device is not paired" is the one failure with a
        // concrete remedy the user can carry out (re-pair with what
        // the listener printed), so it gets a sheet instead of a
        // notice nobody can act on. Matched on the CODE only -- see
        // REFUSE_PAIRING. Everything else still funnels through
        // idleHome.
        if (msg.includes(REFUSE_PAIRING)) {
          // Not awaited: this catch still owes its caller a result,
          // and the sheet outlives the dial. `dialing` is cleared by
          // the finally below before any answer can arrive.
          repairFlow(connstring, { user, method, command }, msg);
          return { error: msg, handled: true };
        }
        idleHome(msg);
      }
      return { error: msg };
    } finally {
      dialing = false;
    }
  }

  /// The re-pair sheet: this listener no longer recognises this
  /// browser (it ran with --no-token, or its enrollment was wiped), so
  /// the saved card's tokenless connstring can never be accepted
  /// again. Everything needed to fix it is printed by the listener at
  /// startup.
  ///
  /// The token field comes FIRST: the card already knows the endpoint
  /// and the relay, so a bare token is the smallest thing that can
  /// recover this connection -- and unlike a QR it can be read out
  /// over a call or pasted from a chat. Scanning again is the
  /// secondary way round.
  ///
  /// Resolves nothing; on a successful re-pair it dials exactly as any
  /// other dial does, so the listener enrols this device and the saved
  /// card works unaided afterwards.
  async function repairFlow(connstring, params, error) {
    const details = connstringDetails(connstring);
    const redial = await showSheet("repair", ({ append, done }) => {
      const wrap = el("div", { className: "confirm" });
      wrap.append(
        el("h2", { textContent: "this machine no longer recognises this browser" }),
        el("p", {
          textContent: "saved connections carry no token — they rely on this browser " +
            "having been paired. that pairing is gone (the listener was started " +
            "without a token, or its data was wiped), so it has to be done once more.",
        }),
        el("div", {
          className: "hedge",
          textContent: "the listener prints what is needed when it starts: a wosh link, " +
            "and the line “pairing token required: …”. either one works below.",
        }),
      );
      if (details) {
        wrap.append(el("div", {
          className: "target",
          textContent: `${details.id.slice(0, 16)}… via ${details.relay}`,
        }));
      }
      const notice = el("div", { className: "notice", textContent: "" });
      wrap.append(
        el("div", { className: "fieldlabel", textContent: "pairing token, or the whole link" }),
      );
      const field = el("input", { type: "text", placeholder: "pairing token or wosh link" });
      // The token is printed in uppercase, and the alphabet's one trap
      // is that lowercase `l` means `I` while uppercase `L` is its own
      // symbol -- so ask the keyboard for the form that was printed.
      field.setAttribute("autocapitalize", "characters");
      field.setAttribute("autocorrect", "off");
      field.setAttribute("spellcheck", "false");
      wrap.append(field, notice);

      const submit = () => {
        const raw = field.value;
        // A link (or a pasted connstring) is self-contained: use it
        // verbatim, endpoint and relay included -- it may well be a
        // different listener, and that is the user's call to make.
        const asLink = connstringFrom(raw);
        if (asLink && connstringDetails(asLink)) return done(asLink);
        // Otherwise: a bare pairing token, in the encoding the listener
        // prints (see decodeToken -- it forgives case, separators and
        // the classic misreadings).
        const token = decodeToken(raw);
        if (token && details) {
          return done(tokenedConnstring(details.id, details.relay, token));
        }
        notice.textContent = details
          ? "that is neither a wosh link nor a pairing token (26 characters, as the listener prints it)"
          : "this connection has no saved endpoint to attach a token to — paste the whole link";
      };
      const go = el("button", { className: "primary", textContent: "re-pair and connect" });
      go.addEventListener("click", submit);
      const scan = el("button", { className: "quiet", textContent: "scan the QR again" });
      scan.addEventListener("click", () => done("scan"));
      wrap.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && e.target === field) submit();
      });
      wrap.append(el("div", { className: "stack" }, go, scan));
      append(wrap);
      setTimeout(() => field.focus(), 0);
    });
    if (!redial) return idleHome(error); // dismissed: home tells the story
    if (redial === "scan") return scanFlow();
    const outcome = await doConnect({ connstring: redial, ...params });
    if (outcome.error && !outcome.handled) {
      dialWithSheet(redial, params, outcome.error);
    }
  }

  /// The sheet-driven dial loop: connect form -> dial -> on failure the
  /// form returns with the error and the previous answers.
  async function dialWithSheet(connstring, prefill, error) {
    let params = await connectSheet({ connstring, prefill, error });
    while (params) {
      const outcome = await doConnect({ connstring, ...params });
      if (outcome.session) return outcome.session;
      if (outcome.handled) return null; // the re-pair sheet owns the retry now
      if (!outcome.error) return null; // rejected host key or cancelled: home has the story
      params = await connectSheet({ connstring, error: outcome.error, prefill: params });
    }
    return null;
  }

  /// A card tap: dial with the card's remembered parameters, no form.
  /// On failure the connect sheet opens WITH the error -- that is the
  /// retry surface.
  async function dialFromEntry(entry, { command } = {}) {
    const cs = tokenlessConnstring(entry.id, entry.relay);
    const cmd = command !== undefined ? command : (entry.command ?? "");
    const method = entry.method ?? "auto";
    const outcome = await doConnect({ connstring: cs, user: entry.user, method, command: cmd });
    if (outcome.error && !outcome.handled) {
      dialWithSheet(cs, { user: entry.user, method, command: cmd }, outcome.error);
    }
  }

  /**
   * Ask the target, once per connect, which session managers it
   * actually has, and remember the answer against this connection.
   * Fire-and-forget: nothing the user asked for waits on it.
   */
  function detectTools(id, user) {
    probeSession(detectCommand).then((r) => {
      if (!r) return;
      // Only patches an entry that already exists -- an unremembered
      // connection is not resurrected by an observation about it.
      updateConnection(id, user, { tools: parseDetect(r.text), toolsAt: Date.now() });
    }).catch(() => {
      // A probe is a question; an unanswered one costs the annotation
      // and nothing else.
    });
  }

  /**
   * Attempt a silent, same-parameters reconnect after a session was
   * lost (terminal.wit's `close-kind` -- `lost` is the one kind the
   * WIT enum exists to mark as reasonable to retry automatically).
   */
  async function autoReconnect(why) {
    if (!lastConnected) return false;
    // password / keyboard-interactive need a human to type something;
    // those fall through to the home screen like any other end.
    if (!["auto", "publickey", "passkey"].includes(lastConnected.method ?? "auto")) return false;
    // An unpinned host key would need the TOFU ask; only reconnect
    // silently onto a key this browser has already pinned.
    const id = endpointIdOf(lastConnected.connstring);
    if (!id || !loadPins()[id]?.fp) return false;
    // With an on-connect command the reconnect REATTACHES (the shell
    // and its work are on the target), so the rate limit is only a
    // battery guard and can be short. Without one every automatic
    // reconnect is a NEW shell, and the minute stands.
    const command = lastConnected.command;
    if (Date.now() - lastAutoAt < (command ? 15_000 : 60_000)) return false;
    lastAutoAt = Date.now();
    // EXACT copy on the no-command path: host-test/browser-fallthrough
    // greps the scrollback for "starting a new session".
    note(command ? `${why} — reattaching…` : `${why} — starting a new session…`);
    const outcome = await doConnect({
      connstring: lastConnected.connstring,
      user: lastConnected.user,
      method: lastConnected.method ?? "auto",
      command: command ?? "",
      quiet: true,
    });
    return !!outcome.session;
  }

  /// The two things that can be said about an `ended` session that ran
  /// a command, rendered as offers rather than actions: `ended` is a
  /// deliberate act on the other side, so redialing automatically would
  /// fight the human who just left.
  async function commandSessionEnded({ why, code, uptimeMs }) {
    const lc = lastConnected;
    const command = lc.command;
    // The program 127 is about is almost never the FIRST word of the
    // command: the presets open with `mkdir -p … && exec dtach …`, and
    // "command not found" is the shell failing on the program it was
    // finally asked to run.
    const lastSegment = command.split(/&&|\|\||;/).pop() ?? "";
    const tool =
      lastSegment
        .trim()
        .split(/\s+/)
        .filter((w) => w !== "exec" && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(w))[0] ??
      command.trim().split(/\s+/)[0];
    const details = connstringDetails(lc.connstring);
    const entry = details
      ? loadHistory().find((en) => en.id === details.id && en.user === lc.user)
      : null;
    idleHome(why);

    const redial = (cmd) =>
      doConnect({ connstring: lc.connstring, user: lc.user, method: lc.method ?? "auto", command: cmd });

    if (code === 127 && uptimeMs < 5000) {
      // 127 within seconds of starting is the shell saying "command
      // not found" and nothing else happening: the session manager is
      // simply not on the target. When a previous connect managed to
      // ASK the host what it has (detectTools), the offer can be
      // specific; without data nothing is claimed.
      const alternatives = entry?.tools
        ? PRESETS.filter((p) => p.id !== tool && entry.tools[p.id] === true)
        : [];
      const action = await showSheet("trouble", ({ append, done }) => {
        append(el("h2", { textContent: `\`${tool}\` isn't on that machine` }));
        append(el("p", {
          textContent: 'the command exited 127 right away — the shell saying "command not ' +
            'found". install it there (the dtach, abduco, tmux and screen packages are ' +
            "named after the tools), or:",
        }));
        const stack = el("div", { className: "stack" });
        for (const p of alternatives) {
          const b = el("button", { className: "primary", textContent: `use ${p.label} instead` });
          b.addEventListener("click", () => done({ kind: "swap", preset: p }));
          stack.append(b);
        }
        const once = el("button", { className: "secondary", textContent: "connect with a plain shell" });
        once.addEventListener("click", () => done({ kind: "once" }));
        const always = el("button", { className: "quiet", textContent: "always use a plain shell here" });
        always.addEventListener("click", () => done({ kind: "always" }));
        stack.append(once, always);
        append(stack);
      });
      if (!action) return;
      if (action.kind === "swap") {
        // The name the user was already working with, so a swap of
        // TOOL is not also a silent rename of the session.
        const name = matchCommand(command)?.name ?? "main";
        redial(action.preset.command(validName(name) ? name : "main"));
      } else if (action.kind === "once") {
        redial("");
      } else {
        if (details) clearStoredCommand(details.id, lc.user);
        redial("");
      }
      return;
    }

    // Anything else: the command is gone from THIS connection, but a
    // session manager it started is very likely still running on the
    // target. Truthful hedge ("may"): a plain `exit` inside the manager
    // ends it for good, and this side cannot tell the two apart.
    const again = await showSheet("ended", ({ append, done }) => {
      append(el("h2", { textContent: "session ended or detached" }));
      append(el("p", {
        textContent: "the session manager may still be running on the target — " +
          "reattaching lands back in it.",
      }));
      const re = el("button", { className: "primary", textContent: "reattach" });
      re.addEventListener("click", () => done(true));
      const back = el("button", { className: "quiet", textContent: "back to connections" });
      back.addEventListener("click", () => done(false));
      append(el("div", { className: "stack" }, re, back));
    });
    if (again) redial(command);
  }

  // The session is gone: route by HOW (terminal.wit's close-kind,
  // carried on the event so nothing parses reason strings).
  window.addEventListener("wosh:session-ended", async (e) => {
    const { why, kind, code, uptimeMs } = e.detail ?? {};
    // A detach the user just performed, arriving as the session end it
    // is: already told, already handled.
    if (Date.now() - politeDetachAt < 10_000) {
      politeDetachAt = 0;
      return void idleHome("detached");
    }
    if (kind === "lost") {
      try {
        if (await autoReconnect(why ?? "connection lost")) return;
      } catch {
        // fall through to the home screen
      }
      return void idleHome(why);
    }
    // Only when this page actually asked for a command: without one
    // there is nothing to reattach to and nothing 127 could be about.
    if (kind === "ended" && lastConnected?.command) {
      return void commandSessionEnded({ why: why ?? "session ended", code, uptimeMs });
    }
    idleHome(why);
  });

  // --- the ui contract app.mjs drives ----------------------------------------

  // The user of the attempt in flight, for the host-key ask's copy.
  let attemptUser = "";

  const ui = {
    confirmHostKey(fingerprint, connstring) {
      const endpointId = endpointIdOf(connstringFrom(connstring ?? ""));
      const pinned = endpointId ? loadPins()[endpointId] : undefined;
      // The pinning payoff: this listener presented exactly the
      // fingerprint the user approved-and-saved before. Note it and
      // proceed without a prompt.
      if (pinned && pinned.fp === fingerprint) {
        setHomeNotice(
          `host key matches the approval saved in this browser on ${String(pinned.at).slice(0, 10)}`,
        );
        return Promise.resolve(true);
      }
      const target = `${attemptUser || "?"}@${endpointId ? `${endpointId.slice(0, 8)}…` : "this machine"}`;
      return hostKeyAsk(fingerprint, { pinned, target }).then((r) => {
        if (!r?.ok) return false;
        if (endpointId && r.remember) savePin(endpointId, fingerprint);
        return true;
      });
    },
    getCredential() {
      // No password here: the password method collects it through
      // `collectPrompts` at the moment auth runs, in the same sheet
      // keyboard-interactive uses, never parked in a long-lived input.
      return { kind: attemptMethod || "auto" };
    },
    collectPrompts(batch) {
      return promptsAsk(batch);
    },
  };

  // --- wiring ------------------------------------------------------------------

  sessionsBtn.addEventListener("click", () => {
    if (document.body.classList.contains("live")) sessionSheet();
    else showChrome("home");
  });

  // Method support depends on the loaded component; ask it rather than
  // assume. Probing also forces the component to load, so the connect
  // sheet reflects reality before the user commits to anything.
  (async () => {
    try {
      caps = await capabilities();
      // Screens rendered before the probe answered were built against
      // caps === null (the passkey card hidden, every method offered):
      // re-render whichever is showing so the answer lands.
      if (prefsEl.classList.contains("on")) renderPrefs();
      if (connectionEl.classList.contains("on")) renderConnection();
    } catch (e) {
      setHomeNotice(`could not load the client component: ${e.message ?? e}`);
    }
  })();

  // Boot: home first. A fragment link is a deliberate destination and
  // goes straight to its connect sheet (and wins over auto-resume,
  // which renderHome only arms when there is no fragment).
  showChrome("home");
  const frag = connstringFromLocation();
  if (frag) dialWithSheet(frag);

  return { connect: doConnect, ui };
}

