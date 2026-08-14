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
} from "./app.mjs";
import { scanQr } from "./qr.mjs";

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

/** MRU list of `{ id, relay, user, at }`; [] when unavailable. */
function loadHistory() {
  try {
    const h = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
    return Array.isArray(h) ? h : [];
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

/** Insert-or-bump, deduped by (endpoint id, user). */
function recordConnection(id, relay, user) {
  const rest = loadHistory().filter((e) => !(e.id === id && e.user === user));
  saveHistory([{ id, relay, user, at: new Date().toISOString() }, ...rest]);
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
  const scanBtn = el("button", {
    className: "scan",
    textContent: "scan QR",
    title: "scan the listener's QR code with this device's camera",
  });
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
  const closeBtn = el("button", { textContent: "×", title: "close" });

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
  const enrollBtn = el("button", { textContent: "enrol a passkey" });
  const forgetBtn = el("button", { textContent: "forget" });
  const adoptInput = el("input", {
    size: 40,
    placeholder: "paste the authorized_keys line from another device",
  });
  const adoptBtn = el("button", { textContent: "adopt" });
  const recoverBtn = el("button", { textContent: "recover from this passkey" });

  // Connection history: tap to reconnect. Rendered only when there is
  // something to show; the whole section disappears otherwise.
  const historySection = el("div", { className: "history" });
  const rememberConn = el("input", {
    type: "checkbox",
    id: "remember-connection",
    checked: true,
  });

  // The always-visible bar (index.html): session controls live there,
  // not in the dialog, so they work while the dialog is closed.
  const detachBtn = document.getElementById("detach-btn");
  const settingsBtn = document.getElementById("settings-btn");

  panel.append(
    el("div", { className: "title" }, el("span", { textContent: "wosh" }), closeBtn),
    historySection,
    el("div", { className: "field", textContent: "connection string" }),
    scanRow,
    scanHost,
    el("div", { className: "row" },
      el("label", { textContent: "user" }), userInput, method),
    el("div", { className: "row" }, connectBtn, showKeyBtn),
    el("div", { className: "row remember" },
      rememberConn,
      el("label", {
        htmlFor: "remember-connection",
        textContent: " remember this connection",
      }),
      el("span", {
        className: "hint",
        textContent: "(the pairing token is never saved)",
      })),
    keyRow,
    passkeySection,
    notice,
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
      row.append(
        el("div", { textContent: `${entry.user}@${entry.id.slice(0, 8)}…` }),
        el("div", { className: "sub", textContent: sub.join(" · ") }),
      );
      row.addEventListener("click", () => {
        csInput.value = tokenlessConnstring(entry.id, entry.relay);
        userInput.value = entry.user;
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
  window.addEventListener("wosh:session-ended", (e) => sessionOver(e.detail?.why));

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
      passkeySection.append(
        el("div", {
          textContent:
            "enrolled -- add this line to ~/.ssh/authorized_keys on the target host:",
        }),
        el("code", { textContent: line }),
        el("div", {
          className: "sub",
          textContent:
            "Nothing else is installed on the target. OpenSSH 10.3 and later accept " +
            "this as-is; on 8.4 through 10.2 the server also needs " +
            "PubkeyAcceptedAlgorithms +webauthn-sk-ecdsa-sha2-nistp256@openssh.com " +
            "in sshd_config, or it refuses the key before ever checking a signature.",
        }),
        el("div", { className: "row" }, forgetBtn),
      );
    } else {
      passkeySection.append(
        el("div", {
          className: "sub",
          textContent:
            "no passkey enrolled -- enrolling asks your platform authenticator to create one, " +
            "then prints an ordinary authorized_keys line to install on the target",
        }),
        el("div", { className: "row" }, enrollBtn),
        el("div", { className: "row" }, adoptInput, adoptBtn),
        el("div", {
          className: "sub",
          textContent: "adopting brings in a passkey already enrolled on another device, from the line it printed there",
        }),
        el("div", { className: "row" }, recoverBtn),
        el("div", {
          className: "sub",
          textContent:
            "recovering needs nothing else -- not the authorized_keys line, not the target, not " +
            "another device -- but asks for TWO touches of the SAME passkey to work its public " +
            "key back out. Prefer adopt when the line is to hand: one touch, and no chance of " +
            "picking the wrong passkey partway through.",
        }),
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
    new Promise((resolve) => {
      withdrawCeremony();
      const row = el("div", { className: "confirm" });
      const btn = el("button", { textContent: "touch your passkey to sign in" });
      row.append(el("div", { textContent: "the server is asking for your passkey:" }), btn);
      panel.append(row);
      pendingCeremony = row;
      btn.addEventListener("click", () => {
        withdrawCeremony();
        resolve();
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
        panel.append(row);
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
        panel.append(row);
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

  const doConnect = async () => {
    notice.textContent = "";
    // A pasted QR link becomes its fragment here, and the field is
    // rewritten to match: what the user sees is what gets dialed (and
    // what the host-key prompt keys its pin on).
    const connstring = connstringFrom(csInput.value);
    if (connstring !== csInput.value) csInput.value = connstring;
    const user = userInput.value.trim();
    if (!connstring) return void (notice.textContent = "a connection string is required");
    if (!user) return void (notice.textContent = "a user name is required");
    connectBtn.disabled = true;
    try {
      const session = await onConnect({ connstring, user, ui });
      if (session) {
        // History bookkeeping, only for connects that actually reached
        // a session: failed dials and rejected host keys are not
        // "connections". Checked (the default) records or bumps the
        // entry; unchecked records nothing and touches nothing --
        // forgetting is the history rows' own, confirmed, affordance.
        const details = connstringDetails(connstring);
        if (details && rememberConn.checked) {
          recordConnection(details.id, details.relay, user);
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
    } catch (e) {
      notice.textContent = `${e.message ?? e}`;
    } finally {
      connectBtn.disabled = false;
      // An attempt that died mid-ceremony leaves nothing to tap: the
      // signature it was asking for belongs to a session that is gone.
      withdrawCeremony();
    }
  };

  connectBtn.addEventListener("click", doConnect);
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

  return { connect: doConnect, ui };
}
