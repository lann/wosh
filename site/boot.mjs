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

import { identity, detach, capabilities } from "./app.mjs";
import { scanQr, scanSupported } from "./qr.mjs";

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
 * lib.rs: version byte, then 32 raw pubkey bytes -- v2 keeps the
 * pubkey as the FIRST postcard field precisely so this prefix never
 * moves), and refuses versions it doesn't know, so a format change
 * degrades to "no pinning" -- more prompting, never less.
 */
export function endpointIdOf(connstring) {
  try {
    const bin = atob(connstring.trim().replace(/-/g, "+").replace(/_/g, "/"));
    const version = bin.charCodeAt(0);
    if (bin.length < 34 || (version !== 1 && version !== 2)) return null;
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
  // camera performs. Hidden where there is no camera API at all
  // (insecure context, or a browser without getUserMedia) rather than
  // offered and then failing.
  const scanBtn = el("button", {
    className: "scan",
    textContent: "scan QR",
    title: "scan the listener's QR code with this device's camera",
    hidden: !scanSupported(),
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
    el("option", { value: "password", textContent: "password" }),
    el("option", { value: "keyboard-interactive", textContent: "keyboard-interactive (OTP/2FA)" }),
  );

  const connectBtn = el("button", { textContent: "connect" });
  const showKeyBtn = el("button", { textContent: "show this browser's public key" });
  const closeBtn = el("button", { textContent: "×", title: "close" });

  // The always-visible bar (index.html): session controls live there,
  // not in the dialog, so they work while the dialog is closed.
  const detachBtn = document.getElementById("detach-btn");
  const settingsBtn = document.getElementById("settings-btn");

  panel.append(
    el("div", { className: "title" }, el("span", { textContent: "wosh" }), closeBtn),
    el("div", { className: "field", textContent: "connection string" }),
    scanRow,
    scanHost,
    el("div", { className: "row" },
      el("label", { textContent: "user" }), userInput, method),
    el("div", { className: "row" }, connectBtn, showKeyBtn),
    keyRow,
    notice,
  );

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

  openPanel();

  return { connect: doConnect, ui };
}
