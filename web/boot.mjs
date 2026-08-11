// Bootstrap panel (M5, workstream D): connection-string entry (URL
// fragment or manual), explicit save offers, saved-proxy list, the
// client identity line — and the connect action itself: parsed
// connection strings carry a pairing token and connect directly; saved
// proxies (tokens are deliberately not persisted) ask for a token at
// connect time. The session runs in the terminal below (app.mjs
// connectIroh: the composed client over real iroh, hosted by deltic).

import { parseConnstring, connstringFromFragment } from "./connstring.mjs";
import * as store from "./storage.mjs";
import { openKeyStore, ensureIdentity } from "./idb-keys.mjs";

export async function initBoot(panel, storage = localStorage, { onConnect } = {}) {
  let state = store.load(storage);
  let pending = null; // parsed-but-unsaved proxy details
  let notice = "";
  let connecting = false;

  const keyStore = await openKeyStore();
  let identity = null;
  let identityError = null;
  try {
    const { keyPair, created } = await ensureIdentity(keyStore);
    identity = keyPair;
    if (created || !state.identityRef) {
      state = store.setIdentityRef(state, { kind: "idb", name: "identity-ed25519" });
      store.save(storage, state);
    }
  } catch (e) {
    identityError = e.message ?? String(e);
  }

  const el = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "onclick") node.onclick = v;
      else node.setAttribute(k, v);
    }
    node.append(...children);
    return node;
  };

  const tryParse = (raw) => {
    notice = "";
    pending = null;
    const cs = connstringFromFragment(raw);
    if (!cs) {
      notice = "no connection string found";
    } else {
      try {
        pending = parseConnstring(cs);
      } catch (e) {
        notice = e.message;
      }
    }
    render();
  };

  const saveOffer = () => {
    if (!pending) return;
    const { state: next } = store.upsertProxy(state, {
      endpointIdHex: pending.endpointIdHex,
      relayUrl: pending.relayUrl,
    });
    state = next;
    store.save(storage, state);
    notice = `saved proxy ${pending.endpointIdHex.slice(0, 8)}…`;
    pending = null;
    render();
  };

  // Connect through app.mjs (iroh mode). One at a time; failures land
  // in the notice line, user-legible.
  const connect = async ({ relayUrl, endpointIdHex, token }) => {
    if (connecting) return;
    if (!token) {
      notice = "pairing token required (tokens are not persisted — get one from the proxy)";
      render();
      return;
    }
    if (!onConnect) {
      notice = "connect is not wired on this page";
      render();
      return;
    }
    connecting = true;
    notice = `connecting to ${endpointIdHex.slice(0, 8)}…`;
    render();
    try {
      await onConnect({ relayUrl, endpointIdHex, token });
      notice = "";
    } catch (e) {
      notice = `connect failed: ${e.message ?? e}`;
    } finally {
      connecting = false;
      render();
    }
  };

  const render = () => {
    panel.replaceChildren();
    const idLine = identityError
      ? `identity: unavailable (${identityError})`
      : identity
        ? "identity: Ed25519 (non-extractable, IndexedDB)"
        : "identity: …";
    panel.append(el("div", { class: "boot-id" }, idLine));

    const input = el("input", {
      id: "connstring-input",
      placeholder: "paste connection string or #fragment URL",
      size: "60",
    });
    panel.append(
      el(
        "div",
        { class: "boot-entry" },
        input,
        el("button", { id: "parse-btn", onclick: () => tryParse(input.value) }, "add"),
      ),
    );

    if (pending) {
      panel.append(
        el(
          "div",
          { class: "boot-pending" },
          `proxy ${pending.endpointIdHex.slice(0, 16)}… via ${pending.relayUrl} — `,
          el(
            "button",
            { id: "connect-pending-btn", onclick: () => connect(pending) },
            "connect",
          ),
          " ",
          el("button", { id: "save-btn", onclick: saveOffer }, "save"),
          " ",
          el(
            "button",
            {
              onclick: () => {
                pending = null;
                render();
              },
            },
            "discard",
          ),
        ),
      );
    }

    const list = el("div", { class: "boot-proxies" });
    for (const p of state.proxies) {
      const tokenInput = el("input", {
        class: "token-input",
        placeholder: "pairing token",
        size: "14",
      });
      list.append(
        el(
          "div",
          { class: "boot-proxy", "data-id": p.endpointIdHex },
          `${p.name} (${p.endpointIdHex.slice(0, 8)}… via ${p.relayUrl}) `,
          tokenInput,
          " ",
          el(
            "button",
            {
              class: "connect-btn",
              onclick: () =>
                connect({
                  relayUrl: p.relayUrl,
                  endpointIdHex: p.endpointIdHex,
                  token: tokenInput.value.trim(),
                }),
            },
            "connect",
          ),
          " ",
          el(
            "button",
            {
              class: "forget-btn",
              onclick: () => {
                state = store.removeProxy(state, p.endpointIdHex);
                store.save(storage, state);
                render();
              },
            },
            "forget",
          ),
        ),
      );
    }
    panel.append(list);
    if (notice) panel.append(el("div", { class: "boot-notice" }, notice));
  };

  // A fragment in the page URL is a bootstrap request (QR scan or
  // pasted link): parse it and offer connect/save.
  if (location.hash.length > 1) tryParse(location.hash);
  render();

  // Test hook (headless assertions drive the same paths the UI does).
  return {
    get state() {
      return state;
    },
    get pending() {
      return pending;
    },
    get notice() {
      return notice;
    },
    identityAvailable: !!identity,
    identityError,
    tryParse,
    saveOffer,
    connect,
    render,
  };
}
