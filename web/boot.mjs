// Bootstrap panel (M5, workstream D): connection-string entry (URL
// fragment or manual), explicit save offers, saved-proxy list, and the
// client identity line. The terminal below stays on the M2 dev bridge
// when one is present; the in-browser iroh leg is blocked upstream
// (A3: polymorph-iroh#10 / lann/jco#11) and this panel says so rather
// than faking it.

import { parseConnstring, connstringFromFragment } from "/connstring.mjs";
import * as store from "/storage.mjs";
import { openKeyStore, ensureIdentity } from "/idb-keys.mjs";

const A3_MESSAGE =
  "in-browser iroh is pending upstream jco async-scheduler hardening " +
  "(polymorph-iroh#10, lann/jco#11); native path: just m4";

export async function initBoot(panel, storage = localStorage) {
  let state = store.load(storage);
  let pending = null; // parsed-but-unsaved proxy details
  let notice = "";

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
      list.append(
        el(
          "div",
          { class: "boot-proxy", "data-id": p.endpointIdHex },
          `${p.name} (${p.endpointIdHex.slice(0, 8)}… via ${p.relayUrl}) `,
          el(
            "button",
            {
              class: "connect-btn",
              onclick: () => {
                notice = A3_MESSAGE;
                render();
              },
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
  // pasted link): parse it and offer the save.
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
    render,
  };
}
