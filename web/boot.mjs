// Bootstrap panel (M5, workstream D): connection-string entry (URL
// fragment or manual), explicit save offers, saved-proxy list, the
// client identity line — and the connect action itself: parsed
// connection strings carry a pairing token and connect directly; saved
// proxies (tokens are deliberately not persisted) ask for a token at
// connect time. The session runs in the terminal below (app.mjs
// connectIroh: the composed client over real iroh, hosted by deltic).
//
// M6: a live session can be made persistent ("persist session":
// passkey registration + PRF-wrapped escrow, app.mjs persistCurrent),
// and a saved proxy with a recorded session offers "reattach"
// (assertion-gated, same token rules — app.mjs reattachIroh).
//
// M7: "ssh" connects through the deprivileged proxy path — end-to-end
// ssh auth through the forwarded stream (app.mjs connectSshIroh). The
// host-key pin is TOFU: first success stores the fingerprint on the
// proxy record; later connects pass it as expected-host-key, so a
// mismatch fails before the password is ever sent.

import { parseConnstring, connstringFromFragment } from "./connstring.mjs";
import * as store from "./storage.mjs";
import { openKeyStore, ensureIdentity } from "./idb-keys.mjs";

export async function initBoot(
  panel,
  storage = localStorage,
  { onConnect, onPersist, onReattach, onConnectSsh } = {},
) {
  let state = store.load(storage);
  let pending = null; // parsed-but-unsaved proxy details
  let notice = "";
  let connecting = false;
  let connected = null; // { relayUrl, endpointIdHex } of the live session
  // The last successful iroh connect/reattach of THIS TAB, token
  // included (issue #12): pairing tokens are deliberately never
  // persisted, but retaining the one in hand for the tab's lifetime is
  // what makes a transport drop recoverable in one gesture instead of
  // a re-pairing ceremony — mobile's common case, not its edge. ssh
  // credentials are NOT retained: an ssh reconnect is a full re-auth
  // through the panel, by design (the TOFU pin does its work there).
  let lastConnect = null;

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
      connected = { relayUrl, endpointIdHex };
      lastConnect = { relayUrl, endpointIdHex, token };
      notice = "";
    } catch (e) {
      notice = `connect failed: ${e.message ?? e}`;
    } finally {
      connecting = false;
      render();
    }
  };

  // Make the live session persistent (M6): ceremony in app.mjs; the
  // proxy entry is saved implicitly (a persistent session without its
  // proxy row would be unreachable after reload).
  const persist = async () => {
    if (connecting || !connected || !onPersist) return;
    connecting = true;
    notice = "persisting session (passkey ceremony)…";
    render();
    try {
      const { escrow, sessionId } = await onPersist();
      const { state: withProxy } = store.upsertProxy(state, connected);
      state = store.recordSession(withProxy, {
        proxyId: connected.endpointIdHex,
        sessionId,
        key: escrow,
      });
      store.save(storage, state);
      notice = `session ${sessionId} persistent (passkey-gated reattach)`;
    } catch (e) {
      notice = `persist failed: ${e.message ?? e}`;
    } finally {
      connecting = false;
      render();
    }
  };

  // Assertion-gated reattach to a recorded session; the fresh escrow
  // (re-sealed at a jumped floor) replaces the stored arm.
  const reattach = async (proxy, session, token) => {
    if (connecting || !onReattach) return;
    if (!token) {
      notice = "pairing token required (tokens are not persisted — get one from the proxy)";
      render();
      return;
    }
    connecting = true;
    notice = `reattaching session ${session.sessionId}…`;
    render();
    try {
      const { escrow } = await onReattach({
        relayUrl: proxy.relayUrl,
        endpointIdHex: proxy.endpointIdHex,
        token,
        sessionId: session.sessionId,
      });
      connected = { relayUrl: proxy.relayUrl, endpointIdHex: proxy.endpointIdHex };
      lastConnect = { relayUrl: proxy.relayUrl, endpointIdHex: proxy.endpointIdHex, token };
      state = store.recordSession(state, {
        proxyId: proxy.endpointIdHex,
        sessionId: session.sessionId,
        key: escrow,
      });
      store.save(storage, state);
      notice = "";
    } catch (e) {
      notice = `reattach failed: ${e.message ?? e}`;
    } finally {
      connecting = false;
      render();
    }
  };

  // One-gesture retry of the last connect/reattach (issue #12); called
  // by app.mjs's disconnected-state key/tap handler (that gesture also
  // satisfies WebAuthn user activation for the reattach arm). Prefers
  // the assertion-gated reattach when this proxy has a persistent
  // session — same session, screen resynced; otherwise a fresh connect
  // (v0: non-persistent sessions die with their connection, so this is
  // a NEW session on a live proxy). Success ⇔ `connected` set again.
  const reconnect = async () => {
    if (connecting) return false;
    if (!lastConnect) {
      notice = "no previous connection to retry — connect from the panel";
      render();
      return false;
    }
    const { relayUrl, endpointIdHex, token } = lastConnect;
    connected = null;
    const session = state.sessions.find(
      (s) => s.proxyId === endpointIdHex && s.sessionId != null && s.key.prf,
    );
    if (session && onReattach) {
      await reattach({ relayUrl, endpointIdHex }, session, token);
    } else {
      await connect({ relayUrl, endpointIdHex, token });
    }
    return connected != null;
  };

  // Inner-ssh connect (M7). On success the proxy is saved and the
  // observed host key pinned — the pin is what makes the NEXT connect
  // refuse an impostor before sending the password.
  const connectSsh = async ({ relayUrl, endpointIdHex }, { token, user, password, command }) => {
    if (connecting || !onConnectSsh) return;
    if (!token || !user || !password) {
      notice = "ssh needs pairing token, user, and password";
      render();
      return;
    }
    const pinned = state.proxies.find((p) => p.endpointIdHex === endpointIdHex)?.sshHostKey;
    connecting = true;
    notice = `ssh-connecting to ${endpointIdHex.slice(0, 8)}…`;
    render();
    try {
      const { hostKey } = await onConnectSsh({
        relayUrl,
        endpointIdHex,
        token,
        user,
        password,
        expectedHostKey: pinned ?? undefined,
        command: command || undefined,
      });
      connected = { relayUrl, endpointIdHex };
      const { state: withProxy } = store.upsertProxy(state, { endpointIdHex, relayUrl });
      state = store.pinHostKey(withProxy, endpointIdHex, hostKey);
      store.save(storage, state);
      notice = pinned ? "" : `ssh host key pinned (TOFU first contact): ${hostKey}`;
    } catch (e) {
      notice = `connect failed: ${e.message ?? e}`;
    } finally {
      connecting = false;
      render();
    }
  };

  const render = () => {
    panel.replaceChildren();
    // The ssh input cluster (M7), shared by the pending row and saved
    // rows; `tokenFn` defers to whichever token source the row has.
    const sshCluster = (proxyish, tokenFn) => {
      if (!onConnectSsh) return null;
      const user = el("input", { class: "ssh-user", placeholder: "user", size: "8" });
      const pass = el("input", {
        class: "ssh-pass",
        placeholder: "password",
        type: "password",
        size: "10",
      });
      const cmd = el("input", {
        class: "ssh-cmd",
        placeholder: "command (default: mosh-server …)",
        size: "24",
      });
      const btn = el(
        "button",
        {
          class: "ssh-btn",
          onclick: () =>
            connectSsh(proxyish, {
              token: tokenFn(),
              user: user.value.trim(),
              password: pass.value,
              command: cmd.value.trim(),
            }),
        },
        "ssh",
      );
      return el("span", { class: "boot-ssh" }, " · ssh: ", user, " ", pass, " ", cmd, " ", btn);
    };
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
      const row = el(
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
      );
      const ssh = sshCluster(
        { relayUrl: pending.relayUrl, endpointIdHex: pending.endpointIdHex },
        () => pending.token,
      );
      if (ssh) row.append(ssh);
      panel.append(row);
    }

    if (connected && onPersist) {
      panel.append(
        el(
          "div",
          { class: "boot-session" },
          `live session on ${connected.endpointIdHex.slice(0, 8)}… — `,
          el("button", { id: "persist-btn", onclick: persist }, "persist session"),
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
      // Reattach rides the prf arm only (plain-arm records are test
      // fixtures) and needs the proxy-assigned session id.
      const session = state.sessions.find(
        (s) => s.proxyId === p.endpointIdHex && s.sessionId != null && s.key.prf,
      );
      const row = el(
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
      );
      if (session && onReattach) {
        row.append(
          " ",
          el(
            "button",
            {
              class: "reattach-btn",
              onclick: () => reattach(p, session, tokenInput.value.trim()),
            },
            `reattach #${session.sessionId}`,
          ),
        );
      }
      const ssh = sshCluster(
        { relayUrl: p.relayUrl, endpointIdHex: p.endpointIdHex },
        () => tokenInput.value.trim(),
      );
      if (ssh) row.append(ssh);
      row.append(
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
      );
      list.append(row);
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
    get connected() {
      return connected;
    },
    identityAvailable: !!identity,
    identityError,
    tryParse,
    saveOffer,
    connect,
    connectSsh,
    persist,
    reattach,
    reconnect,
    render,
  };
}
