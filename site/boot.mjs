// The connect panel: read the connection string, collect a user name,
// show the host key for confirmation, and offer a credential.
//
// Deliberately stateless ITSELF: this panel writes nothing to storage.
// The one durable thing -- the browser's SSH identity -- lives behind
// the component's `identity-store` import (site/identity-store.ts): a
// non-extractable WebCrypto pair in IndexedDB, so the key line shown
// here keeps working across visits. main's equivalent carried saved
// proxies, passkey registration, PRF-wrapped key escrow and its own
// IndexedDB identity -- none of which applies here: authentication is
// SSH's own.

import { identity, detach, capabilities } from "./app.mjs";

const el = (tag, props = {}, ...children) => {
  const node = Object.assign(document.createElement(tag), props);
  for (const c of children) node.append(c);
  return node;
};

/**
 * The connection string travels in the URL fragment, so it stays out of
 * request logs and Referer headers. Accepts a bare string too, for
 * manual paste.
 */
export function connstringFromLocation(loc = location) {
  const frag = (loc.hash || "").replace(/^#/, "");
  return frag ? decodeURIComponent(frag) : "";
}

export async function initBoot(panel, { onConnect }) {
  const notice = el("div", { className: "notice" });
  const keyRow = el("div", { className: "key" });

  const csInput = el("input", {
    size: 48,
    placeholder: "connection string (from the listener's QR link)",
    value: connstringFromLocation(),
  });
  const userInput = el("input", {
    size: 16,
    placeholder: "user",
    value: "",
  });
  const method = el("select");
  method.append(
    el("option", { value: "publickey", textContent: "publickey (this browser's key)" }),
    el("option", { value: "password", textContent: "password" }),
    el("option", { value: "keyboard-interactive", textContent: "keyboard-interactive (OTP/2FA)" }),
  );
  const passInput = el("input", {
    size: 20,
    type: "password",
    placeholder: "password",
    disabled: true,
  });
  method.addEventListener("change", () => {
    passInput.disabled = method.value !== "password";
  });

  const connectBtn = el("button", { textContent: "connect" });
  const detachBtn = el("button", { textContent: "detach", disabled: true });
  const showKeyBtn = el("button", { textContent: "show this browser's public key" });

  panel.append(
    el("div", { className: "row" }, el("label", { textContent: "connection" }), csInput),
    el("div", { className: "row" }, el("label", { textContent: "user" }), userInput,
      " ", method, " ", passInput),
    el("div", { className: "row" }, connectBtn, " ", detachBtn, " ", showKeyBtn),
    keyRow,
    notice,
  );

  // Publickey support depends on the loaded component; ask it rather
  // than assume. Probing also forces the component to load, so the
  // panel reflects reality before the user commits to anything.
  (async () => {
    try {
      const caps = await capabilities();
      if (!caps.publickey) {
        for (const opt of [...method.options]) {
          if (opt.value === "publickey") opt.remove();
        }
        passInput.disabled = false;
        showKeyBtn.disabled = true;
        notice.textContent =
          "this build of the client component supports password auth only; " +
          "publickey (WebCrypto) auth is not available yet";
      }
      if (!caps.keyboardInteractive) {
        for (const opt of [...method.options]) {
          if (opt.value === "keyboard-interactive") opt.remove();
        }
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

  // The human decisions, rendered inline in the panel.
  const ui = {
    confirmHostKey(fingerprint) {
      return new Promise((resolve) => {
        const row = el("div", { className: "confirm" });
        const yes = el("button", { textContent: "yes, connect" });
        const no = el("button", { textContent: "no" });
        row.append(
          el("div", { textContent: "the server presented this host key:" }),
          el("code", { textContent: fingerprint }),
          el("div", { textContent: "does it match what the operator published?" }),
          yes, " ", no,
        );
        panel.append(row);
        const done = (v) => {
          row.remove();
          resolve(v);
        };
        yes.addEventListener("click", () => done(true));
        no.addEventListener("click", () => done(false));
      });
    },
    getCredential() {
      if (method.value === "password") {
        return { kind: "password", password: passInput.value };
      }
      if (method.value === "keyboard-interactive") {
        return { kind: "keyboard-interactive" };
      }
      return { kind: "publickey" };
    },
    // One keyboard-interactive batch: instruction text, then an input
    // per prompt -- masked unless the server said echo. Resolves with
    // the answers, in order.
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
        row.append(answerBtn);
        panel.append(row);
        inputs[0]?.focus();
        const done = () => {
          const answers = inputs.map((i) => i.value);
          row.remove();
          resolve(answers);
        };
        answerBtn.addEventListener("click", done);
        row.addEventListener("keydown", (e) => {
          if (e.key === "Enter") done();
        });
      });
    },
  };

  const doConnect = async () => {
    notice.textContent = "";
    const connstring = csInput.value.trim();
    const user = userInput.value.trim();
    if (!connstring) return void (notice.textContent = "a connection string is required");
    if (!user) return void (notice.textContent = "a user name is required");
    connectBtn.disabled = true;
    try {
      const session = await onConnect({ connstring, user, ui });
      detachBtn.disabled = !session;
      passInput.value = "";
    } catch (e) {
      notice.textContent = `${e.message ?? e}`;
    } finally {
      connectBtn.disabled = false;
    }
  };

  connectBtn.addEventListener("click", doConnect);
  detachBtn.addEventListener("click", async () => {
    await detach();
    detachBtn.disabled = true;
  });

  return { connect: doConnect, ui };
}
