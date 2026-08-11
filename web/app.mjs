// wosh browser client. Two session modes in front of xterm.js, both
// hosted by deltic (runtime-linked components, ./dist/deltic.js — built
// by `just web-bundle`):
//
//  - bridge mode (M2): the bare engine component; datagrams over the
//    throwaway websocket dev bridge (host-test/browser-smoke.mjs). The
//    page drives the engine's sans-I/O contract exactly like the M1
//    conformance driver: inbound datagrams → handle-datagram, an ~8 ms
//    tick whose returned datagrams go to the wire, display bytes
//    drained and written rAF-coalesced. No bridge → the terminal idles
//    and says so.
//
//  - iroh mode (M5): the composed client core (engine + glue +
//    endpoint) speaking mosh SSP to a proxy over real iroh — dialed on
//    the relay wire, upgraded to a WebRTC data channel in the
//    background (the status line's `path` reports the move). The glue
//    owns the pumps and the tick; the page only feeds keys, drains
//    output, and resizes. Reached from the bootstrap panel (boot.mjs)
//    via connectIroh().
//
// Every component export is Promise-shaped under deltic, so both modes
// run one async pump loop with a single writer draining output (two
// concurrent drains could interleave screen bytes out of order).

import { initMobile, transformInput } from "./mobile.mjs";
import { OverlayAddon } from "./overlay.mjs";

const status = (msg) => {
  document.getElementById("status").textContent = msg;
};

const fatal = (msg) => {
  status(`FAILED: ${msg}`);
  window.__mosh.failure = String(msg);
  throw new Error(msg);
};

window.__mosh = { failure: null }; // test hook, filled in below

const DIST = {
  bundle: "./dist/deltic.js",
  translator: "./dist/deltic-translator-shim.wasm",
  engine: "./dist/main.wasm",
  client: "./dist/composed-client.wasm",
};

// --- terminal ---------------------------------------------------------------
const term = new Terminal({
  scrollback: 0, // mosh is a screen-state protocol; no scrollback exists
  fontSize: 14,
  cursorBlink: false,
});
const fit = new FitAddon.FitAddon();
term.loadAddon(fit);
const overlay = new OverlayAddon();
term.loadAddon(overlay);
term.open(document.getElementById("term"));
fit.fit(); // synchronous: sessions read term.cols/rows at connect time
term.focus();
// Refits beyond the first are owned by the observer: everything that
// moves the terminal's BOX funnels through it — the boot panel
// rendering (async, grows #panel), the extra-keys bar filling in,
// mobile.mjs resizing #wrap to the visual viewport, plain window
// resizes. A one-shot startup fit alone goes stale on the first of
// those (seen live: rows fitted before the keys bar filled overflow
// the flex box and eat the bar's taps).
new ResizeObserver(() => fit.fit()).observe(document.getElementById("term"));
addEventListener("resize", () => fit.fit()); // zoom edge cases; harmless overlap
initMobile(term); // soft-keyboard viewport glue + extra-keys bar
// The status line renders cols×rows once at session wire-up and goes
// stale on later resizes; this is the live feedback (issue #11). Fires
// on any real dims change — including the settling refit when the boot
// panel/keys bar land shortly after load, which is a genuine resize.
term.onResize(({ cols, rows }) => overlay.showOverlay(`${cols}×${rows}`, 500));

let sessionActive = false;

// --- shared plumbing ---------------------------------------------------------
// rAF-coalesced terminal writes; the pump is the only drainer. The
// bytes are STATEFUL diffs (the engine assumes everything it emitted
// reached the screen model), so the queue is flushed, never shed
// (issue #12): rAF starves in background tabs while the pump keeps
// draining on throttled timers, so a timer fallback bounds the queue,
// and hiding the tab flushes synchronously.
let chunks = [];
let rafId = null;
let flushTimer = null;
const paintStats = { peak: 0, flushes: 0, timerFlushes: 0 }; // test/measure hook
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
  if (!out.length) return;
  chunks.push(out);
  if (chunks.length > paintStats.peak) paintStats.peak = chunks.length;
  if (rafId === null) {
    rafId = requestAnimationFrame(() => flush());
    flushTimer = setTimeout(() => flush(true), 250);
  }
};
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden" && chunks.length) flush(true);
});

// A sleep the input path can cut short (prediction paints same-frame).
let wake = null;
const tickSleep = (ms) =>
  new Promise((r) => {
    wake = r;
    setTimeout(r, ms);
  });
const wakeNow = () => wake?.();

const installHooks = (mode, session, extra = {}) => {
  window.__mosh = {
    failure: null,
    mode,
    session,
    term,
    stats: () => session.stats(), // Promise under deltic
    text: () => {
      const buf = term.buffer.active;
      const lines = [];
      for (let y = 0; y < term.rows; y++) {
        lines.push(buf.getLine(y)?.translateToString(true) ?? "");
      }
      return lines.join("\n");
    },
    underlinedCells: () => {
      const buf = term.buffer.active;
      let n = 0;
      const cell = buf.getNullCell();
      for (let y = 0; y < term.rows; y++) {
        const line = buf.getLine(y);
        if (!line) continue;
        for (let x = 0; x < term.cols; x++) {
          line.getCell(x, cell);
          if (cell.isUnderline() && cell.getChars().trim()) n++;
        }
      }
      return n;
    },
    resize: (cols, rows) => term.resize(cols, rows),
    paintStats: () => ({ ...paintStats }),
    ...extra,
  };
};

// --- iroh mode (M5): the composed client over a real proxy -------------------
// Called by the bootstrap panel. Throws a user-legible error on failure
// (the panel renders it); on success the terminal is live end-to-end.

let currentSession = null;

// --- session end + reconnect (issue #12) --------------------------------------
// Transport death was indistinguishable from a programming error: every
// pump exception funneled to fatal() and the only recovery was a manual
// reload + re-pair. Now a LIVE session's errors end the session into a
// reconnectable state instead; fatal() stays for setup and engine-level
// failures. The reconnect handler is registered by the page glue
// (boot.reconnect — in-memory connstring/token retry, preferring the
// assertion-gated reattach); the one-shot key/tap that triggers it is a
// user gesture, which doubles as the WebAuthn user activation reattach
// needs — auto-reconnect is impossible by design for persistent
// sessions, so the gesture IS the mechanism, not a compromise.
let reconnector = null;
export function setReconnectHandler(fn) {
  reconnector = fn;
}

const sessionEnded = (session, msg) => {
  if (currentSession !== session || !sessionActive) return; // superseded/duplicate
  sessionActive = false;
  currentSession = null;
  window.__mosh.sessionEnded = String(msg); // test hook
  status(`disconnected — ${msg}`);
  if (!reconnector) {
    overlay.showOverlay("session ended — connect from the panel");
    return;
  }
  overlay.showOverlay("disconnected — tap or key to reconnect");
  const el = term.element;
  let done = false;
  const go = () => {
    if (done) return;
    done = true;
    keyHook.dispose();
    el.removeEventListener("pointerdown", go);
    overlay.hide();
    Promise.resolve(reconnector()).catch(() => {}); // boot renders its own notice
  };
  const keyHook = term.onData(go);
  el.addEventListener("pointerdown", go, { once: true });
};

// Input wiring for the live session. Sessions are sequential per tab
// (connect → disconnect → reattach …), so the previous session's
// handlers are disposed instead of stacking up and feeding a dead
// session object; the guard covers the gap where a handler is
// registered but the session it closed over was superseded.
let wired = null;
const wireInput = (session, fail) => {
  wired?.data.dispose();
  wired?.resize.dispose();
  wired = {
    data: term.onData((s) => {
      if (currentSession !== session || window.__mosh.failure) return;
      // transformInput: mobile.mjs's sticky Ctrl/Alt over every chunk
      // (identity unless armed) — one spot covers both session modes.
      session.feedKeys(new TextEncoder().encode(transformInput(s))).then(wakeNow, fail);
    }),
    resize: term.onResize(({ cols, rows }) => {
      if (currentSession !== session) return;
      session.resize(cols, rows).catch(fail);
    }),
  };
};

// Terminal + pump wiring shared by connect and reattach: the session is
// live; make the page drive it.
async function wireSession(session, { relayUrl, endpointIdHex }) {
  sessionActive = true;
  currentSession = session;

  wireInput(session, (e) => sessionEnded(session, `input: ${e.message ?? e}`));

  (async () => {
    try {
      for (;;) {
        if (currentSession !== session) return; // superseded — stop draining
        paint(await session.drainOutput());
        await tickSleep(8);
      }
    } catch (e) {
      sessionEnded(session, `session pump: ${e.message ?? e}`);
    }
  })();

  const dgramMax = await session.maxDatagramSize();
  let path = await session.path();
  const renderStatus = () =>
    status(
      `iroh session · proxy ${endpointIdHex.slice(0, 8)}… · relay ${relayUrl} · ` +
        `path ${path} · dgram ≤${dgramMax ?? "?"}B · ${term.cols}×${term.rows}`,
    );
  renderStatus();
  overlay.showOverlay("connected", 600);
  // Path watcher (plain sleep — tickSleep's wake slot belongs to the
  // drain pump): the WebRTC upgrade runs in the background and `path`
  // is not latched (it can move to the channel and fall back), so
  // poll and re-render on change.
  (async () => {
    try {
      for (;;) {
        await new Promise((r) => setTimeout(r, 1500));
        const p = await session.path();
        if (p !== path) {
          path = p;
          renderStatus();
          overlay.showOverlay(`path ${path}`, 1200);
        }
      }
    } catch {
      /* session gone (detach/teardown) — stop watching */
    }
  })();
  installHooks("iroh", session, {
    detach: () => session.detach(),
    sessionId: () => session.sessionId(),
    path: () => session.path(),
  });
  return session;
}

export async function connectIroh({ relayUrl, endpointIdHex, token }) {
  if (sessionActive) throw new Error("a session is already running in this tab");
  status(`connecting to ${endpointIdHex.slice(0, 8)}… via ${relayUrl}`);
  const { loadClient, WitError } = await import(DIST.bundle);
  const client = await loadClient(DIST.client, DIST.translator);

  let session;
  try {
    // direct: none — a page has no UDP; the paths are relay + WebRTC.
    session = await client.ClientSession.connectProxy(
      relayUrl,
      endpointIdHex,
      undefined,
      token,
      term.cols,
      term.rows,
    );
  } catch (e) {
    const msg = e instanceof WitError ? String(e.payload) : (e.message ?? String(e));
    status(`connect failed: ${msg}`);
    throw new Error(msg);
  }
  return wireSession(session, { relayUrl, endpointIdHex });
}

// Inner-ssh mode (M7, workstream F): dial the proxy deprivileged-style,
// authenticate end-to-end over ssh through the forwarded stream, boot a
// mosh-server via ssh exec, and run mosh over the datagram tunnel. The
// proxy never sees the mosh key. Host-key policy is the embedder's
// (boot.mjs pins through storage): `expectedHostKey` some ⇒ mismatch
// fails BEFORE the password is sent. First contact (no pin) does NOT
// belong here — boot.mjs routes it through beginSshIroh so the user
// confirms the fingerprint before any credentials move.
export async function connectSshIroh({
  relayUrl,
  endpointIdHex,
  token,
  user,
  password,
  expectedHostKey,
  command,
}) {
  if (sessionActive) throw new Error("a session is already running in this tab");
  status(`ssh-connecting to ${endpointIdHex.slice(0, 8)}… via ${relayUrl}`);
  const { loadClient, WitError } = await import(DIST.bundle);
  const client = await loadClient(DIST.client, DIST.translator);

  let session;
  try {
    session = await client.ClientSession.connectSsh(
      relayUrl,
      endpointIdHex,
      undefined,
      token,
      user,
      password,
      expectedHostKey ?? undefined,
      command ?? undefined,
      term.cols,
      term.rows,
    );
  } catch (e) {
    const msg = e instanceof WitError ? String(e.payload) : (e.message ?? String(e));
    status(`connect failed: ${msg}`);
    throw new Error(msg);
  }
  await wireSession(session, { relayUrl, endpointIdHex });
  return { hostKey: await session.sshHostKey() };
}

// First-contact inner ssh (issue #7): begin dials and runs kex, then
// PARKS at the host-key gate — the composed client holds no password
// yet, so it cannot leave before the user rules on the fingerprint
// (the user NAME rides begin, but is only sent in auth requests,
// strictly after the gate). Returns { hostKey, confirm, decline }:
// the panel shows hostKey, then either confirm({ password, command })
// → live session (pin on success), or decline() → teardown with zero
// auth attempts.
export async function beginSshIroh({ relayUrl, endpointIdHex, token, user }) {
  if (sessionActive) throw new Error("a session is already running in this tab");
  status(`ssh-connecting to ${endpointIdHex.slice(0, 8)}… via ${relayUrl}`);
  const { loadClient, WitError } = await import(DIST.bundle);
  const client = await loadClient(DIST.client, DIST.translator);
  const witMsg = (e) => (e instanceof WitError ? String(e.payload) : (e.message ?? String(e)));

  let flow;
  try {
    flow = await client.SshFlow.begin(relayUrl, endpointIdHex, undefined, token, user);
  } catch (e) {
    const msg = witMsg(e);
    status(`connect failed: ${msg}`);
    throw new Error(msg);
  }
  const hostKey = await flow.hostKey();
  status(`first contact: ssh host key ${hostKey} — confirm to authenticate`);
  return {
    hostKey,
    confirm: async ({ password, command }) => {
      // Re-check: another session may have gone live while the
      // prompt sat open (the park window is user-paced).
      if (sessionActive) throw new Error("a session is already running in this tab");
      let session;
      try {
        session = await flow.authenticate(password, command ?? undefined, term.cols, term.rows);
      } catch (e) {
        const msg = witMsg(e);
        status(`connect failed: ${msg}`);
        throw new Error(msg);
      }
      await wireSession(session, { relayUrl, endpointIdHex });
      return { hostKey };
    },
    decline: async () => {
      try {
        await flow.decline();
      } finally {
        status("ssh first contact declined — no credentials were sent");
      }
    },
  };
}

// --- passkey persistence (M6 browser leg) -------------------------------------
// Ceremonies live in passkey.mjs; these wrappers bind them to the live
// session / a fresh client instance. The panel owns storage.

/** Make the LIVE session persistent; returns { escrow, sessionId }. */
export async function persistCurrent() {
  if (!sessionActive || !currentSession) throw new Error("no live session to persist");
  const { persistSession } = await import("./passkey.mjs");
  return persistSession(currentSession);
}

/** Assertion-gated reattach to a persistent session (fresh client). */
export async function reattachIroh({ relayUrl, endpointIdHex, token, sessionId }) {
  if (sessionActive) throw new Error("a session is already running in this tab");
  status(`reattaching session ${sessionId} on ${endpointIdHex.slice(0, 8)}…`);
  const { loadClient, WitError } = await import(DIST.bundle);
  const { reattachSession } = await import("./passkey.mjs");
  const client = await loadClient(DIST.client, DIST.translator);
  let session, escrow;
  try {
    ({ session, escrow } = await reattachSession(
      client,
      { relayUrl, endpointIdHex, token, sessionId },
      term.cols,
      term.rows,
    ));
  } catch (e) {
    const msg = e instanceof WitError ? String(e.payload) : (e.message ?? String(e));
    status(`reattach failed: ${msg}`);
    throw new Error(msg);
  }
  await wireSession(session, { relayUrl, endpointIdHex });
  return { escrow };
}

// --- bridge mode (M2) ---------------------------------------------------------
// The dev bridge spawns a dedicated mosh-server per connection (a fresh
// engine instance cannot rejoin a running server: SSP replay protection
// reads our restarted nonce sequence as replay) and sends its key in a
// JSON hello frame; every later frame is one datagram. A static serve
// has no bridge: not an error, the terminal idles. (Scheme must follow
// the page's: an https page may not open ws://, and the constructor
// throws synchronously if asked — the wss attempt instead fails through
// the normal no-bridge path.)

// Dial the bridge; resolves { ws, hello } or rejects (no bridge).
const bridgeDial = () =>
  new Promise((resolve, reject) => {
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${scheme}//${location.host}/ws${location.search}`);
    ws.binaryType = "arraybuffer";
    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") resolve({ ws, hello: JSON.parse(ev.data) });
    };
    ws.onerror = () => reject(new Error("websocket failed"));
    ws.onclose = () => reject(new Error("websocket closed before hello"));
  });

// A dropped bridge auto-redials with backoff (issue #12): each redial
// is a NEW mosh-server and a fresh shell — that's bridge-mode
// semantics (dev only), not session resumption; term.reset() makes the
// break visible instead of interleaving two servers' screens. Gives up
// (or stands down) if another session takes the terminal meanwhile.
async function bridgeRedial() {
  for (const delay of [1000, 2000, 4000, 8000, 8000]) {
    overlay.showOverlay("reconnecting…");
    status("reconnecting to dev bridge…");
    await new Promise((r) => setTimeout(r, delay));
    if (sessionActive) return; // an iroh session took over — stand down
    let conn;
    try {
      conn = await bridgeDial();
    } catch {
      continue; // bridge still down — next attempt
    }
    if (sessionActive) {
      conn.ws.close();
      return;
    }
    term.reset();
    overlay.showOverlay("reconnected", 600);
    await runBridgeSession(conn.ws, conn.hello); // engine errors propagate — not a dial retry
    return;
  }
  status("disconnected");
  overlay.showOverlay("disconnected");
}

try {
  let conn = null;
  try {
    conn = await bridgeDial();
  } catch {
    window.__mosh.noBridge = true;
    status("no dev bridge — idle; connect to a proxy from the panel below");
  }

  if (conn) await runBridgeSession(conn.ws, conn.hello);
} catch (e) {
  fatal(e.message ?? e);
}

async function runBridgeSession(ws, hello) {
  const { loadEngine } = await import(DIST.bundle);
  const engine = await loadEngine(DIST.engine, DIST.translator);
  const session = await engine.Session.connect(hello.key, term.cols, term.rows, undefined);
  sessionActive = true;
  currentSession = session;

  // --- datagram path ---------------------------------------------------------
  let inbound = [];
  ws.onmessage = (ev) => {
    if (typeof ev.data === "string") return; // hello already consumed
    inbound.push(new Uint8Array(ev.data));
    wakeNow();
  };
  let closed = false;
  ws.onclose = () => {
    closed = true;
    if (currentSession === session) {
      sessionActive = false;
      currentSession = null;
      status("disconnected");
      bridgeRedial().catch((e) => fatal(e.message ?? e));
    }
  };

  // --- input path --------------------------------------------------------------
  // feed-keys then an immediate pump round: predictions paint same-frame.
  wireInput(session, (e) => fatal(e.message ?? e));

  // --- the pump: feed inbound, tick, drain — one writer, in order -------------
  (async () => {
    try {
      while (!closed) {
        const batch = inbound;
        inbound = [];
        for (const d of batch) await session.handleDatagram(d);
        for (const d of await session.tick()) {
          if (ws.readyState === WebSocket.OPEN) ws.send(d);
        }
        paint(await session.drainOutput());
        await tickSleep(8);
      }
    } catch (e) {
      fatal(`bridge pump: ${e.message ?? e}`);
    }
  })();

  const version = await engine.version();
  if (currentSession !== session) return; // superseded during the awaits above
  status(
    `${version} · ${hello.delayMs ? `bridge delay ${hello.delayMs}ms/way · ` : ""}` +
      `${term.cols}×${term.rows}`,
  );
  overlay.showOverlay("connected", 600);
  installHooks("bridge", session);
}
