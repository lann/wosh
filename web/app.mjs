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
term.open(document.getElementById("term"));
fit.fit();
term.focus();
addEventListener("resize", () => fit.fit());

let sessionActive = false;

// --- shared plumbing ---------------------------------------------------------
// rAF-coalesced terminal writes; the pump is the only drainer.
let chunks = [];
let rafId = null;
const flush = () => {
  rafId = null;
  const batch = chunks;
  chunks = [];
  for (const c of batch) term.write(c);
};
const paint = (out) => {
  if (!out.length) return;
  chunks.push(out);
  if (rafId === null) rafId = requestAnimationFrame(flush);
};

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
    ...extra,
  };
};

// --- iroh mode (M5): the composed client over a real proxy -------------------
// Called by the bootstrap panel. Throws a user-legible error on failure
// (the panel renders it); on success the terminal is live end-to-end.

let currentSession = null;

// Terminal + pump wiring shared by connect and reattach: the session is
// live; make the page drive it.
async function wireSession(session, { relayUrl, endpointIdHex }) {
  sessionActive = true;
  currentSession = session;

  term.onData((s) => {
    if (window.__mosh.failure) return;
    session.feedKeys(new TextEncoder().encode(s)).then(wakeNow, (e) => fatal(e.message ?? e));
  });
  term.onResize(({ cols, rows }) => {
    session.resize(cols, rows).catch((e) => fatal(e.message ?? e));
  });

  (async () => {
    try {
      for (;;) {
        paint(await session.drainOutput());
        await tickSleep(8);
      }
    } catch (e) {
      fatal(`session pump: ${e.message ?? e}`);
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
try {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${scheme}//${location.host}/ws${location.search}`);
  ws.binaryType = "arraybuffer";
  let hello = null;
  try {
    hello = await new Promise((resolve, reject) => {
      ws.onmessage = (ev) => {
        if (typeof ev.data === "string") resolve(JSON.parse(ev.data));
      };
      ws.onerror = () => reject(new Error("websocket failed"));
      ws.onclose = () => reject(new Error("websocket closed before hello"));
    });
  } catch {
    window.__mosh.noBridge = true;
    status("no dev bridge — idle; connect to a proxy from the panel below");
  }

  if (hello) await runBridgeSession(ws, hello);
} catch (e) {
  fatal(e.message ?? e);
}

async function runBridgeSession(ws, hello) {
  const { loadEngine } = await import(DIST.bundle);
  const engine = await loadEngine(DIST.engine, DIST.translator);
  const session = await engine.Session.connect(hello.key, term.cols, term.rows, undefined);
  sessionActive = true;

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
    status("disconnected");
  };

  // --- input path --------------------------------------------------------------
  term.onData((s) => {
    // feed-keys then an immediate pump round: predictions paint same-frame.
    session.feedKeys(new TextEncoder().encode(s)).then(wakeNow, (e) => fatal(e.message ?? e));
  });
  term.onResize(({ cols, rows }) => {
    session.resize(cols, rows).catch((e) => fatal(e.message ?? e));
  });

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

  status(
    `${await engine.version()} · ${hello.delayMs ? `bridge delay ${hello.delayMs}ms/way · ` : ""}` +
      `${term.cols}×${term.rows}`,
  );
  installHooks("bridge", session);
}
