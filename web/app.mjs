// experiment-mosh browser client. M2 shape below the M5 bootstrap
// panel: xterm.js in front of the jco-transpiled engine component,
// datagrams over the throwaway websocket dev bridge
// (host-test/browser-smoke.mjs). The page drives the engine's sans-I/O
// contract exactly like the M1 conformance driver: inbound datagrams →
// handle-datagram, an 8 ms tick whose returned datagrams go to the
// wire, display bytes drained and written to the terminal
// rAF-coalesced. The composed-core-over-iroh path (D7) is blocked on
// A3 (jco scheduler) — without a dev bridge the terminal stays idle
// and says so; see boot.mjs for the bootstrap flows.

const status = (msg) => {
  document.getElementById("status").textContent = msg;
};

const fatal = (msg) => {
  status(`FAILED: ${msg}`);
  window.__mosh.failure = String(msg);
  throw new Error(msg);
};

window.__mosh = { failure: null }; // test hook, filled in below

try {
  // --- terminal -----------------------------------------------------------
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

  // --- datagram bridge -----------------------------------------------------
  // The dev bridge spawns a dedicated mosh-server per connection (a
  // fresh engine instance cannot rejoin a running server: SSP replay
  // protection reads our restarted nonce sequence as replay) and sends
  // its key in a JSON hello frame; every later frame is one datagram.
  // A static serve has no bridge: not an error, the terminal idles.
  const ws = new WebSocket(`ws://${location.host}/ws${location.search}`);
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
    status("no dev bridge — terminal idle (in-browser iroh pending A3)");
  }

  if (hello) await runBridgeSession(term, fit, ws, hello);

  async function runBridgeSession(term, fit, ws, hello) {
    // --- engine -----------------------------------------------------------
    const { engine } = await import("/generated/mosh-engine.js");
    const session = engine.Session.connect(hello.key, term.cols, term.rows);

    // --- display path: drain → rAF-coalesced terminal writes --------------
    let chunks = [];
    let rafId = null;
    const flush = () => {
      rafId = null;
      const batch = chunks;
      chunks = [];
      for (const c of batch) term.write(c);
    };
    const drain = () => {
      const out = session.drainOutput();
      if (out.length) {
        chunks.push(out);
        if (rafId === null) rafId = requestAnimationFrame(flush);
      }
    };

    // --- datagram path -----------------------------------------------------
    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") return; // hello already consumed
      session.handleDatagram(new Uint8Array(ev.data));
      drain();
    };
    ws.onclose = () => {
      clearInterval(pump);
      status("disconnected");
    };

    // --- input path --------------------------------------------------------
    const encoder = new TextEncoder();
    term.onData((s) => {
      session.feedKeys(encoder.encode(s));
      drain(); // surface the prediction overlay immediately
    });
    term.onResize(({ cols, rows }) => {
      session.resize(cols, rows);
    });

    // --- the tick -----------------------------------------------------------
    const pump = setInterval(() => {
      for (const d of session.tick()) ws.send(d);
      drain();
    }, 8);

    status(
      `${engine.version()} · ${hello.delayMs ? `bridge delay ${hello.delayMs}ms/way · ` : ""}` +
        `${term.cols}×${term.rows}`,
    );

    // --- test hook -----------------------------------------------------------
    window.__mosh = {
      failure: null,
      session,
      term,
      stats: () => session.stats(),
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
    };
  }
} catch (e) {
  fatal(e.message ?? e);
}
