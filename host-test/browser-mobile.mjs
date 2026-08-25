// Gate: the mobile layer (site/mobile.mjs) under real touch input --
// the extra-keys bar's tap-vs-drag rule, the focus rule that keeps the
// soft keyboard reachable, and scrolling the terminal with a finger.
//
// The bar (site/mobile.mjs) is the one part of the page a thumb touches
// constantly, and its key strip scrolls sideways -- so fingers land on
// keys on their way somewhere else. It used to act on pointerdown,
// which made every such drag emit whatever key it started on (flick the
// strip to reach the arrows, get a stray `~` in your shell). The rule
// now is: a key fires on pointerUP, and only if the finger never
// traveled; travel or a browser-claimed gesture (pointercancel) drops
// the press.
//
// That is pure DOM gesture handling -- no component, no wasm, no
// network -- so this gate drives site/mobile.mjs and the page's real
// stylesheet directly against a stub terminal, in Chromium under touch
// emulation. It needs no `just site` build, and it is the only gate
// that can see this class of bug: the e2e legs type through xterm, not
// through the bar, and neither they nor any native test synthesize a
// finger that moves.
//
// The scrolling legs need a REAL terminal (xterm's scrollback, its own
// scrollbar), so they run against a second fixture that mounts xterm
// from site/node_modules -- `just web-deps` puts it there. Everything
// else drives a stub terminal.
//
// The same fixture carries the FORWARDING legs (18m-18q). A finger
// must not always move the scrollback: an app that has turned mouse
// tracking on wants the wheel itself, and an alternate-screen program
// (tmux, vim, less) has no scrollback to move at all -- which is why
// touch scroll used to do nothing there. Those drags are turned into
// wheel events on xterm's own screen element and left to xterm to
// encode, so the legs assert on the REPORTS the terminal emits (SGR
// wheel reports, or the cursor keys xterm substitutes when nothing is
// tracking) rather than on a viewport that must now stay put. Leg 25h
// closes the other half of the same path in the real app: a report
// whose coordinate byte runs past 0x7f leaves xterm through onBinary,
// not onData, and has to reach the session byte for byte.
//
// Usage: node host-test/browser-mobile.mjs [--keep]

import { chromium } from "playwright-core";
import { existsSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname } from "node:path";

const ROOT = new URL("../", import.meta.url).pathname;
const PORT = Number(process.env.WOSH_HTTP_PORT ?? 8101); // one per browser gate: 8098/8099/8102/8123/8129/8131/8132/8133 are taken

const MIME = { ".mjs": "text/javascript", ".js": "text/javascript", ".css": "text/css" };

function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  // Playwright-managed builds; newest wins.
  const glob = `${process.env.HOME}/.cache/ms-playwright`;
  const dirs = readdirSync(glob)
    .filter((d) => d.startsWith("chromium-"))
    .sort((a, b) => Number(a.split("-")[1]) - Number(b.split("-")[1]));
  for (const d of dirs.reverse()) {
    // Chrome for Testing unpacks as chrome-linux64/; older Chromium
    // builds as chrome-linux/.
    for (const sub of ["chrome-linux64", "chrome-linux"]) {
      const p = join(glob, d, sub, "chrome");
      if (existsSync(p)) return p;
    }
  }
  throw new Error("no Chromium found; set CHROME_PATH");
}

// The page's own <style>, verbatim: the bar's layout, its coarse-pointer
// gating and `touch-action` are as much of the behavior under test as
// the JS is, and lifting them out of index.html leaves nothing to drift.
const style = (await readFile(join(ROOT, "site/index.html"), "utf8"))
  .match(/<style>([\s\S]*?)<\/style>/)[1];

// A terminal stand-in with the four members mobile.mjs touches. Keys
// reach it through term.input(), the same call the real bar makes.
const FIXTURE = `<!doctype html>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>keys-bar fixture</title>
<style>${style}</style>
<body class="live"><!-- the keys bar shows only WITH a session (body.live) -->
<div id="wrap">
  <div id="bar"><span id="status">fixture</span></div>
  <div id="term"><textarea id="fake-textarea"></textarea></div>
  <div id="keys"></div>
</div>
<script type="module">
  import { autofocusTerminal, initMobile, transformInput } from "/site/mobile.mjs";
  const sent = [];
  const textarea = document.getElementById("fake-textarea");
  const term = {
    textarea,
    options: {},
    modes: { applicationCursorKeysMode: false },
    // app.mjs runs transformInput over every onData chunk; mirror that
    // so armed Ctrl/Alt is observable exactly as the session sees it.
    input: (s) => sent.push(transformInput(s)),
    focus: () => textarea.focus(),
    blur: () => textarea.blur(),
  };
  // app.mjs's startup order, which is what leg 9 is about: it asks for
  // the typing focus before wiring the mobile layer.
  autofocusTerminal(term);
  initMobile(term);
  globalThis.wosh = { sent, term };
</script>
`;

// A REAL terminal, for the scrolling legs: xterm's scrollback and its
// own drawn scrollbar are the subject, so a stub cannot stand in. The
// page below is the app's structure and stylesheet plus one deliberate
// addition -- a spacer that makes the DOCUMENT scrollable, which is
// what a phone looks like whenever the layout viewport outgrows the
// visual one (iOS with the keyboard up). Without it the "and the page
// must not move" assertion could pass on a page that had nowhere to
// move to.
const XTERM_DIR = join(ROOT, "site/node_modules/@xterm");
const TERMINAL_FIXTURE = `<!doctype html>
<meta name="viewport" content="width=device-width, initial-scale=1, interactive-widget=resizes-content">
<title>terminal fixture</title>
<link rel="stylesheet" href="/site/node_modules/@xterm/xterm/css/xterm.css">
<style>${style}</style>
<body class="live"><!-- the keys bar shows only WITH a session (body.live) -->
<div id="wrap">
  <div id="bar"><span id="status">fixture</span></div>
  <div id="term"></div>
  <div id="keys"></div>
</div>
<div id="spacer" style="height: 240px"></div>
<script src="/site/node_modules/@xterm/xterm/lib/xterm.js"></script>
<script src="/site/node_modules/@xterm/addon-fit/lib/addon-fit.js"></script>
<script src="/site/node_modules/@xterm/addon-web-links/lib/addon-web-links.js"></script>
<script type="module">
  import { initMobile } from "/site/mobile.mjs";
  const term = new Terminal({ fontSize: 14, cursorBlink: false, scrollback: 1000 });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  // The link addon is here for leg 18k: a tap on a painted URI must
  // still reach xterm's linkifier THROUGH the selection overlay, which
  // is only true while the overlay is a descendant of .xterm-screen
  // (where the linkifier binds its mouse listeners).
  const linkActivations = [];
  term.loadAddon(new WebLinksAddon.WebLinksAddon((event, uri) => {
    linkActivations.push(uri);
  }));
  term.open(document.getElementById("term"));
  fit.fit();
  // What the terminal SENDS: mouse reports (and the cursor keys xterm
  // substitutes for a wheel on the alt screen) leave through onData,
  // the same channel typing does. The forwarding legs read this.
  const dataLog = [];
  term.onData((s) => dataLog.push(s));
  for (let i = 1; i <= 300; i++) term.write("line " + i + "\\r\\n");
  // app.mjs's shape, verbatim in spirit: the mobile layer hands back a
  // gate, and every refit path goes through it. The counter is the only
  // outside evidence a refit was deferred rather than dropped.
  const { guardRefit } = initMobile(term);
  const refit = guardRefit(() => { globalThis.wosh.refits++; fit.fit(); });
  globalThis.wosh = {
    term,
    data: () => dataLog.splice(0),
    refits: 0,
    refit,
    linkActivations,
    focused: () => document.activeElement === term.textarea,
    state: () => ({
      viewportY: term.buffer.active.viewportY,
      baseY: term.buffer.active.baseY,
      rows: term.rows,
      cellHeight: document.querySelector(".xterm-screen").getBoundingClientRect().height / term.rows,
      pageScrollY: window.scrollY,
      docScrollable: document.documentElement.scrollHeight > document.documentElement.clientHeight,
    }),
    // The scrollbar xterm draws: only grabbable while it is visible
    // (its own CSS gives it pointer-events: none when faded out).
    scrollbar: () => {
      const bar = document.querySelector(".xterm-scrollable-element > .scrollbar.vertical");
      const slider = bar?.querySelector(".slider");
      const box = (el) => { const b = el?.getBoundingClientRect(); return b && b.height ? { x: b.x, y: b.y, w: b.width, h: b.height } : null; };
      return { visible: Boolean(bar?.classList.contains("visible")), bar: box(bar), slider: box(slider) };
    },
  };
</script>
`;

// The page-lifecycle wiring (site/lifecycle.mjs), against a stub
// session that records what it was told. No component and no listener:
// what is under test is which browser event means "away" and which
// means "back", and that the handlers cannot throw on the way out of a
// page that is being frozen.
const LIFECYCLE_FIXTURE = `<!doctype html>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>lifecycle fixture</title>
<script type="module">
  import { initLifecycle } from "/site/lifecycle.mjs";
  const calls = [];
  let session = {
    suspend: async () => { calls.push("suspend"); },
    wake: async () => { calls.push("wake"); },
  };
  let painted = 0;
  initLifecycle(() => session, () => { painted++; });
  globalThis.wosh = {
    calls,
    painted: () => painted,
    reset: () => { calls.length = 0; painted = 0; },
    // Sessions come and go under the handlers; and both of these are
    // states the page really reaches (before connect, after disconnect).
    clearSession: () => { session = null; },
    breakSession: () => {
      session = {
        suspend: () => { throw new Error("torn down"); },
        wake: () => Promise.reject(new Error("torn down")),
      };
    },
    // document.visibilityState is not settable, so shadow it: the
    // handler reads it, and this is the only way to make it read
    // "hidden" without a real backgrounding.
    setVisibility: (state) => {
      Object.defineProperty(document, "visibilityState", { value: state, configurable: true });
      document.dispatchEvent(new Event("visibilitychange"));
    },
  };
  globalThis.addEventListener("unhandledrejection", (e) => {
    globalThis.wosh.calls.push("UNHANDLED:" + e.reason);
  });
</script>
`;

// The connect PANEL, real: index.html + boot.mjs + app.mjs verbatim,
// with only the wasm component behind /dist/polyengine.js stubbed (all
// capabilities true, synthetic identity lines). What is under test is
// the panel's structure -- what a user sees before touching anything,
// and where the rows that need answers appear.
const POLYENGINE_STUB = `
// app.mjs imports this DIRECTLY from the module (not off the client):
// the ceremony gate the panel installs. Retained and exposed so the
// gate legs can raise a ceremony exactly the way the store would.
export function setCeremonyGate(fn) { globalThis.__ceremonyGate = fn; }

export async function loadClient() {
  // A session with just enough surface for the page to go live: the
  // legs below drive UI that only exists WITH a session (the session
  // sheet, and settings reached from inside one). Everything typed at
  // it is kept on globalThis so a leg can see what the page actually
  // put on the pty.
  class Session {}
  Session.prototype.authenticateAuto = () => {};
  Session.prototype.pendingPrompts = () => {};
  Session.prototype.status = async function () {
    return { kind: this._ready ? "ready" : "host-key-check" };
  };
  Session.prototype.hostKeyFingerprint = async () => "SHA256:synthetic-fingerprint-for-the-gate";
  Session.prototype.confirmHostKey = async function () { this._ready = true; };
  Session.prototype.drainOutput = async () => new Uint8Array();
  Session.prototype.exited = async () => false;
  Session.prototype.writeInput = async (bytes) => {
    globalThis.__typedAtSession = (globalThis.__typedAtSession ?? "") +
      new TextDecoder().decode(bytes);
    // ...and the bytes themselves, undecoded: leg 25h is about a byte
    // that has no meaning as UTF-8 text, so the string capture above
    // is exactly the lossy view it must not be judged through.
    globalThis.__typedBytes = (globalThis.__typedBytes ?? []).concat([...bytes]);
  };
  Session.prototype.resize = async () => {};
  Session.prototype.detach = async () => {};
  Session.prototype.closeKind = async () => ({ kind: "ended" });
  Session.prototype.linkState = async () => "attached";
  Session.prototype.suspend = async () => {};
  Session.prototype.wake = async () => {};
  // Echo the command back: the install leg pins the SHAPE of what the
  // page asks a machine to run, which is the part a stub can check and
  // the part that has to be right.
  Session.prototype.probe = async (cmd) => {
    globalThis.__probed = cmd;
    return {
      output: new TextEncoder().encode(globalThis.__probeReply ?? "WOSH_ADDED\\n"),
      exitStatus: 0,
    };
  };
  Session.connect = async () => new Session();
  return {
    Session,
    identityOpenssh: async () => "ssh-ed25519 AAAA-synthetic-not-a-real-key wosh-browser",
    passkeyOpenssh: async () => undefined,
    enrollPasskey: async () => {},
    installCeremonyGate: async () => {},
  };
}
`;
const SITE = join(ROOT, "site");
const XTERM_FILES = {
  "/xterm/xterm.js": "node_modules/@xterm/xterm/lib/xterm.js",
  "/xterm/xterm.css": "node_modules/@xterm/xterm/css/xterm.css",
  "/xterm/addon-fit.js": "node_modules/@xterm/addon-fit/lib/addon-fit.js",
  "/xterm/addon-unicode11.js": "node_modules/@xterm/addon-unicode11/lib/addon-unicode11.js",
  "/xterm/addon-clipboard.js": "node_modules/@xterm/addon-clipboard/lib/addon-clipboard.js",
  "/xterm/addon-web-links.js": "node_modules/@xterm/addon-web-links/lib/addon-web-links.js",
  "/xterm/addon-image.js": "node_modules/@xterm/addon-image/lib/addon-image.js",
  "/xterm/addon-webgl.js": "node_modules/@xterm/addon-webgl/lib/addon-webgl.js",
  "/xterm/addon-serialize.js": "node_modules/@xterm/addon-serialize/lib/addon-serialize.js",
};

const server = createServer(async (req, res) => {
  const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (path === "/") {
    res.writeHead(200, { "content-type": "text/html", "cache-control": "no-store" }).end(FIXTURE);
    return;
  }
  if (path === "/panel") {
    res.writeHead(200, { "content-type": "text/html", "cache-control": "no-store" })
      .end(await readFile(join(SITE, "index.html")));
    return;
  }
  if (path === "/dist/polyengine.js") {
    res.writeHead(200, { "content-type": "text/javascript", "cache-control": "no-store" }).end(POLYENGINE_STUB);
    return;
  }
  if (XTERM_FILES[path]) {
    res.writeHead(200, { "content-type": MIME[extname(path)] ?? "text/plain", "cache-control": "no-store" })
      .end(await readFile(join(SITE, XTERM_FILES[path])));
    return;
  }
  if (path === "/lifecycle") {
    res.writeHead(200, { "content-type": "text/html", "cache-control": "no-store" }).end(LIFECYCLE_FIXTURE);
    return;
  }
  if (path === "/terminal") {
    res.writeHead(200, { "content-type": "text/html", "cache-control": "no-store" }).end(TERMINAL_FIXTURE);
    return;
  }
  if (path === "/favicon.ico") {
    res.writeHead(204).end(); // Chromium asks unprompted; a 404 is not news
    return;
  }
  try {
    // index.html (served at /panel) asks for its siblings at the root;
    // they live in site/. Repo-prefixed paths keep working as before.
    const body = await readFile(join(ROOT, path)).catch(() => readFile(join(SITE, path)));
    res.writeHead(200, {
      "content-type": MIME[extname(path)] ?? "application/octet-stream",
      "cache-control": "no-store",
    });
    res.end(body);
  } catch {
    res.writeHead(404).end("not found");
  }
});

const fail = (msg) => {
  console.error(`FAIL: ${msg}`);
  process.exitCode = 1;
};
const ok = (cond, msg) => cond || (fail(msg), false);

await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
const browser = await chromium.launch({ executablePath: findChrome(), args: ["--no-sandbox"] });

try {
  // A phone: narrow enough that the strip really does overflow and
  // scroll, with touch as the only pointer.
  const context = await browser.newContext({
    viewport: { width: 390, height: 780 },
    deviceScaleFactor: 3,
    hasTouch: true,
    isMobile: true,
  });
  const page = await context.newPage();
  const consoleErrors = [];
  page.on("console", (m) => m.type() === "error" && consoleErrors.push(m.text()));
  page.on("pageerror", (e) => consoleErrors.push(String(e)));

  await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: "load" });
  await page.waitForFunction(() => globalThis.wosh, null, { timeout: 15_000 });

  // Raw touch, not page.touchscreen: only CDP can put a finger down,
  // move it, and lift it -- which is the whole subject of this gate.
  const cdp = await context.newCDPSession(page);
  const points = (x, y) => [{ x: Math.round(x), y: Math.round(y), radiusX: 12, radiusY: 12, force: 1 }];
  const send = (type, touchPoints) => cdp.send("Input.dispatchTouchEvent", { type, touchPoints });

  const box = async (label) => {
    const key = page.locator(`#keys button:text-is("${label}")`);
    // The strip overflows a phone: bring the key under the thumb first,
    // and refuse to aim a finger at coordinates that are off-screen --
    // a touch into empty space emits nothing, which is exactly what
    // these legs assert, so it must never be why one passes.
    await key.scrollIntoViewIfNeeded();
    const b = await key.boundingBox();
    if (!b) throw new Error(`no key button labeled ${label}`);
    const { x, y } = { x: b.x + b.width / 2, y: b.y + b.height / 2 };
    const view = page.viewportSize();
    if (x < 0 || y < 0 || x > view.width || y > view.height) {
      throw new Error(`key ${label} is off-screen at (${x}, ${y})`);
    }
    return { x, y };
  };
  const tap = async (label) => {
    const { x, y } = await box(label);
    await send("touchStart", points(x, y));
    await page.waitForTimeout(40);
    await send("touchEnd", []);
    await page.waitForTimeout(60);
  };
  // A finger that lands at (x, y) and travels (dx, dy) before lifting.
  const dragAt = async (x, y, dx, dy, steps = 8) => {
    await send("touchStart", points(x, y));
    await page.waitForTimeout(30);
    for (let i = 1; i <= steps; i++) {
      await send("touchMove", points(x + (dx * i) / steps, y + (dy * i) / steps));
      await page.waitForTimeout(16);
    }
    await send("touchEnd", []);
    await page.waitForTimeout(120);
  };
  // The same, aimed at a key by label.
  const drag = async (label, dx, dy, steps = 8) => {
    const { x, y } = await box(label);
    await send("touchStart", points(x, y));
    await page.waitForTimeout(30);
    for (let i = 1; i <= steps; i++) {
      await send("touchMove", points(x + (dx * i) / steps, y + (dy * i) / steps));
      await page.waitForTimeout(16);
    }
    await send("touchEnd", []);
    await page.waitForTimeout(80);
  };
  const sent = () => page.evaluate(() => globalThis.wosh.sent.slice());
  const seen = async (label) => {
    const s = await sent();
    return `${label}: ${JSON.stringify(s)}`;
  };

  // 1. The bar exists on a coarse-pointer device (it is display:none
  //    everywhere else, which is what makes it inert on desktop).
  const barBox = await page.locator("#keys").boundingBox();
  const keyCount = await page.locator("#keys button").count();
  if (!barBox || keyCount < 12) fail(`bar not laid out on a touch device (${keyCount} keys, box=${JSON.stringify(barBox)})`);
  else console.log(`[1] extra-keys bar is live under a coarse pointer: ${keyCount} keys`);

  // 2. A tap still types -- including the jittery kind real fingers
  //    make. (Moving the action to pointerup must not regress either
  //    the press or the tolerance around it: a threshold tightened to
  //    zero would break every real-device tap while a perfectly still
  //    synthetic tap kept passing.)
  await tap("esc");
  await drag("tab", 4, 4, 2); // ~6px of travel: under SLOP, still a press
  let s = await sent();
  if (s.join("") !== "\x1b\t") fail(`a tap did not emit Esc, then a jittery tap Tab -- ${await seen("sent")}`);
  else console.log("[2] a tap emits its key, finger jitter included");

  // 3. ...and it does NOT steal focus from the terminal, which on a
  //    phone would drop the soft keyboard mid-press.
  await page.evaluate(() => globalThis.wosh.term.focus());
  await tap("|");
  const stillFocused = await page.evaluate(() => document.activeElement === globalThis.wosh.term.textarea);
  s = await sent();
  if (s.at(-1) !== "|") fail(`tap on | did not emit -- ${await seen("sent")}`);
  else if (!stillFocused) fail("a key press moved focus off the terminal (the soft keyboard would drop)");
  else console.log("[3] a press types without taking focus off the terminal");

  // 4. THE BUG: a finger that lands on a key and drags away is not a
  //    press. Down-the-screen first (the flick that used to emit).
  const before = (await sent()).length;
  await drag("~", 0, 60);
  s = await sent();
  if (s.length !== before) fail(`dragging a finger down off a key emitted it -- ${await seen("sent")}`);
  else console.log("[4] a downward drag off a key emits nothing");

  // 5. The sideways flick that scrolls the strip: the browser claims
  //    the gesture (pointercancel) rather than letting it end as a tap.
  //    Assert the strip really did scroll, so this leg keeps testing the
  //    conflict it is named for and not just a short drag.
  await page.evaluate(() => document.getElementById("keys-strip").scrollLeft = 0);
  await drag("/", -160, 0, 10);
  const scrolled = await page.evaluate(() => document.getElementById("keys-strip").scrollLeft);
  s = await sent();
  if (s.length !== before) fail(`flicking the strip sideways emitted a key -- ${await seen("sent")}`);
  else if (scrolled <= 0) fail(`the strip did not scroll (${scrolled}px): this leg is no longer testing the scroll/press conflict`);
  else console.log(`[5] a sideways flick scrolls the strip (${Math.round(scrolled)}px) and emits nothing`);

  // 6. Sticky modifiers follow the same rule: a tap arms Ctrl, a drag
  //    does not. Then the NEXT key carries it, and only that one
  //    (transformInput, the path app.mjs puts every chunk through).
  const isArmed = () =>
    page.locator('#keys button:text-is("ctrl")').evaluate((b) => b.classList.contains("armed"));
  await page.evaluate(() => document.getElementById("keys-strip").scrollLeft = 0);
  await drag("ctrl", 0, 55);
  const armedByDrag = await isArmed();
  await tap("ctrl");
  const armedByTap = await isArmed();
  await tap("←");
  const withCtrl = (await sent()).at(-1);
  await tap("←");
  const afterCtrl = (await sent()).at(-1);
  const sticky = [
    ok(!armedByDrag, "dragging off Ctrl armed it"),
    ok(armedByTap, "tapping Ctrl did not arm it"),
    ok(withCtrl === "\x1b[1;5D", `armed Ctrl did not reach the next key -- got ${JSON.stringify(withCtrl)}`),
    ok(afterCtrl === "\x1b[D", `Ctrl outlived its one key -- got ${JSON.stringify(afterCtrl)}`),
  ].every(Boolean);
  if (sticky) console.log("[6] Ctrl arms on a tap, not on a drag, and lands on exactly the next key");

  // 6b. ...but a MOUSE REPORT is not "the next key". Once a finger
  //     scroll is forwarded to a mouse-tracking app, the reports it
  //     produces come back down the very same onData path a keystroke
  //     takes -- so the naive "any chunk consumes the arming" rule
  //     made an armed Ctrl evaporate the moment the user scrolled
  //     before typing. The report must pass through byte for byte
  //     (a modified mouse report is not a thing) and leave the arming
  //     alone for the key that was actually meant to carry it.
  await tap("ctrl");
  const armedBeforeReport = await isArmed();
  await page.evaluate(() => globalThis.wosh.term.input("\x1b[<65;3;4M"));
  const reportChunk = (await sent()).at(-1);
  await tap("←");
  const afterReport = (await sent()).at(-1);
  if (ok(armedBeforeReport, "tapping Ctrl did not arm it") &&
      ok(reportChunk === "\x1b[<65;3;4M",
         `an armed modifier rewrote a mouse report -- got ${JSON.stringify(reportChunk)}`) &&
      ok(afterReport === "\x1b[1;5D",
         `a mouse report consumed the armed Ctrl before the next key -- got ${JSON.stringify(afterReport)}`)) {
    console.log("[6b] a mouse report passes through untouched and does not spend an armed Ctrl");
  }

  // 7. The press highlight tracks the same rule, so the finger can see
  //    a drag has disarmed the key before it lifts.
  const { x, y } = await box("esc");
  await send("touchStart", points(x, y));
  await page.waitForTimeout(40);
  const litOnDown = await page.locator('#keys button:text-is("esc")').evaluate((b) => b.classList.contains("pressed"));
  await send("touchMove", points(x, y + 40));
  await page.waitForTimeout(40);
  const litAfterTravel = await page.locator('#keys button:text-is("esc")').evaluate((b) => b.classList.contains("pressed"));
  await send("touchEnd", []);
  await page.waitForTimeout(40);
  if (!litOnDown) fail("a held key shows no pressed state (the press has no feedback until it fires)");
  else if (litAfterTravel) fail("a key still looks pressed after the finger dragged off it");
  else console.log("[7] the pressed highlight appears on touch and drops when the finger travels");

  // 8. The keyboard key still toggles. What this leg CANNOT check is
  //    the reason it moved to pointerup: for touch pointers that is the
  //    event carrying user activation (pointerdown is not one), which
  //    is what lets focus() summon the soft keyboard. The stub's
  //    focus() needs no activation and headless Chromium has no soft
  //    keyboard, so that half stays a spec argument -- confirm it on a
  //    real phone when touching this code.
  await page.evaluate(() => globalThis.wosh.term.focus());
  await tap("⌨");
  const afterFirst = await page.evaluate(() => document.activeElement === globalThis.wosh.term.textarea);
  await tap("⌨");
  const afterSecond = await page.evaluate(() => document.activeElement === globalThis.wosh.term.textarea);
  if (afterFirst) fail("⌨ did not dismiss the keyboard (textarea still focused)");
  else if (!afterSecond) fail("⌨ did not bring the keyboard back (textarea not refocused)");
  else console.log("[8] ⌨ still toggles the soft keyboard");

  // 9. A fresh load must leave NOTHING focused on a touch device. The
  //    page asks for a typing focus at startup (and again once a
  //    session connects), but on a phone a programmatic focus() cannot
  //    raise the keyboard -- it only leaves the textarea holding focus
  //    with no keyboard behind it, and from there a tap on the terminal
  //    is a no-op refocus and ⌨ reads the stale focus as "up" and
  //    dismisses. That is the reopened-app bug: taps do nothing until
  //    something defocuses the terminal once. Reload for a pristine
  //    startup state, since the legs above have been moving focus.
  await page.reload({ waitUntil: "load" });
  await page.waitForFunction(() => globalThis.wosh, null, { timeout: 15_000 });
  const focusedAtStart = await page.evaluate(() => document.activeElement === globalThis.wosh.term.textarea);
  await tap("⌨"); // the first thing the user touches after opening the app
  const summoned = await page.evaluate(() => document.activeElement === globalThis.wosh.term.textarea);
  if (focusedAtStart) {
    fail("a fresh load left the terminal focused on a touch device: a focus with no keyboard behind it, which is the state where taps stop summoning");
  } else if (!summoned) {
    fail("the first ⌨ tap after a fresh load did not focus the terminal (it dismissed instead -- the keyboard would not open)");
  } else {
    console.log("[9] a fresh load leaves nothing focused, so the first ⌨ tap summons");
  }

  // 10. ...and the desktop autofocus survives, because there focus IS
  //     typing: a fine pointer implies a real keyboard, and browser-e2e
  //     types into the terminal without clicking it first.
  const desktop = await browser.newContext({ viewport: { width: 1024, height: 768 } });
  const desktopPage = await desktop.newPage();
  await desktopPage.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: "load" });
  await desktopPage.waitForFunction(() => globalThis.wosh, null, { timeout: 15_000 });
  const desktopFocused = await desktopPage.evaluate(() => document.activeElement === globalThis.wosh.term.textarea);
  const barShown = await desktopPage.locator("#keys").isVisible();
  if (!desktopFocused) fail("a fine pointer no longer autofocuses the terminal (a desktop page would open untypable)");
  else if (barShown) fail("the extra-keys bar is visible on a fine pointer (it must stay inert off touch devices)");
  else console.log("[10] a fine pointer still autofocuses the terminal, bar still inert");

  // 10b. THE OPTION MUST STAY OFF a fine pointer: rightClickSelectsWord
  //      is what makes a long-press (contextmenu) select a word, and it
  //      must not leak onto desktop, where a real right-click means the
  //      OS/browser context menu, not a silent selection. Needs a real
  //      xterm (the /terminal fixture), same as the scrolling legs.
  if (!existsSync(join(XTERM_DIR, "xterm/lib/xterm.js"))) {
    fail("site/node_modules/@xterm is missing: run `just web-deps` (leg 10b needs a real xterm)");
  } else {
    await desktopPage.goto(`http://127.0.0.1:${PORT}/terminal`, { waitUntil: "load" });
    await desktopPage.waitForFunction(() => globalThis.wosh?.state, null, { timeout: 15_000 });
    await desktopPage.waitForTimeout(200);
    const dTermBox = await desktopPage.locator("#term").boundingBox();
    const dClient = { x: dTermBox.x + dTermBox.width / 2, y: dTermBox.y + dTermBox.height / 2 };
    await desktopPage.evaluate(({ x, y }) => {
      document.querySelector(".xterm").dispatchEvent(
        new MouseEvent("contextmenu", { clientX: x, clientY: y, bubbles: true, cancelable: true }));
    }, dClient);
    const dHasSelection = await desktopPage.evaluate(() => globalThis.wosh.term.hasSelection());
    // ...and the touch selection overlay must not exist here either:
    // it is the phone's answer to an unselectable canvas, and desktop
    // selects through xterm's own mouse machinery, which works.
    const dOverlay = await desktopPage.evaluate(() => document.querySelectorAll(".touch-select-layer").length);
    // ...and with no overlay there is nothing to defer refits for:
    // guardRefit must be the identity here, or a desktop page would
    // quietly stop refitting the moment anything selected text.
    const dRefits = await desktopPage.evaluate(() => {
      const before = globalThis.wosh.refits;
      globalThis.wosh.refit();
      return { before, after: globalThis.wosh.refits };
    });
    if (ok(!dHasSelection, "a long-press/contextmenu selected a word on a fine pointer (rightClickSelectsWord must stay off desktop)") &&
        ok(dOverlay === 0, `the touch selection overlay mounted on a fine pointer (${dOverlay} layers): it must stay inert off touch devices`) &&
        ok(dRefits.after === dRefits.before + 1, `guardRefit is not passing refits straight through on a fine pointer (${dRefits.before} -> ${dRefits.after})`)) {
      console.log("[10b] a fine pointer keeps rightClickSelectsWord at its default: no selection from a contextmenu, no touch overlay, refits pass straight through");
    }
  }
  await desktop.close();

  // --- scrolling, against a real terminal ------------------------------
  //
  // xterm scrolls for a mouse and a wheel, not for a finger: the
  // scrollbar it draws answers to mousedown, its touch-gesture support
  // is never registered, and .xterm-viewport is not natively scrollable
  // (scrollHeight == clientHeight -- the renderer owns the position).
  // So every one of these legs measured NOTHING moving before
  // mobile.mjs took the gesture on, while the page moved instead.
  if (!existsSync(join(XTERM_DIR, "xterm/lib/xterm.js"))) {
    fail("site/node_modules/@xterm is missing: run `just web-deps` (the scrolling legs need a real xterm)");
  } else {
    await page.goto(`http://127.0.0.1:${PORT}/terminal`, { waitUntil: "load" });
    await page.waitForFunction(() => globalThis.wosh?.state, null, { timeout: 15_000 });
    await page.waitForTimeout(400);
    const tstate = () => page.evaluate(() => globalThis.wosh.state());
    const termBox = await page.locator("#term").boundingBox();
    const mid = { x: termBox.x + termBox.width / 2, y: termBox.y + termBox.height / 2 };

    let t0 = await tstate();
    if (!ok(t0.baseY > 50, `the fixture has no scrollback to drag (baseY=${t0.baseY})`) ||
        !ok(t0.docScrollable, "the fixture page cannot scroll, so 'the page must not move' would prove nothing")) {
      // fall through: the legs below would be meaningless
    } else {
      // 11. A finger drags the scrollback, and by the distance it
      //     travelled -- the text follows the finger.
      const dragPx = 200;
      await dragAt(mid.x, mid.y, 0, dragPx);
      let t1 = await tstate();
      const expected = Math.round(dragPx / t0.cellHeight);
      const moved = t0.viewportY - t1.viewportY;
      if (!ok(moved > 0, `a finger dragged down the terminal and nothing scrolled (viewportY stayed ${t1.viewportY})`)) {
        // no point measuring how far
      } else if (ok(Math.abs(moved - expected) <= 2, `the text did not follow the finger: ${dragPx}px moved ${moved} lines, expected ~${expected}`)) {
        console.log(`[11] a finger drags the scrollback ${moved} lines for ${dragPx}px (~1 line per cell)`);
      }

      // 12. THE REPORT: the gesture never reaches the browser's own
      //     panning. Dragging UP is the direction that can move this
      //     page (it sits at scrollY 0, so a downward drag has nowhere
      //     to go and would prove nothing), and the terminal is put
      //     mid-scrollback first so it has somewhere to go too.
      await page.evaluate(() => globalThis.wosh.term.scrollLines(-40));
      await page.waitForTimeout(150);
      const t2 = await tstate();
      await dragAt(mid.x, mid.y, 0, -150);
      const t3 = await tstate();
      const forward = t3.viewportY > t2.viewportY;
      if (ok(t3.pageScrollY === 0, `the drag scrolled the PAGE instead of the terminal (scrollY=${t3.pageScrollY})`) &&
          ok(forward, `dragging up did not scroll the terminal forward (${t2.viewportY} -> ${t3.viewportY})`)) {
        console.log("[12] dragging up scrolls the terminal forward and leaves the page at 0");
      }

      // 13. A scroll must not also land as a tap -- the keyboard
      //     leaping up at the end of every drag is its own bug.
      if (ok(!(await page.evaluate(() => globalThis.wosh.focused())), "a scroll gesture focused the terminal (the soft keyboard would open)")) {
        console.log("[13] scrolling does not summon the keyboard");
      }

      // 14. ...while a tap still does, which is how it is summoned.
      await page.evaluate(() => globalThis.wosh.term.blur());
      await send("touchStart", points(mid.x, mid.y));
      await page.waitForTimeout(60);
      await send("touchEnd", []);
      await page.waitForTimeout(250);
      if (ok(await page.evaluate(() => globalThis.wosh.focused()), "a tap on the terminal no longer focuses it (the keyboard could not be summoned)")) {
        console.log("[14] a tap still focuses the terminal");
      }

      // 15. The scrollbar the report was about. Asserting the THUMB
      //     mapping, not merely that something moved: a thumb drag
      //     covers the whole scrollback across the track it can
      //     travel, so 90px of thumb is many more lines than 90px of
      //     content. Measuring only the direction let this leg pass
      //     against a terminal that ignores the finger entirely.
      await page.evaluate(() => { window.scrollTo(0, 0); globalThis.wosh.term.scrollToBottom(); });
      await page.evaluate(() => globalThis.wosh.term.scrollLines(-Math.floor(globalThis.wosh.state().baseY / 2)));
      await page.waitForTimeout(200);
      const sb = await page.evaluate(() => globalThis.wosh.scrollbar());
      if (!ok(Boolean(sb.slider), "xterm drew no vertical scrollbar thumb to drag")) {
        // nothing to grab
      } else {
        const before = (await tstate()).viewportY;
        const thumbPx = 90;
        const perPx = before > 0 ? (await tstate()).baseY / (sb.bar.h - sb.slider.h) : 0;
        const expected = Math.round(thumbPx * perPx);
        await dragAt(sb.slider.x + sb.slider.w / 2, sb.slider.y + sb.slider.h / 2, 0, thumbPx);
        const after = (await tstate()).viewportY;
        const moved = after - before;
        if (ok(moved > 0, `dragging the scrollbar thumb down did not scroll forward (${before} -> ${after})`) &&
            ok(Math.abs(moved - expected) <= Math.max(3, expected * 0.25),
               `the thumb did not carry the scrollback with it: ${thumbPx}px moved ${moved} lines, expected ~${expected}`)) {
          console.log(`[15] the scrollbar thumb drags the scrollback ${moved} lines for ${thumbPx}px (expected ~${expected})`);
        }
      }

      // 16. Only VERTICAL drags are ours. A sideways one stays the
      //     browser's, which on iOS is where the back gesture comes
      //     from -- and it starts at the screen edge, over the
      //     terminal.
      await page.evaluate(() => globalThis.wosh.term.scrollLines(-30));
      await page.waitForTimeout(150);
      const sideways0 = (await tstate()).viewportY;
      await dragAt(mid.x, mid.y, 160, 0);
      const sideways1 = (await tstate()).viewportY;
      if (ok(sideways0 === sideways1, `a sideways drag scrolled the terminal (${sideways0} -> ${sideways1})`)) {
        console.log("[16] a sideways drag is left to the browser");
      }

      // 17. And xterm keeps the mouse: we took the finger, nothing else.
      await page.evaluate(() => globalThis.wosh.term.scrollToBottom());
      const sb2 = await page.evaluate(() => globalThis.wosh.scrollbar());
      if (sb2.slider) {
        const before = (await tstate()).viewportY;
        await page.mouse.move(sb2.slider.x + sb2.slider.w / 2, sb2.slider.y + sb2.slider.h / 2);
        await page.mouse.down();
        for (let i = 1; i <= 8; i++) await page.mouse.move(sb2.slider.x + sb2.slider.w / 2, sb2.slider.y + sb2.slider.h / 2 - i * 12);
        await page.mouse.up();
        await page.waitForTimeout(200);
        const after = (await tstate()).viewportY;
        if (ok(after < before, `xterm's own mouse drag on the thumb stopped working (${before} -> ${after})`)) {
          console.log("[17] xterm still owns the mouse: its thumb drag is untouched");
        }
      }

      // 18. The terminal moves ITSELF while a finger is down: output
      //     arriving while the view sits at the bottom carries it
      //     along. A drag that remembers an absolute position from
      //     where the finger landed goes dead that many lines short of
      //     the top; measuring the finger absolutely but applying it as
      //     a delta against the live position does not. Small
      //     scrollback here so one drag can reach the top at all.
      await page.evaluate(() => {
        const t = globalThis.wosh.term;
        t.clear();
        for (let i = 0; i < t.rows + 15; i++) t.write("pre " + i + "\r\n");
      });
      await page.waitForTimeout(400); // xterm parses writes off the main path
      await page.evaluate(() => globalThis.wosh.term.scrollToBottom());
      await page.waitForTimeout(200);
      const t6 = await tstate();
      if (ok(t6.baseY > 5 && t6.viewportY === t6.baseY, `leg 18 needs a small scrollback sitting at the bottom (viewportY=${t6.viewportY} baseY=${t6.baseY})`)) {
        await send("touchStart", points(mid.x, mid.y));
        await page.waitForTimeout(40);
        // ...output lands mid-gesture, and the view follows it down.
        await page.evaluate(() => {
          for (let i = 0; i < 10; i++) globalThis.wosh.term.write("late " + i + "\r\n");
        });
        await page.waitForTimeout(200);
        const drop = (t6.baseY + 12) * t6.cellHeight; // more than enough to hit the top
        for (let i = 1; i <= 16; i++) {
          await send("touchMove", points(mid.x, mid.y + (drop * i) / 16));
          await page.waitForTimeout(14);
        }
        await send("touchEnd", []);
        await page.waitForTimeout(250);
        const t7 = await tstate();
        if (ok(t7.viewportY === 0, `output arriving mid-drag left the gesture ${t7.viewportY} lines short of the top`)) {
          console.log("[18] a drag still reaches the top when output moves the view under it");
        }
      }

      // --- long-press selection (site/mobile.mjs: initLongPressSelect) --
      //
      // xterm's selection answers only to a mouse and the screen is an
      // unselectable canvas, so a phone has no way to select terminal
      // text at all -- UNLESS Android's long-press contextmenu is wired
      // through rightClickSelectsWord. A synthetic contextmenu stands in
      // for the real long-press (Chromium dispatches one at the finger
      // on Android; CDP touch events do not reach that platform code in
      // headless Linux Chromium, so this is the same substitution the
      // background doc names).
      await page.evaluate(() => { globalThis.wosh.term.write("alpha bravo charlie\r\n"); globalThis.wosh.term.scrollToBottom(); });
      await page.waitForFunction(
        () => globalThis.wosh.term.buffer.active.getLine(
          globalThis.wosh.term.buffer.active.baseY + globalThis.wosh.term.buffer.active.cursorY - 1,
        )?.translateToString(true) === "alpha bravo charlie",
        null, { timeout: 5_000 },
      );

      // The written line sits one row above the cursor's resting row
      // (the \r\n advanced past it); translate buffer-absolute to
      // on-screen via viewportY, then buffer-cell to pixel via the
      // screen's own box -- never a hardcoded row.
      const wordPoint = async (col, len) => {
        const st = await page.evaluate(() => {
          const buf = globalThis.wosh.term.buffer.active;
          const row = buf.baseY + buf.cursorY - 1;
          return { row, viewportY: buf.viewportY, cellHeight: globalThis.wosh.state().cellHeight };
        });
        const screen = await page.locator(".xterm-screen").boundingBox();
        const cellWidth = screen.width / (await page.evaluate(() => globalThis.wosh.term.cols));
        const viewRow = st.row - st.viewportY;
        return {
          x: screen.x + (col + len / 2) * cellWidth,
          y: screen.y + (viewRow + 0.5) * st.cellHeight,
        };
      };

      // 18b. THE CONTRACT: a long-press (contextmenu) selects the word
      //      under the finger, and mirrors it into xterm's hidden
      //      textarea -- the thing Android's floating Copy toolbar
      //      actually copies from.
      const bravoPt = await wordPoint(6, 5); // "alpha "=6 cols, "bravo"=5
      await page.evaluate(({ x, y }) => {
        document.querySelector(".xterm").dispatchEvent(
          new MouseEvent("contextmenu", { clientX: x, clientY: y, bubbles: true, cancelable: true }));
      }, bravoPt);
      const sel18b = await page.evaluate(() => globalThis.wosh.term.getSelection());
      const activeIsTextarea = await page.evaluate(() => document.activeElement === globalThis.wosh.term.textarea);
      const textareaVal = await page.evaluate(() => globalThis.wosh.term.textarea.value);
      if (ok(sel18b === "bravo", `long-press (contextmenu) did not select the word under the finger -- got ${JSON.stringify(sel18b)}`) &&
          ok(activeIsTextarea, "long-press did not focus xterm's hidden textarea (the platform Copy toolbar acts on focus)") &&
          ok(textareaVal === "bravo", `the selected word was not mirrored into the textarea the Copy toolbar reads -- got ${JSON.stringify(textareaVal)}`)) {
        console.log("[18b] a long-press selects the word under the finger and mirrors it into the textarea");
      }
      await page.evaluate(() => globalThis.wosh.term.clearSelection());

      // 18c. A long-press INSIDE an existing selection keeps it, rather
      //      than collapsing it to the one word under the finger
      //      (upstream rightClickSelect semantics).
      await page.evaluate(() => {
        const buf = globalThis.wosh.term.buffer.active;
        const row = buf.baseY + buf.cursorY - 1;
        globalThis.wosh.term.select(6, row, 13); // "bravo charlie" (13 cols)
      });
      const insidePt = await wordPoint(6, 13);
      await page.evaluate(({ x, y }) => {
        document.querySelector(".xterm").dispatchEvent(
          new MouseEvent("contextmenu", { clientX: x, clientY: y, bubbles: true, cancelable: true }));
      }, insidePt);
      const sel18c = await page.evaluate(() => globalThis.wosh.term.getSelection());
      if (ok(sel18c === "bravo charlie", `a long-press inside an existing selection collapsed it to one word -- got ${JSON.stringify(sel18c)}`)) {
        console.log("[18c] a long-press inside an existing selection keeps it");
      }
      await page.evaluate(() => globalThis.wosh.term.clearSelection());

      // 18d. The other selection gesture -- double-tap -- still selects
      //      a word (xterm's compat dblclick path, unaffected by the
      //      rightClickSelectsWord wiring above).
      const alphaPt = await wordPoint(0, 5); // "alpha" starts at col 0
      await send("touchStart", points(alphaPt.x, alphaPt.y));
      await page.waitForTimeout(50);
      await send("touchEnd", []);
      await page.waitForTimeout(80);
      await send("touchStart", points(alphaPt.x, alphaPt.y));
      await page.waitForTimeout(50);
      await send("touchEnd", []);
      await page.waitForTimeout(400);
      const sel18d = await page.evaluate(() => globalThis.wosh.term.getSelection());
      if (ok(sel18d === "alpha", `a double-tap did not select the word under the finger -- got ${JSON.stringify(sel18d)}`)) {
        console.log("[18d] a double-tap selects the word under the finger");
      }
      await page.evaluate(() => globalThis.wosh.term.clearSelection());

      // --- the touch selection overlay (site/touch-select.mjs) ---------
      //
      // The word-granularity contextmenu path above is all a phone had.
      // The overlay supersedes it: an invisible, selectable DOM mirror
      // of the visible viewport, mounted inside .xterm-screen, so the
      // PLATFORM's own selection machinery has real text to work on --
      // arbitrary ranges, drag handles, the floating Copy toolbar.
      // These legs pin the mirror's fidelity, its geometry, the freeze
      // that keeps live output from moving text out from under a
      // highlight, and the copy that keeps soft wraps from becoming
      // hard newlines.

      // Which visual row of the overlay a given buffer row sits on, and
      // what the overlay put there. The rows live one level down, on
      // the SHEET: the layer stays the clip box (fixed px size,
      // overflow hidden) so that translating the sheet -- which is how
      // a held selection stays glued to its buffer lines -- does not
      // drag the clip region along with it.
      const overlay = async () => page.evaluate(() => {
        const term = globalThis.wosh.term;
        const layer = document.querySelector(".xterm-screen > .touch-select-layer");
        const sheet = layer?.querySelector(":scope > .touch-select-sheet");
        if (!layer || !sheet) return null;
        const buf = term.buffer.active;
        return {
          hasSheet: Boolean(sheet),
          rowCount: sheet.children.length,
          termRows: term.rows,
          userSelect: getComputedStyle(layer).userSelect || getComputedStyle(layer).webkitUserSelect,
          texts: [...sheet.children].map((d) => d.textContent),
          viewportY: buf.viewportY,
          markerViewRow: buf.baseY + buf.cursorY - 1 - buf.viewportY,
          markerBufferText: buf.getLine(buf.baseY + buf.cursorY - 1)?.translateToString(false) ?? null,
        };
      });

      // 18e. The mirror exists where it has to (a CHILD of
      //      .xterm-screen -- see 18k), with its rows on the inner
      //      sheet, is selectable despite .xterm's user-select: none,
      //      and reproduces the buffer line character for character.
      //      UNtrimmed: offsets in the mirror must map 1:1 onto
      //      terminal columns.
      const o18e = await overlay();
      if (!ok(Boolean(o18e), "no .touch-select-layer > .touch-select-sheet inside .xterm-screen: the overlay did not mount under a coarse pointer, or its rows are not on a translatable sheet")) {
        // the legs below have nothing to measure
      } else if (
        ok(o18e.hasSheet, "the overlay rows are not under a .touch-select-sheet: translating the layer itself would move its own clip region") &&
        ok(o18e.rowCount === o18e.termRows, `the overlay has ${o18e.rowCount} rows for a ${o18e.termRows}-row terminal`) &&
        ok(o18e.userSelect === "text", `the overlay is not selectable (user-select: ${o18e.userSelect}); .xterm's user-select: none would win`) &&
        ok(o18e.texts[o18e.markerViewRow] === o18e.markerBufferText,
           `the overlay row does not mirror its buffer line:\n    overlay ${JSON.stringify(o18e.texts[o18e.markerViewRow])}\n    buffer  ${JSON.stringify(o18e.markerBufferText)}`)
      ) {
        console.log(`[18e] the overlay mirrors the viewport: ${o18e.rowCount} selectable rows, marker row exact`);
      }

      // 18e2. ...and the page chrome around it is NOT selectable. A
      //       selection handle dragged off the top of the terminal has
      //       to land somewhere: with #bar selectable the platform
      //       extends the selection into the header's own labels, so
      //       the controls light up and nothing scrolls (the narrow
      //       margin between bar and terminal worked precisely because
      //       it holds no text). Unselectable, the drag clamps to the
      //       nearest selectable position -- the mirror's edge row --
      //       which is what arms the ratchet. Same story for #keys
      //       below the terminal, where the blank area left by a
      //       deferred refit sits directly above the key labels. This
      //       fixture lifts index.html's real <style>, so the rule
      //       under test is the page's own.
      const chromeSelect = await page.evaluate(() => {
        const of = (id) => {
          const cs = getComputedStyle(document.getElementById(id));
          return cs.userSelect || cs.webkitUserSelect;
        };
        return { bar: of("bar"), keys: of("keys") };
      });
      if (ok(chromeSelect.bar === "none", `#bar is selectable (user-select: ${chromeSelect.bar}): a handle dragged above the terminal would highlight the header controls`) &&
          ok(chromeSelect.keys === "none", `#keys is selectable (user-select: ${chromeSelect.keys}): a handle dragged below the terminal would highlight the key labels`)) {
        console.log("[18e2] the chrome bars are unselectable, so a drag off either edge clamps to the mirror");
      }

      // 18f. The geometry that makes a highlight land on the glyphs it
      //      is highlighting: rows sit on cell boundaries, and one DOM
      //      character advances exactly one cell (the letter-spacing
      //      math -- font advance alone is off by a fraction that
      //      compounds across a row).
      const geo = await page.evaluate(() => {
        const term = globalThis.wosh.term;
        const sheet = document.querySelector(".xterm-screen > .touch-select-layer > .touch-select-sheet");
        const screen = document.querySelector(".xterm-screen").getBoundingClientRect();
        const buf = term.buffer.active;
        const viewRow = buf.baseY + buf.cursorY - 1 - buf.viewportY;
        const div = sheet.children[viewRow];
        const cellW = screen.width / term.cols;
        const cellH = screen.height / term.rows;
        // "alpha bravo charlie" is 19 characters starting at column 0.
        const range = document.createRange();
        range.setStart(div.firstChild, 0);
        range.setEnd(div.firstChild, 19);
        const runW = range.getBoundingClientRect().width;
        range.detach?.();
        return {
          top: div.getBoundingClientRect().top,
          expectedTop: screen.y + viewRow * cellH,
          runW,
          expectedRunW: 19 * cellW,
        };
      });
      if (ok(Math.abs(geo.top - geo.expectedTop) <= 1.5,
             `the overlay row is not on its cell row: top ${geo.top.toFixed(2)}, expected ${geo.expectedTop.toFixed(2)}`) &&
          ok(Math.abs(geo.runW - geo.expectedRunW) <= 2,
             `one overlay character does not advance one cell: 19 chars measured ${geo.runW.toFixed(2)}px, expected ${geo.expectedRunW.toFixed(2)}px`)) {
        console.log(`[18f] the overlay is on the cell grid: 19 chars span ${geo.runW.toFixed(1)}px vs ${geo.expectedRunW.toFixed(1)}px of cells`);
      }

      // 18g. It tracks live output -- the mirror is only useful if it
      //      is current when the finger lands.
      await page.evaluate(() => {
        globalThis.wosh.term.write("delta echo foxtrot\r\n");
        globalThis.wosh.term.scrollToBottom();
      });
      await page.waitForTimeout(300);
      await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
      const synced = await page.evaluate(() =>
        [...document.querySelector(".touch-select-sheet").children].some((d) =>
          d.textContent.includes("delta echo foxtrot")));
      if (ok(synced, "fresh output never reached the overlay: a finger would select stale text")) {
        console.log("[18g] the overlay follows live output");
      }

      // Build a REAL DOM selection over a run of an overlay row -- what
      // the platform's long-press produces, and the only way to get one
      // in headless Chromium.
      const selectRun = (viewRow, from, to) => page.evaluate(({ viewRow, from, to }) => {
        const div = document.querySelector(".touch-select-sheet").children[viewRow];
        const range = document.createRange();
        range.setStart(div.firstChild, from);
        range.setEnd(div.firstChild, to);
        const sel = document.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        return sel.toString();
      }, { viewRow, from, to });

      // 18h. THE FREEZE: while the platform holds a selection over the
      //      mirror, the mirror stops updating. Output arriving
      //      underneath would otherwise rewrite the very characters the
      //      highlight is drawn around -- the user watches their
      //      selection quietly become a selection of something else,
      //      and copies text they never highlighted. The change below
      //      repaints row 0 in place (save cursor / home / write /
      //      restore) so viewportY never moves and this leg is about
      //      the freeze alone, not about scrolling.
      const markerRow = (await overlay()).markerViewRow;
      const held = await selectRun(markerRow, 6, 10); // "echo" in "delta echo foxtrot"
      await page.waitForTimeout(150);
      const row0Before = await page.evaluate(() =>
        document.querySelector(".touch-select-sheet").children[0].textContent);
      await page.evaluate(() => globalThis.wosh.term.write("\x1b[s\x1b[H*CHANGED*\x1b[u"));
      await page.waitForTimeout(300);
      await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
      const frozenRow0 = await page.evaluate(() => ({
        overlay: document.querySelector(".touch-select-sheet").children[0].textContent,
        buffer: globalThis.wosh.term.buffer.active
          .getLine(globalThis.wosh.term.buffer.active.viewportY)?.translateToString(false),
        selection: document.getSelection().toString(),
      }));
      await page.evaluate(() => document.getSelection().removeAllRanges());
      await page.waitForTimeout(150);
      await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
      const thawedRow0 = await page.evaluate(() =>
        document.querySelector(".touch-select-sheet").children[0].textContent);
      if (ok(held === "echo", `the test selection did not take (got ${JSON.stringify(held)})`) &&
          ok(frozenRow0.buffer.startsWith("*CHANGED*"), "the in-place repaint never reached the buffer, so this leg proves nothing") &&
          ok(frozenRow0.overlay === row0Before,
             `the overlay updated under a live selection (row 0 became ${JSON.stringify(frozenRow0.overlay)}): the highlight would slide onto other text`) &&
          ok(frozenRow0.selection === held, "the selection did not survive the output it was supposed to freeze out") &&
          ok(thawedRow0.startsWith("*CHANGED*"),
             `the overlay stayed frozen after the selection was dropped (row 0 is ${JSON.stringify(thawedRow0)})`)) {
        console.log("[18h] a live selection freezes the overlay, and releasing it resyncs");
      }

      // 18i. Scrolling KEEPS the selection. The mirror stops tracking
      //      the viewport the moment a selection is held and anchors
      //      itself to BUFFER rows instead: the frozen rows keep their
      //      text, an inner sheet is translated so they stay glued to
      //      the lines they came from, and the rows the viewport
      //      uncovers are revealed at the edge. That is what lets a
      //      selection run past the bottom of the screen -- and it is
      //      why the layer stays the clip box while the SHEET moves:
      //      a transform on the layer would carry its own clip region
      //      along with the rows.
      const scrollRow = (await overlay()).markerViewRow;
      const held18i = await selectRun(scrollRow, 0, 5);
      await page.waitForTimeout(150);
      const beforeScroll = await page.evaluate(() => ({
        viewportY: globalThis.wosh.term.buffer.active.viewportY,
        rowCount: document.querySelector(".touch-select-sheet").children.length,
        texts: [...document.querySelector(".touch-select-sheet").children].map((d) => d.textContent),
        cellHeight: globalThis.wosh.state().cellHeight,
      }));
      await page.evaluate(() => globalThis.wosh.term.scrollLines(-3));
      await page.waitForTimeout(250);
      await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
      const afterScroll = await page.evaluate(() => {
        const term = globalThis.wosh.term;
        const buf = term.buffer.active;
        const sheet = document.querySelector(".touch-select-sheet");
        const tf = getComputedStyle(sheet).top;
        return {
          selectionText: document.getSelection().toString(),
          viewportY: buf.viewportY,
          rowCount: sheet.children.length,
          // The sheet is moved by LAYOUT, not by a transform: a
          // composited offset never invalidates the boxes the platform
          // derives its selection handles from, which is what left them
          // stranded mid-pan on a real phone.
          offsetTop: tf === "auto" ? 0 : parseFloat(tf),
          revealed: [0, 1, 2].map((i) => sheet.children[i].textContent),
          revealedBuffer: [0, 1, 2].map((i) => buf.getLine(buf.viewportY + i)?.translateToString(false) ?? ""),
          texts: [...sheet.children].map((d) => d.textContent),
        };
      });
      const kept = afterScroll.texts.slice(3).join("\n") === beforeScroll.texts.join("\n");
      if (ok(held18i === "delta", `the test selection did not take (got ${JSON.stringify(held18i)})`) &&
          ok(afterScroll.viewportY === beforeScroll.viewportY - 3, `the scroll did not move the viewport (${beforeScroll.viewportY} -> ${afterScroll.viewportY})`) &&
          ok(afterScroll.selectionText === held18i,
             `scrolling dropped the selection instead of carrying it into the scrollback (${JSON.stringify(afterScroll.selectionText)})`) &&
          ok(Math.abs(afterScroll.offsetTop) <= 1,
             `the sheet is not glued to the buffer lines it mirrors: top ${afterScroll.offsetTop.toFixed(2)}px, expected 0 once the revealed rows are prepended`) &&
          ok(afterScroll.rowCount === beforeScroll.rowCount + 3,
             `the mirror did not grow by the 3 rows the scroll uncovered (${beforeScroll.rowCount} -> ${afterScroll.rowCount})`) &&
          ok(afterScroll.revealed.join("\n") === afterScroll.revealedBuffer.join("\n"),
             `the revealed rows do not mirror their buffer lines:\n    overlay ${JSON.stringify(afterScroll.revealed)}\n    buffer  ${JSON.stringify(afterScroll.revealedBuffer)}`) &&
          ok(kept, "the frozen rows were rewritten when the mirror grew: a Range endpoint lives in those text nodes, and replacing the data collapses it")) {
        console.log("[18i] scrolling carries the selection into the scrollback: rows revealed at the edge, frozen rows untouched");
      }

      // ...and the same selection still held, scrolled BACK: the sheet
      // is what keeps the mirrored lines over their own glyphs. The
      // rows it needs already exist now, so nothing is revealed and the
      // offset alone does the work -- which is the direction that shows
      // the offset doing anything at all. (The invariant is
      // (top - viewportY) * cellH where `top` is the buffer
      // line rows[0] holds: revealing UPWARD walks `top` down to meet
      // viewportY, so that direction legitimately lands on 0.)
      await page.evaluate(() => globalThis.wosh.term.scrollLines(3));
      await page.waitForTimeout(250);
      const backScroll = await page.evaluate(() => {
        const sheet = document.querySelector(".touch-select-sheet");
        const tf = getComputedStyle(sheet).top;
        return {
          offsetTop: tf === "auto" ? 0 : parseFloat(tf),
          rowCount: sheet.children.length,
          selectionText: document.getSelection().toString(),
        };
      });
      if (ok(Math.abs(backScroll.offsetTop + 3 * beforeScroll.cellHeight) <= 1,
             `the sheet did not slide back with the viewport: top ${backScroll.offsetTop.toFixed(2)}px, expected ${(-3 * beforeScroll.cellHeight).toFixed(2)}px`) &&
          ok(backScroll.rowCount === afterScroll.rowCount,
             `scrolling back grew the mirror again (${afterScroll.rowCount} -> ${backScroll.rowCount}): those rows were already mounted`) &&
          ok(backScroll.selectionText === held18i, "scrolling back dropped the selection")) {
        console.log(`[18i] scrolling back slides the sheet by layout (top ${backScroll.offsetTop.toFixed(0)}px) instead of remounting rows`);
      }

      // ...and releasing it puts the mirror back on the viewport: the
      // sheet un-translates and the extra rows are trimmed.
      await page.evaluate(() => document.getSelection().removeAllRanges());
      await page.waitForTimeout(200);
      await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
      const thawed18i = await page.evaluate(() => {
        const buf = globalThis.wosh.term.buffer.active;
        const sheet = document.querySelector(".touch-select-sheet");
        const tf = getComputedStyle(sheet).top;
        return {
          offsetTop: tf === "auto" ? 0 : parseFloat(tf),
          rowCount: sheet.children.length,
          termRows: globalThis.wosh.term.rows,
          row0: sheet.children[0].textContent,
          bufferRow0: buf.getLine(buf.viewportY)?.translateToString(false) ?? "",
        };
      });
      if (ok(Math.abs(thawed18i.offsetTop) <= 0.5, `the sheet stayed offset after the selection was dropped (top ${thawed18i.offsetTop}px)`) &&
          ok(thawed18i.rowCount === thawed18i.termRows, `the mirror kept its scrollback rows after release (${thawed18i.rowCount} rows for ${thawed18i.termRows})`) &&
          ok(thawed18i.row0 === thawed18i.bufferRow0,
             `the overlay did not resync to the viewport:\n    overlay ${JSON.stringify(thawed18i.row0)}\n    buffer  ${JSON.stringify(thawed18i.bufferRow0)}`)) {
        console.log("[18i] releasing it re-anchors the mirror on the viewport and trims it back");
      }
      await page.evaluate(() => globalThis.wosh.term.scrollToBottom());
      await page.waitForTimeout(200);

      // 18i2. COPY ACROSS THE SEAM: a selection that spans revealed
      //       scrollback and on-screen rows copies the buffer lines it
      //       covers, joined by the same rules as any other copy. The
      //       whole point of anchoring to buffer rows is that what
      //       lands on the clipboard is what was highlighted -- across
      //       the seam where the mirror grew, not just within one
      //       screenful.
      const seamRow = (await overlay()).markerViewRow;
      const topAbs = await page.evaluate(() => globalThis.wosh.term.buffer.active.viewportY);
      await selectRun(seamRow, 0, 5);
      await page.waitForTimeout(150);
      await page.evaluate(() => globalThis.wosh.term.scrollLines(-3));
      await page.waitForTimeout(250);
      const seam = await page.evaluate((topAbs) => {
        const term = globalThis.wosh.term;
        const buf = term.buffer.active;
        const layer = document.querySelector(".touch-select-layer");
        const sheet = layer.querySelector(".touch-select-sheet");
        if (typeof ClipboardEvent !== "function" || typeof DataTransfer !== "function") {
          return { error: "this Chromium cannot construct ClipboardEvent/DataTransfer; leg 18i2 cannot run" };
        }
        // The marker line, in the sheet's buffer-row coordinates: the
        // sheet's row 0 is `topAbs` minus however many rows were
        // revealed above it.
        const markerAbs = buf.baseY + buf.cursorY - 1;
        const firstAbs = buf.viewportY; // the topmost revealed row
        const idx = (abs) => abs - firstAbs;
        const startDiv = sheet.children[0]; // a row that only exists because we scrolled
        const endDiv = sheet.children[idx(markerAbs)];
        const range = document.createRange();
        range.setStart(startDiv.firstChild, 0);
        range.setEnd(endDiv.firstChild, endDiv.textContent.length);
        const sel = document.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        const ev = new ClipboardEvent("copy", {
          clipboardData: new DataTransfer(),
          bubbles: true,
          cancelable: true,
        });
        layer.dispatchEvent(ev);
        // What the BUFFER says those rows are -- computed from the
        // terminal, not from the mirror, so this cannot pass by the
        // mirror merely agreeing with itself.
        const expected = [];
        for (let abs = firstAbs; abs <= markerAbs; abs++) {
          expected.push((buf.getLine(abs)?.translateToString(false) ?? "").trimEnd());
        }
        return {
          text: ev.clipboardData.getData("text/plain"),
          defaultPrevented: ev.defaultPrevented,
          expected: expected.join("\n"),
          spanned: markerAbs - firstAbs + 1,
          revealedRows: topAbs - firstAbs,
        };
      }, topAbs);
      if (seam.error) {
        fail(seam.error);
      } else if (ok(seam.revealedRows === 3, `leg 18i2 did not copy across a seam: ${seam.revealedRows} rows were revealed by the scroll, expected 3`) &&
                 ok(seam.defaultPrevented, "the copy handler let the browser's default through for a selection spanning the seam") &&
                 ok(seam.text === seam.expected,
                    `the copy across the seam is not the buffer lines it covered:\n    got      ${JSON.stringify(seam.text)}\n    expected ${JSON.stringify(seam.expected)}`)) {
        console.log(`[18i2] a selection spanning revealed scrollback copies all ${seam.spanned} buffer rows it covers`);
      }
      await page.evaluate(() => document.getSelection().removeAllRanges());
      await page.waitForTimeout(200);
      await page.evaluate(() => globalThis.wosh.term.scrollToBottom());
      await page.waitForTimeout(200);

      // 18i3. THE EDGE RATCHET: dragging a handle onto the top visible
      //       row scrolls the terminal, so a selection can be extended
      //       past the edge of the screen. Native handle drags cannot
      //       be synthesized in headless Chromium (the browser consumes
      //       the drag's touch events itself), so Selection.extend()
      //       stands in for the handle -- it produces the same
      //       selectionchange stream, which is all the ratchet reads.
      //
      //       Keyed on the focus endpoint changing ROWS, not on it
      //       sitting at the edge: a timer keyed on position would run
      //       away on a finished selection whose end happens to rest
      //       there, and there is no way to know a handle is still
      //       down.
      await page.evaluate(() => globalThis.wosh.term.scrollLines(-10));
      await page.waitForTimeout(200);
      const ratchetStart = await page.evaluate(() => {
        const sheet = document.querySelector(".touch-select-sheet");
        const div = sheet.children[2]; // view row 2: two rows clear of the edge
        const range = document.createRange();
        range.setStart(div.firstChild, 0);
        range.setEnd(div.firstChild, Math.min(4, div.textContent.length));
        const sel = document.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        return globalThis.wosh.term.buffer.active.viewportY;
      });
      await page.waitForTimeout(150); // selectionchange is async: let the freeze land
      // A handle dragged up one row: a transition, but not onto the
      // edge row, so nothing should scroll yet.
      await page.evaluate(() => {
        const sheet = document.querySelector(".touch-select-sheet");
        document.getSelection().extend(sheet.children[1].firstChild, 2);
      });
      await page.waitForTimeout(150);
      const midRatchet = await page.evaluate(() => globalThis.wosh.term.buffer.active.viewportY);
      // ...and onto the top visible row, which is the trigger.
      await page.evaluate(() => {
        const sheet = document.querySelector(".touch-select-sheet");
        document.getSelection().extend(sheet.children[0].firstChild, 0);
      });
      await page.waitForTimeout(200); // longer than the 80ms rate cap
      const afterRatchet = await page.evaluate(() => ({
        viewportY: globalThis.wosh.term.buffer.active.viewportY,
        selection: document.getSelection().toString(),
      }));
      if (ok(midRatchet === ratchetStart, `a handle moved onto a row that is not the edge scrolled the terminal (${ratchetStart} -> ${midRatchet})`) &&
          ok(afterRatchet.viewportY === ratchetStart - 2,
             `dragging a handle onto the top visible row did not ratchet the view by one step (${ratchetStart} -> ${afterRatchet.viewportY}, expected ${ratchetStart - 2})`) &&
          ok(afterRatchet.selection !== "", "the ratchet dropped the selection it was supposed to be extending")) {
        console.log(`[18i3] a handle dragged onto the top row ratchets the view (${ratchetStart} -> ${afterRatchet.viewportY}), and only on a row transition`);
      }
      await page.evaluate(() => document.getSelection().removeAllRanges());
      await page.waitForTimeout(200);

      // ...and the NEGATIVE: a selection that is BORN on the edge row
      // -- a long-press there -- must not scroll. There was no
      // previous row for the handle to have come from, and a
      // long-press that yanked the view out from under itself would be
      // unusable.
      const fresh = await page.evaluate(() => {
        const before = globalThis.wosh.term.buffer.active.viewportY;
        const sheet = document.querySelector(".touch-select-sheet");
        const div = sheet.children[0];
        const range = document.createRange();
        range.setStart(div.firstChild, 0);
        range.setEnd(div.firstChild, Math.min(4, div.textContent.length));
        const sel = document.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        return before;
      });
      await page.waitForTimeout(250);
      const afterFresh = await page.evaluate(() => globalThis.wosh.term.buffer.active.viewportY);
      if (ok(afterFresh === fresh, `a fresh selection on the top row scrolled the terminal on its own (${fresh} -> ${afterFresh})`)) {
        console.log("[18i3] a fresh selection on the edge row does not ratchet: only a handle ARRIVING there does");
      }

      // 18i4. REFITS ARE DEFERRED while a selection is held. Starting a
      //       native selection blurs xterm's hidden textarea (the
      //       platform steals focus for selection on non-editable text,
      //       and that is not cancellable), so the soft keyboard
      //       closes, the visual viewport grows, and the page's
      //       ResizeObserver refits -- reflowing the terminal under a
      //       frozen mirror, which leaves the platform's drag handles
      //       floating over content that moved. The refit is not
      //       dropped, only held: it runs once on release, however many
      //       were swallowed.
      const deferred = await page.evaluate(() => {
        const before = { refits: globalThis.wosh.refits, rows: globalThis.wosh.term.rows, cols: globalThis.wosh.term.cols };
        globalThis.wosh.refit();
        globalThis.wosh.refit();
        return { before, after: { refits: globalThis.wosh.refits, rows: globalThis.wosh.term.rows, cols: globalThis.wosh.term.cols } };
      });
      await page.evaluate(() => document.getSelection().removeAllRanges());
      await page.waitForTimeout(250);
      const flushed = await page.evaluate(() => globalThis.wosh.refits);
      const immediate = await page.evaluate(() => {
        const before = globalThis.wosh.refits;
        globalThis.wosh.refit();
        return { before, after: globalThis.wosh.refits };
      });
      if (ok(deferred.after.refits === deferred.before.refits,
             `a refit ran under a live selection (${deferred.before.refits} -> ${deferred.after.refits}): the terminal would reflow out from under the handles`) &&
          ok(deferred.after.rows === deferred.before.rows && deferred.after.cols === deferred.before.cols,
             `the terminal geometry changed under a live selection (${deferred.before.cols}x${deferred.before.rows} -> ${deferred.after.cols}x${deferred.after.rows})`) &&
          ok(flushed === deferred.before.refits + 1,
             `releasing the selection did not replay the deferred refit exactly once (${deferred.before.refits} -> ${flushed}, two calls were deferred)`) &&
          ok(immediate.after === immediate.before + 1,
             `a refit with no selection held did not run immediately (${immediate.before} -> ${immediate.after})`)) {
        console.log("[18i4] refits are deferred while a selection is held and replayed once on release");
      }

      // 18i5. RATCHET CATCH-UP: a focus endpoint that lands BEYOND the
      //       edge row scrolls by the overshoot, not by a fixed crawl.
      //
      //       This is the blank-area bug. With the refit deferred, the
      //       closed keyboard leaves a strip below the canvas that has
      //       no selectable text in it, so a finger there is mapped to
      //       the nearest selectable position in document order -- one
      //       of the clipped rows an earlier scroll appended below the
      //       viewport. The old trigger tested `view === rows - 1`
      //       exactly and so never fired, and the selection silently ran
      //       into rows nobody could see.
      //
      //       Mounting hidden TAIL rows takes a scroll DOWN while frozen
      //       (which appends below) and then back up: revealing upward
      //       only ever prepends, so scrolling up would put the extra
      //       rows on the wrong end.
      await page.evaluate(() => {
        globalThis.wosh.term.scrollToBottom();
        globalThis.wosh.term.scrollLines(-20); // room to move both ways
      });
      await page.waitForTimeout(250);
      await page.evaluate(() => {
        const sheet = document.querySelector(".touch-select-sheet");
        const div = sheet.children[2];
        const range = document.createRange();
        range.setStart(div.firstChild, 0);
        range.setEnd(div.firstChild, Math.min(4, div.textContent.length));
        const sel = document.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      });
      await page.waitForTimeout(200); // the freeze lands
      await page.evaluate(() => globalThis.wosh.term.scrollLines(6)); // appends 6 below
      await page.waitForTimeout(200);
      await page.evaluate(() => globalThis.wosh.term.scrollLines(-6)); // back: those 6 are now clipped
      await page.waitForTimeout(250);
      const tail = await page.evaluate(() => {
        const term = globalThis.wosh.term;
        const sheet = document.querySelector(".touch-select-sheet");
        return {
          rowCount: sheet.children.length,
          termRows: term.rows,
          viewportY: term.buffer.active.viewportY,
        };
      });
      if (!ok(tail.rowCount >= tail.termRows + 3,
              `leg 18i5 has no hidden tail rows to aim at (${tail.rowCount} rows for a ${tail.termRows}-row view)`)) {
        // nothing below the fold to select into
      } else {
        // Three rows PAST the last visible one -- what a finger in the
        // blank strip resolves to.
        const overshoot = 3;
        await page.evaluate((overshoot) => {
          const term = globalThis.wosh.term;
          const sheet = document.querySelector(".touch-select-sheet");
          const div = sheet.children[term.rows - 1 + overshoot];
          document.getSelection().extend(div.firstChild, 0);
        }, overshoot);
        await page.waitForTimeout(300); // past the rate cap, and let onScroll land
        const caught = await page.evaluate(() => ({
          viewportY: globalThis.wosh.term.buffer.active.viewportY,
          selection: document.getSelection().toString(),
        }));
        if (ok(caught.viewportY === tail.viewportY + overshoot,
               `the ratchet did not catch up to a focus past the bottom row (${tail.viewportY} -> ${caught.viewportY}, expected ${tail.viewportY + overshoot}: one step of exactly the overshoot)`) &&
            ok(caught.selection !== "", "catching up dropped the selection it was chasing")) {
          console.log(`[18i5] a focus ${overshoot} rows past the bottom scrolls exactly ${overshoot} lines: the view catches up to what is being selected`);
        }
      }

      // 18i6. HANDLE REFRESH: after the mirror moves, the selection is
      //       re-asserted with the SAME endpoints, so the platform is
      //       given an event telling it to re-derive its selection UI.
      //
      //       A pan fires no selectionchange of its own -- the Range
      //       never moves, only the boxes under it -- and Android's
      //       teardrop handles are drawn from cached endpoint geometry,
      //       so they were left stranded where the text used to be.
      //       What this leg can pin is that the mechanism fires and
      //       costs nothing: the selection text is unchanged, and a
      //       selectionchange arrives after the scroll settled without
      //       the gate touching the selection. Whether the teardrops
      //       actually follow is a device question no headless Chromium
      //       can answer.
      const refreshSel = await page.evaluate(() => {
        globalThis.__selChanges = 0;
        document.addEventListener("selectionchange", () => { globalThis.__selChanges++; });
        return document.getSelection().toString();
      });
      await page.evaluate(() => {
        globalThis.wosh.term.scrollLines(-2);
        globalThis.__selChanges = 0; // count only what happens AFTER the move
      });
      await page.waitForTimeout(400); // the refresh waits out ~150ms of quiet
      const refreshed = await page.evaluate(() => ({
        changes: globalThis.__selChanges,
        selection: document.getSelection().toString(),
      }));
      if (ok(refreshSel !== "", "leg 18i6 needs a live selection to re-assert") &&
          ok(refreshed.changes >= 1,
             "no selectionchange arrived after the mirror moved: nothing ever tells the platform to re-derive the handles") &&
          ok(refreshed.selection === refreshSel,
             `re-asserting the selection changed it:\n    before ${JSON.stringify(refreshSel)}\n    after  ${JSON.stringify(refreshed.selection)}`)) {
        console.log(`[18i6] the mirror moving re-asserts the same selection (${refreshed.changes} selectionchange) so the platform can redraw its handles`);
      }

      // 18i7. THE SCROLLBAR STOPS EATING THE HANDLE. xterm's drawn
      //       scrollbar overlays the right edge and, while visible,
      //       takes pointer events for itself -- so a selection handle
      //       parked at the END of a line, which is exactly where it
      //       sits, cannot be picked up at all. While a selection is
      //       held the class on .xterm suppresses the widget's hit
      //       testing; the thumb drag is the cheaper of the two to lose,
      //       since a content pan and the ratchet both still scroll.
      //
      //       The widget writes pointer-events on itself as it fades, so
      //       the leg forces its VISIBLE state (the state in which it
      //       would otherwise take the touch) before measuring.
      const grabbed = await page.evaluate(() => {
        const bar = document.querySelector(".xterm-scrollable-element > .scrollbar.vertical");
        if (!bar) return null;
        bar.classList.remove("invisible");
        bar.classList.add("visible");
        return {
          holding: document.querySelector(".xterm").classList.contains("touch-select-holding"),
          pointerEvents: getComputedStyle(bar).pointerEvents,
        };
      });
      if (!ok(Boolean(grabbed), "xterm has drawn no vertical scrollbar, so leg 18i7 has nothing to suppress")) {
        // nothing to measure
      } else {
        await page.evaluate(() => document.getSelection().removeAllRanges());
        await page.waitForTimeout(250);
        const released = await page.evaluate(() => {
          const bar = document.querySelector(".xterm-scrollable-element > .scrollbar.vertical");
          bar.classList.remove("invisible");
          bar.classList.add("visible");
          return {
            holding: document.querySelector(".xterm").classList.contains("touch-select-holding"),
            pointerEvents: getComputedStyle(bar).pointerEvents,
          };
        });
        if (ok(grabbed.holding, "the holding class was not on .xterm while a selection was held") &&
            ok(grabbed.pointerEvents === "none",
               `the scrollbar still takes pointer events under a live selection (${grabbed.pointerEvents}): an end-of-line handle stays ungrabbable`) &&
            ok(!released.holding, "the holding class outlived the selection") &&
            ok(released.pointerEvents !== "none",
               `the scrollbar never got its pointer events back after release (${released.pointerEvents}): the thumb drag would stay dead`)) {
          console.log("[18i7] a held selection suppresses the scrollbar's hit testing, and release gives it back");
        }
      }
      await page.evaluate(() => document.getSelection().removeAllRanges());
      await page.waitForTimeout(200);
      await page.evaluate(() => globalThis.wosh.term.scrollToBottom());
      await page.waitForTimeout(200);

      // 18j. COPY: a soft wrap is not a line break. The mirror is one
      //      div per VISUAL row, so the browser's default copy puts a
      //      newline at every wrap -- pasting a wrapped command back
      //      into a shell would break it in half. The handler rebuilds
      //      the text from the mirror's own characters, joining rows
      //      the buffer marks as wrapped and right-trimming only the
      //      rows that really ended.
      const wrapped = await page.evaluate(() => new Promise((resolve) => {
        const term = globalThis.wosh.term;
        const long = "A".repeat(term.cols) + "BBBBBBBBBB"; // one full row, then a wrap
        term.write(`\r\n${long}\r\nZSHORT\r\n`, () => {
          term.scrollToBottom();
          resolve({ cols: term.cols });
        });
      }));
      await page.waitForTimeout(300);
      await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
      const copied = await page.evaluate(() => {
        const term = globalThis.wosh.term;
        const buf = term.buffer.active;
        const layer = document.querySelector(".touch-select-layer");
        const sheet = layer.querySelector(".touch-select-sheet");
        // Cursor rests on the line after ZSHORT: the three visual rows
        // above it are the A-row, the B-row (its soft continuation) and
        // ZSHORT.
        const cursorAbs = buf.baseY + buf.cursorY;
        const rowOf = (abs) => abs - buf.viewportY;
        const aRow = sheet.children[rowOf(cursorAbs - 3)];
        const bRow = sheet.children[rowOf(cursorAbs - 2)];
        const zRow = sheet.children[rowOf(cursorAbs - 1)];
        if (typeof ClipboardEvent !== "function" || typeof DataTransfer !== "function") {
          return { error: "this Chromium cannot construct ClipboardEvent/DataTransfer; leg 18j cannot run" };
        }
        const range = document.createRange();
        range.setStart(aRow.firstChild, 40); // mid-way along the first visual row
        // ...through the very END of the ZSHORT row, trailing cell
        // padding included, so the right-trim is exercised.
        range.setEnd(zRow.firstChild, zRow.textContent.length);
        const sel = document.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);

        const ev = new ClipboardEvent("copy", {
          clipboardData: new DataTransfer(),
          bubbles: true,
          cancelable: true,
        });
        layer.dispatchEvent(ev);
        return {
          text: ev.clipboardData.getData("text/plain"),
          defaultPrevented: ev.defaultPrevented,
          aJoins: aRow.dataset.joinNext === "1",
          bJoins: bRow.dataset.joinNext === "1",
          aText: aRow.textContent,
          bText: bRow.textContent,
          zText: zRow.textContent,
        };
      });
      if (copied.error) {
        fail(copied.error);
      } else {
        const expected = `${"A".repeat(wrapped.cols - 40)}BBBBBBBBBB\nZSHORT`;
        if (ok(copied.aJoins, "the wrapped row is not marked as joining the next: the copy has nothing to join on") &&
            ok(!copied.bJoins, "the continuation row was marked as wrapping too, but ZSHORT is a fresh line") &&
            ok(copied.defaultPrevented, "the copy handler let the browser's default (a newline at every wrap) through") &&
            ok(copied.text === expected,
               `the copy did not join the soft wrap:\n    got      ${JSON.stringify(copied.text)}\n    expected ${JSON.stringify(expected)}`) &&
            ok((copied.text.match(/\n/g) ?? []).length === 1, `the copy carries ${(copied.text.match(/\n/g) ?? []).length} newlines, expected exactly the one hard break`)) {
          console.log("[18j] copying across a soft wrap joins it, and the hard break stays one trimmed newline");
        }
      }
      await page.evaluate(() => document.getSelection().removeAllRanges());

      // 18k. THE PLACEMENT: a tap on a painted URI still reaches
      //      xterm's linkifier THROUGH the overlay. The linkifier binds
      //      its mouse listeners on .xterm-screen (the selection
      //      service and the contextmenu handler bind on .xterm), so
      //      only an overlay mounted as a DESCENDANT of .xterm-screen
      //      lets a tap's compatibility mouse events bubble through
      //      both. Mount it one level up and link taps die silently on
      //      every phone -- which is the failure this leg exists to
      //      catch.
      const LINK_URI = "https://example.com/tap";
      const linkAt = await page.evaluate((uri) => new Promise((resolve) => {
        const term = globalThis.wosh.term;
        globalThis.wosh.linkActivations.length = 0;
        term.write(`\r\nsee ${uri} done\r\n`, () => {
          term.scrollToBottom();
          const buf = term.buffer.active;
          resolve({
            viewRow: buf.baseY + buf.cursorY - 1 - buf.viewportY,
            col: 4 + Math.floor(uri.length / 2), // "see " is 4 cells
            // A phone is ~44 columns: the line has to FIT, or the row
            // below the cursor is the wrap continuation and the
            // coordinates land past the end of the URI -- a leg that
            // fails for a reason that is not the one it is testing.
            fits: `see ${uri} done`.length <= term.cols,
          });
        });
      }), LINK_URI);
      await page.waitForTimeout(300);
      if (!ok(linkAt.fits, "the link line wrapped: leg 18k would be aiming at the continuation row, not the URI")) {
        // the tap below would prove nothing
      } else {
      const linkScreen = await page.locator(".xterm-screen").boundingBox();
      const linkCols = await page.evaluate(() => globalThis.wosh.term.cols);
      const linkRows = await page.evaluate(() => globalThis.wosh.term.rows);
      const linkPt = {
        x: linkScreen.x + (linkScreen.width / linkCols) * (linkAt.col + 0.5),
        y: linkScreen.y + (linkScreen.height / linkRows) * (linkAt.viewRow + 0.5),
      };
      await send("touchStart", points(linkPt.x, linkPt.y));
      await page.waitForTimeout(60);
      await send("touchEnd", []);
      await page.waitForTimeout(500);
      const activations = await page.evaluate(() => globalThis.wosh.linkActivations.slice());
      if (ok(activations.length === 1,
             `a tap on a painted URI produced ${activations.length} link activations, expected 1 -- if the overlay is not a child of .xterm-screen, the linkifier never sees the tap`) &&
          ok(activations[0] === LINK_URI, `the linkifier reported ${JSON.stringify(activations[0])}, expected the URI verbatim`)) {
        console.log("[18k] a tap on a link still reaches the linkifier through the overlay");
      }
      }
      await page.evaluate(() => globalThis.wosh.term.clearSelection());

      // --- forwarding a finger to the application ---------------------
      //
      // scrollLines only ever moves the SCROLLBACK, and there are two
      // states where that is the wrong sink. An app that turned mouse
      // tracking on (tmux, less, a mouse-aware vim) wants the wheel
      // itself; and any alternate-screen program has no scrollback at
      // all -- baseY is pinned at 0, so the local path was a silent
      // no-op and touch scrolling simply did nothing inside tmux. Both
      // now forward: the drag becomes wheel events on xterm's screen
      // element, and xterm encodes and sends whatever the active mode
      // and encoding call for. So these legs read what the TERMINAL
      // SENT, not where the viewport went.
      //
      // Drags are 3.5 cells rather than a flat 3: the synthetic touch
      // points are rounded to whole pixels, so a drag of exactly 3
      // cells can measure a pixel short and truncate to 2 -- a flake
      // about the CDP coordinate rounding, not about the code.
      await page.evaluate(() => { globalThis.wosh.term.scrollToBottom(); });
      const drainData = () => page.evaluate(() => globalThis.wosh.data());
      const cellH = (await tstate()).cellHeight;
      const trackingIs = (mode) =>
        page.waitForFunction((m) => globalThis.wosh.term.modes.mouseTrackingMode === m,
          mode, { timeout: 5_000 }).then(() => true, () => false);

      // 18m. A tracking app OWNS the wheel: dragging down sends it
      //      wheel-up reports (SGR button 64) and the local scrollback
      //      does not ALSO move -- double-handling a gesture is its own
      //      bug, and the page must still stay where it is.
      await page.evaluate(() => globalThis.wosh.term.write("\x1b[?1002h\x1b[?1006h"));
      const tracking = await trackingIs("drag");
      // Leg 18k left the terminal focused (it tapped a link), so the
      // focus assertion below would be reading that, not this drag.
      await page.evaluate(() => globalThis.wosh.term.blur());
      await drainData();
      const fwd0 = await tstate();
      await dragAt(mid.x, mid.y, 0, Math.round(3.5 * cellH));
      const fwdReports = await drainData();
      const fwd1 = await tstate();
      const wheelUp = fwdReports.filter((c) => /^\x1b\[<64;\d+;\d+M$/.test(c));
      if (ok(tracking, "the fixture never entered mouse-tracking mode, so leg 18m proves nothing") &&
          ok(fwdReports.length === 3 && wheelUp.length === 3,
             `a forwarded 3-cell drag did not send exactly 3 wheel-up reports -- got ${JSON.stringify(fwdReports)}`) &&
          ok(fwd1.viewportY === fwd0.viewportY,
             `the forwarded drag ALSO scrolled the local scrollback (${fwd0.viewportY} -> ${fwd1.viewportY}): the app owns the wheel, nothing else may act on it`) &&
          ok(fwd1.pageScrollY === 0, `the forwarded drag scrolled the PAGE (scrollY=${fwd1.pageScrollY})`) &&
          ok(!(await page.evaluate(() => globalThis.wosh.focused())),
             "a forwarded scroll focused the terminal: it is still a scroll, not a tap")) {
        console.log("[18m] a drag under mouse tracking sends 3 wheel-up reports and moves nothing locally");
      }

      // 18n. ...and the other direction is the other button. Finger up
      //      is wheel DOWN (65): the text follows the finger, exactly
      //      as it does when the scrollback is the sink.
      await drainData();
      await dragAt(mid.x, mid.y, 0, -Math.round(3.5 * cellH));
      const upReports = await drainData();
      if (ok(upReports.length === 3 && upReports.every((c) => /^\x1b\[<65;\d+;\d+M$/.test(c)),
             `dragging up did not send exactly 3 wheel-down reports -- got ${JSON.stringify(upReports)}`)) {
        console.log("[18n] dragging the other way sends wheel-down reports");
      }

      // 18o. THE POSITION IS THE FINGER'S. A wheel report carries the
      //      cell it happened over, and tmux routes it to the pane
      //      there -- a report pinned to the middle of the screen, or
      //      to where the gesture started, scrolls the wrong pane.
      const posAt = { x: mid.x - 60, y: mid.y - 40 };
      await drainData();
      await dragAt(posAt.x, posAt.y, 0, Math.round(3.5 * cellH));
      const posReports = await drainData();
      const screenBox = await page.locator(".xterm-screen").boundingBox();
      const cols = await page.evaluate(() => globalThis.wosh.term.cols);
      const last = posReports.at(-1);
      const m = /^\x1b\[<6[45];(\d+);(\d+)M$/.exec(last ?? "");
      // Where the finger ENDED -- the last step's event is dispatched
      // at the live position, which is the whole claim.
      const endY = posAt.y + Math.round(3.5 * cellH);
      const wantCol = Math.floor((posAt.x - screenBox.x) / (screenBox.width / cols)) + 1;
      const wantRow = Math.floor((endY - screenBox.y) / cellH) + 1;
      if (ok(Boolean(m), `leg 18o got no wheel report to read a position off -- ${JSON.stringify(posReports)}`) &&
          ok(Math.abs(Number(m[1]) - wantCol) <= 1 && Math.abs(Number(m[2]) - wantRow) <= 1,
             `the report is not at the finger: got col ${m[1]} row ${m[2]}, expected ~${wantCol},${wantRow}`)) {
        console.log(`[18o] the report carries the cell under the finger (${m[1]},${m[2]} vs ~${wantCol},${wantRow})`);
      }

      // 18p. THE tmux/vim CASE WITH NO TRACKING AT ALL: an alternate
      //      screen has no scrollback (baseY 0), so the local path was
      //      a no-op -- this is the bug the forwarding exists for. With
      //      nothing tracking, xterm answers a wheel with a CURSOR KEY,
      //      exactly one per event however big its delta is, which is
      //      why the forwarding sends one event per cell rather than
      //      one fat event per pointermove.
      await page.evaluate(() => globalThis.wosh.term.write("\x1b[?1002l\x1b[?1006l\x1b[?1049h"));
      const onAlt = await page.waitForFunction(
        () => globalThis.wosh.term.buffer.active.type === "alternate", null, { timeout: 5_000 },
      ).then(() => true, () => false);
      await drainData();
      await dragAt(mid.x, mid.y, 0, Math.round(3.5 * cellH));
      const altDown = await drainData();
      await dragAt(mid.x, mid.y, 0, -Math.round(3.5 * cellH));
      const altUp = await drainData();
      // ...and DECCKM is honored, because xterm's own wheel path is
      // what produced these and it reads the mode at send time.
      await page.evaluate(() => globalThis.wosh.term.write("\x1b[?1h"));
      await page.waitForTimeout(150);
      await drainData();
      await dragAt(mid.x, mid.y, 0, Math.round(1.5 * cellH));
      const appMode = await drainData();
      if (ok(onAlt, "the fixture never reached the alternate screen, so leg 18p proves nothing") &&
          ok(altDown.join("") === "\x1b[A\x1b[A\x1b[A",
             `a 3-cell drag down the alt screen did not send 3 up-arrows -- got ${JSON.stringify(altDown)}`) &&
          ok(altUp.join("") === "\x1b[B\x1b[B\x1b[B",
             `a 3-cell drag up the alt screen did not send 3 down-arrows -- got ${JSON.stringify(altUp)}`) &&
          ok(appMode.join("") === "\x1bOA",
             `application cursor mode was not honored -- got ${JSON.stringify(appMode)}`)) {
        console.log("[18p] on an alt screen with nothing tracking, a finger becomes arrow keys (one per cell, DECCKM included)");
      }
      await page.evaluate(() => globalThis.wosh.term.write("\x1b[?1l\x1b[?1049l"));
      await page.waitForTimeout(200);

      // 18q. A TAP IS STILL A TAP. Forwarding takes the claimed SCROLL
      //      gesture only: a touch that never travels stays xterm's,
      //      which means the app gets a click report (through the
      //      browser's compatibility mouse events) AND the keyboard is
      //      still summoned -- leg 14's contract has to survive
      //      reporting being on.
      await page.evaluate(() => globalThis.wosh.term.write("\x1b[?1002h\x1b[?1006h"));
      await trackingIs("drag");
      await page.evaluate(() => globalThis.wosh.term.blur());
      await drainData();
      const tapPt = { x: mid.x + 40, y: mid.y + 30 };
      await send("touchStart", points(tapPt.x, tapPt.y));
      await page.waitForTimeout(60);
      await send("touchEnd", []);
      await page.waitForTimeout(300);
      const tapReports = await drainData();
      const press = /^\x1b\[<0;(\d+);(\d+)M$/.exec(tapReports[0] ?? "");
      const release = /^\x1b\[<0;(\d+);(\d+)m$/.exec(tapReports[1] ?? "");
      const tapCol = Math.floor((tapPt.x - screenBox.x) / (screenBox.width / cols)) + 1;
      const tapRow = Math.floor((tapPt.y - screenBox.y) / cellH) + 1;
      if (ok(Boolean(press) && Boolean(release),
             `a tap under mouse tracking did not report a press then a release -- got ${JSON.stringify(tapReports)}`) &&
          ok(Math.abs(Number(press[1]) - tapCol) <= 1 && Math.abs(Number(press[2]) - tapRow) <= 1,
             `the click was reported at col ${press[1]} row ${press[2]}, expected ~${tapCol},${tapRow}`) &&
          ok(await page.evaluate(() => globalThis.wosh.focused()),
             "a tap under mouse tracking no longer focuses the terminal: the soft keyboard would be unreachable inside tmux")) {
        console.log(`[18q] a tap still clicks (${press[1]},${press[2]}) and still summons the keyboard`);
      }
      await page.evaluate(() => globalThis.wosh.term.write("\x1b[?1002l\x1b[?1006l"));
      await page.waitForTimeout(150);
    }
  }

  // --- the page lifecycle, against a stub session ----------------------
  //
  // A backgrounded phone takes the network away, and the client must
  // stop redialing into it and start again the moment the page is back.
  // The page is the only thing that knows which is happening.
  await page.goto(`http://127.0.0.1:${PORT}/lifecycle`, { waitUntil: "load" });
  await page.waitForFunction(() => globalThis.wosh?.calls, null, { timeout: 15_000 });
  const calls = () => page.evaluate(() => globalThis.wosh.calls.slice());
  const reset = () => page.evaluate(() => globalThis.wosh.reset());

  // 19. Hidden means away, visible means back -- and the screen is
  //     still flushed on the way out, which is what this handler used
  //     to do and only do. (`pageshow` fires once on load too, which
  //     is a wake at a moment when there is no session to wake: reset
  //     past it rather than pretend it does not happen.)
  await reset();
  await page.evaluate(() => globalThis.wosh.setVisibility("hidden"));
  await page.evaluate(() => globalThis.wosh.setVisibility("visible"));
  const seen19 = await calls();
  const painted = await page.evaluate(() => globalThis.wosh.painted());
  if (ok(seen19.join(",") === "suspend,wake", `hiding then showing the page did not suspend then wake: ${JSON.stringify(seen19)}`) &&
      ok(painted === 1, `the screen was not flushed on the way out (painted ${painted}x)`)) {
    console.log("[19] hidden suspends the session and paints; visible wakes it");
  }

  // 20. "Away" arrives under three names and platforms disagree about
  //     which they send -- iOS often skips freeze, bfcache uses
  //     pagehide -- so all three must mean the same thing. The events
  //     are synthesized: this headless Chromium fires neither a real
  //     freeze (Page.setWebLifecycleState is silently inert) nor a
  //     real visibilitychange (every page reports itself visible), so
  //     what is pinned here is the wiring, not the platform's delivery
  //     of it.
  await reset();
  await page.evaluate(() => dispatchEvent(new Event("pagehide")));
  await page.evaluate(() => dispatchEvent(new Event("pageshow")));
  await page.evaluate(() => document.dispatchEvent(new Event("freeze")));
  await page.evaluate(() => document.dispatchEvent(new Event("resume")));
  const seen20 = await calls();
  if (ok(seen20.join(",") === "suspend,wake,suspend,wake",
         `pagehide/pageshow and freeze/resume do not both mean away/back: ${JSON.stringify(seen20)}`)) {
    console.log("[20] pagehide and freeze also mean away; pageshow and resume mean back");
  }

  // 21. These handlers run on the browser's way OUT of the page, where
  //     there is nobody to report to: a session that is missing or
  //     already torn down must not throw, and must not leave an
  //     unhandled rejection behind in a page about to be frozen.
  await reset();
  await page.evaluate(() => globalThis.wosh.clearSession());
  await page.evaluate(() => globalThis.wosh.setVisibility("hidden"));
  await page.evaluate(() => globalThis.wosh.setVisibility("visible"));
  await page.evaluate(() => globalThis.wosh.breakSession());
  await page.evaluate(() => globalThis.wosh.setVisibility("hidden"));
  await page.evaluate(() => globalThis.wosh.setVisibility("visible"));
  await page.waitForTimeout(300);
  const quiet = await calls();
  if (ok(quiet.length === 0, `a missing or broken session was not survived quietly: ${JSON.stringify(quiet)}`)) {
    console.log("[21] no session, or a torn-down one, is survived quietly");
  }

  // --- the chrome's shape ------------------------------------------------
  //
  // The chrome outside the terminal is a home screen plus ONE ask at a
  // time in a bottom sheet (#sheet). These legs pin the structure that
  // makes the old failure modes unrepresentable -- a question buried
  // below a phone's fold, a dead attempt's prompt left answerable, a
  // history row tappable mid-auth -- against the real index.html +
  // boot.mjs with only the wasm component stubbed.
  await page.goto(`http://127.0.0.1:${PORT}/panel`, { waitUntil: "load" });
  await page.waitForSelector("#home button.scan", { timeout: 15_000 });
  await page.waitForFunction(() => window.__woshBoot?.ui, null, { timeout: 15_000 });

  // 22. A fresh home screen is the TASK: scan (primary), paste, and
  //     nothing else demanding answers -- no cards on fresh storage, no
  //     folds, and the extra-keys bar stays hidden until a session
  //     exists (body.live).
  const shape = await page.evaluate(() => ({
    cards: document.querySelectorAll("#home .histrow").length,
    scanVisible: document.querySelector("#home button.scan")?.checkVisibility() ?? false,
    pasteVisible: document.querySelector("#home input.connstring")?.checkVisibility() ?? false,
    textInputs: [...document.querySelectorAll("#home input[type=text]")].length,
    keysDisplay: getComputedStyle(document.getElementById("keys")).display,
    live: document.body.classList.contains("live"),
  }));
  if (ok(shape.cards === 0, `fresh storage must show no connection cards (found ${shape.cards})`) &&
      ok(shape.scanVisible && shape.pasteVisible, "scan and paste must both be visible on a fresh home") &&
      ok(shape.textInputs === 1, `a fresh home should carry exactly the paste field (${shape.textInputs} inputs)`) &&
      ok(!shape.live && shape.keysDisplay === "none",
         `the extra-keys bar must stay hidden without a session (display: ${shape.keysDisplay})`)) {
    console.log("[22] a fresh home is the task: scan + paste, no cards, keys bar hidden");
  }

  // 22b. body.live is the keys bar's whole switch: flipping it on shows
  //      the bar under a coarse pointer (boot.mjs flips it on connect).
  const keysLive = await page.evaluate(() => {
    document.body.classList.add("live");
    const display = getComputedStyle(document.getElementById("keys")).display;
    document.body.classList.remove("live");
    return display;
  });
  if (ok(keysLive === "flex", `body.live must show the keys bar (display: ${keysLive})`)) {
    console.log("[22b] the keys bar rides body.live");
  }

  // 23. An ask OWNS the screen: the host-key confirmation arrives as a
  //     modal sheet -- visible, above everything, nothing else tappable
  //     -- and its buttons resolve it. This is what retired the
  //     below-the-fold prompt (the page looking hung on
  //     "authenticating…" while its question sat unseen).
  const asked = page.evaluate(() =>
    window.__woshBoot.ui.confirmHostKey("SHA256:synthetic-fingerprint-for-the-gate", ""));
  await page.waitForSelector("#sheet[data-ask='hostkey'] .confirm", { timeout: 5_000 });
  const askShape = await page.evaluate(() => {
    const sheet = document.getElementById("sheet");
    const fp = sheet.querySelector(".confirm code.fp");
    return {
      open: sheet.open,
      modal: sheet.matches(":modal"),
      fpVisible: fp?.checkVisibility() ?? false,
      fpText: fp?.textContent ?? "",
      rememberUnchecked: sheet.querySelector("#remember-hostkey")?.checked === false,
    };
  });
  await page.click(`#sheet button:has-text("don't connect")`);
  if (ok(await asked === false, "the host-key ask did not resolve from its buttons") &&
      ok(askShape.open && askShape.modal, "the ask must be a modal sheet") &&
      ok(askShape.fpVisible, "the fingerprint must be visible in the sheet") &&
      ok(askShape.fpText === "SHA256:synthetic-fingerprint-for-the-gate",
         `the fingerprint text must be EXACT (grouping is visual only); got ${JSON.stringify(askShape.fpText)}`) &&
      ok(askShape.rememberUnchecked, "the remember checkbox must default to unchecked")) {
    console.log("[23] a host-key ask owns the screen as a modal sheet; the fingerprint text is exact");
  }

  // 23b. Superseding an ask resolves it null: the sheet can never
  //      accumulate a dead attempt's questions (the zombie-prompt bug).
  const first = page.evaluate(() =>
    window.__woshBoot.ui.collectPrompts({ instruction: "first", prompts: [{ text: "a:", echo: true }] }));
  await page.waitForSelector("#sheet[data-ask='prompts']", { timeout: 5_000 });
  const second = page.evaluate(() =>
    window.__woshBoot.ui.collectPrompts({ instruction: "second", prompts: [{ text: "b:", echo: true }] }));
  await page.waitForFunction(
    () => document.querySelector("#sheet p")?.textContent === "second", null, { timeout: 5_000 });
  if (ok(await first === null, "a superseded ask must resolve null (cancelled), not linger")) {
    console.log("[23b] a superseded ask resolves null; one question on screen at a time");
  }
  await page.click("#sheet button:text-is('cancel')");
  if (ok(await second === null, "cancel must resolve the prompt batch null")) {
    console.log("[23c] cancel resolves the batch null (the attempt tears down)");
  }

  // 24. The connect sheet: paste + go opens it, its options fold
  //     announces itself with an explicit chevron (display:flex on
  //     summary removes the native marker), and the method select
  //     works inside it.
  await page.fill("#home input.connstring", "not-a-real-connstring");
  await page.click("#home .pasterow button.go");
  await page.waitForSelector("#sheet[data-ask='connect']", { timeout: 5_000 });
  const marker = await page.evaluate(() => {
    const summary = document.querySelector("#sheet details.options summary");
    const closed = getComputedStyle(summary, "::before").content;
    document.querySelector("#sheet details.options").open = true;
    const opened = getComputedStyle(summary, "::before").content;
    return { closed, opened };
  });
  if (ok(marker.closed !== "none" && marker.closed !== "normal", "the options fold has no expand indicator") &&
      ok(marker.opened !== marker.closed, "the indicator does not change when the fold opens")) {
    console.log(`[24] the options fold carries an explicit expand indicator (${marker.closed} -> ${marker.opened})`);
  }
  await page.selectOption("#sheet select.method", "password");
  const picked = await page.locator("#sheet select.method").inputValue();
  if (ok(picked === "password", `the method select did not take a selection (${picked})`)) {
    console.log("[25] the method select works inside the options fold");
  }
  await page.click("#sheet button:text-is('cancel')");

  // 25b. The settings screen carries identity & keys: the browser key
  //      renders on demand, and the passkey card is one compact action
  //      row -- adopt's paste field hidden until asked for, the
  //      guidance behind the "?".
  await page.click("#home .topline button:has-text('settings')");
  await page.waitForFunction(
    () => !document.querySelector("#prefs .passkey")?.hidden, null, { timeout: 15_000 });
  await page.click(`#prefs button:has-text("show this browser's public key")`);
  await page.waitForSelector("#prefs .key code", { timeout: 5_000 });
  const line = (await page.locator("#prefs .key code").textContent()).trim();
  if (ok(line.startsWith("ssh-ed25519 "), `the browser-key line did not render: "${line}"`)) {
    console.log("[25c] the settings screen renders the browser key on demand");
  }
  const submenu = await page.evaluate(() => {
    const section = document.querySelector("#prefs .passkey");
    const visible = (el) => el.checkVisibility();
    const byText = (t) => [...section.querySelectorAll("button")].find((b) => b.textContent.trim() === t);
    const adoptInput = section.querySelector("input");
    const helpBody = section.querySelector(".help-body");
    const before = { adoptInput: visible(adoptInput), helpBody: visible(helpBody) };
    byText("adopt…").click();
    byText("?").click();
    const after = { adoptInput: visible(adoptInput), helpBody: visible(helpBody) };
    return { before, after };
  });
  if (ok(!submenu.before.adoptInput, "the adopt paste field rendered before being asked for") &&
      ok(!submenu.before.helpBody, "the guidance prose rendered before the ? was pressed") &&
      ok(submenu.after.adoptInput, "adopt… did not reveal the paste field") &&
      ok(submenu.after.helpBody, "? did not reveal the guidance")) {
    console.log("[25d] passkey is one action row; adopt and the guidance reveal on demand");
  }
  await page.click("#prefs .backrow .back");

  // 25e. Settings is reachable FROM a live session -- without ending
  //      it, and without a detour through the connection list. That is
  //      the one moment it used to be unreachable, and the moment a key
  //      line is most wanted: you are logged into the machine you want
  //      to install it on. Leaving goes back to the session, not to the
  //      connection list, so the way out is where you came from.
  {
    await page.evaluate(() => {
      localStorage.setItem("wosh.history.v1", JSON.stringify([{
        id: "c0ffee".padEnd(64, "0"),
        relay: "https://use1-1.relay.n0.iroh.link",
        user: "lann", name: "ivy", at: new Date().toISOString(),
      }]));
      localStorage.setItem("wosh.hostkeys.v1", JSON.stringify({
        ["c0ffee".padEnd(64, "0")]: { fp: "SHA256:synthetic-fingerprint-for-the-gate", at: "2026-08-01" },
      }));
    });
    await page.reload({ waitUntil: "load" });
    await page.waitForFunction(() => window.__woshBoot?.ui, null, { timeout: 15_000 });
    await page.click("#home .histrow");
    const live = await page.waitForFunction(() => document.body.classList.contains("live"), null,
      { timeout: 15_000 }).then(() => true, () => false);
    if (!ok(live, "the pinned card did not reach a live session against the stub")) {
      // the rest of the leg cannot run
    } else {
      await page.click("#sessions-btn");
      await page.waitForSelector("#sheet[data-ask='session']", { timeout: 5_000 });
      const reachable = await page.locator("#sheet button:text-is('settings & keys')").count();
      if (ok(reachable === 1, "a live session offers no way into settings")) {
        await page.click("#sheet button:text-is('settings & keys')");
        await page.waitForSelector("#prefs .backrow", { timeout: 5_000 });
        await page.click(`#prefs button:has-text("show this browser's public key")`);
        await page.waitForSelector("#prefs .key code", { timeout: 5_000 });
        const line = (await page.locator("#prefs .key code").textContent()).trim();
        // Back out: the session is still there, and it is what you see.
        await page.click("#prefs .backrow .back");
        await page.waitForTimeout(200);
        const after = await page.evaluate(() => ({
          chromeHidden: document.getElementById("chrome").hidden,
          live: document.body.classList.contains("live"),
        }));
        if (ok(line.startsWith("ssh-ed25519 "), `the key did not render inside a live session: ${line}`) &&
            ok(after.live, "the session did not survive a trip through settings") &&
            ok(after.chromeHidden, "leaving settings left it covering the session it came from")) {
          console.log("[25e] settings opens from a live session, shows the key, and gives the session back");
        }
      }
      await page.evaluate(() => localStorage.clear());
      await page.reload({ waitUntil: "load" });
      await page.waitForFunction(() => window.__woshBoot?.ui, null, { timeout: 15_000 });
    }
  }

  // 25f. Installing the key on the connected machine: the button is
  //      dead without a session, and with one it asks the machine to
  //      run ssh-copy-id's command rather than typing anything into the
  //      terminal. Each clause of that command is pinned because each
  //      one is a bug ssh-copy-id already paid for: umask 077 (sshd
  //      ignores a group-writable authorized_keys, silently), the
  //      tail -1c guard (a file with no trailing newline gets its last
  //      key concatenated with the new one), restorecon (SELinux), and
  //      the already-there check.
  {
    // With no session, the affordance exists but is disabled -- that is
    // how you learn it is there at all. (The key card renders its
    // buttons only once the line is shown, so ask for it first.)
    await page.click("#home .topline button:has-text('settings')");
    await page.click(`#prefs button:has-text("show this browser's public key")`);
    await page.waitForSelector("#prefs .key code", { timeout: 5_000 });
    const idle = await page.evaluate(() => {
      const b = [...document.querySelectorAll("#prefs button")]
        .find((x) => x.textContent.trim() === "install on this machine");
      return { present: !!b, disabled: b?.disabled ?? null };
    });
    if (!ok(idle.present && idle.disabled === true,
            `without a session the install button must be present and disabled: ${JSON.stringify(idle)}`)) {
      // fall through; the live half is still worth running
    }

    await page.evaluate(() => {
      localStorage.setItem("wosh.history.v1", JSON.stringify([{
        id: "c0ffee".padEnd(64, "0"),
        relay: "https://use1-1.relay.n0.iroh.link",
        user: "lann", name: "ivy", at: new Date().toISOString(),
      }]));
      localStorage.setItem("wosh.hostkeys.v1", JSON.stringify({
        ["c0ffee".padEnd(64, "0")]: { fp: "SHA256:synthetic-fingerprint-for-the-gate", at: "2026-08-01" },
      }));
    });
    await page.reload({ waitUntil: "load" });
    await page.waitForFunction(() => window.__woshBoot?.ui, null, { timeout: 15_000 });
    await page.click("#home .histrow");
    await page.waitForFunction(() => document.body.classList.contains("live"), null, { timeout: 15_000 });
    await page.click("#sessions-btn");
    await page.click("#sheet button:text-is('settings & keys')");
    await page.waitForSelector("#prefs .backrow", { timeout: 5_000 });
    await page.click(`#prefs button:has-text("show this browser's public key")`);
    await page.waitForSelector("#prefs .key code", { timeout: 5_000 });
    const line = (await page.locator("#prefs .key code").textContent()).trim();

    await page.click("#prefs button:text-is('install on this machine')");
    await page.waitForSelector("#sheet[data-ask='install'] input", { timeout: 5_000 });
    // The default comment is offered as a PLACEHOLDER, so leaving the
    // field alone keeps it -- and typing replaces it.
    const placeholder = await page.locator("#sheet input").getAttribute("placeholder");
    await page.fill("#sheet input", "my phone");
    await page.click("#sheet button:text-is('install')");
    await page.waitForFunction(() => globalThis.__probed, null, { timeout: 5_000 });
    const cmd = await page.evaluate(() => globalThis.__probed);
    const blob = line.split(/\s+/)[1];
    const said = await page.locator("#prefs .key .sub").textContent();

    const clauses = [
      ["umask 077", /umask 077/],
      ["mkdir -p .ssh", /mkdir -p \.ssh/],
      ["the already-there check", new RegExp(`grep -qsF '${blob.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}'`)],
      ["the missing-newline guard", /tail -1c \.ssh\/authorized_keys/],
      ["an append, not a clobber", />> \.ssh\/authorized_keys/],
      ["restorecon", /restorecon/],
    ];
    const missing = clauses.filter(([, re]) => !re.test(cmd)).map(([name]) => name);
    if (ok(placeholder === "wosh-browser", `the default comment must be the placeholder, got ${placeholder}`) &&
        ok(missing.length === 0, `the install command is missing: ${missing.join(", ")}\n  ${cmd}`) &&
        ok(cmd.includes("'ssh-ed25519 " + blob + " my phone'"), // spaces survive; quotes never would
           `the typed comment did not reach the line: ${cmd}`) &&
        ok(!/\r|\n/.test(cmd), "the command must be one line: a newline in it would append a second key") &&
        ok(/installed on ivy/.test(said ?? ""), `the outcome was not reported: ${said}`)) {
      console.log("[25f] install asks the machine to run ssh-copy-id's command, with the comment given");
    }

    // ...and a key already in the file is reported, not appended twice.
    await page.evaluate(() => { globalThis.__probeReply = "WOSH_ALREADY\n"; });
    await page.click("#prefs button:text-is('install on this machine')");
    await page.waitForSelector("#sheet[data-ask='install'] input", { timeout: 5_000 });
    await page.click("#sheet button:text-is('install')");
    await page.waitForFunction(
      () => /already/.test(document.querySelector("#prefs .key .sub")?.textContent ?? ""),
      null, { timeout: 5_000 },
    ).then(() => console.log("[25g] a key already in the file is reported, not installed again"),
           () => fail("an already-present key was not reported as such"));

    await page.evaluate(() => localStorage.clear());
    await page.reload({ waitUntil: "load" });
    await page.waitForFunction(() => window.__woshBoot?.ui, null, { timeout: 15_000 });
  }

  // 25h. THE OTHER INPUT CHANNEL: a mouse report whose coordinate byte
  //      runs past 0x7f leaves xterm through onBinary, not onData, and
  //      has to reach the session BYTE FOR BYTE.
  //
  //      This is not a corner case. vim (not neovim) asks the terminal
  //      for a version before it will use SGR mouse reports; xterm.js
  //      answers 276 and vim wants >= 277, so it settles for the legacy
  //      X10 encoding, where a coordinate is one byte of 32 + column.
  //      Past column ~95 that byte is >= 0x80 -- which is exactly why
  //      xterm hands those chunks over on a separate event instead of
  //      as text: encode them as UTF-8 and every high byte becomes two,
  //      and the remote app is told about a column that does not exist.
  //      With onBinary unwired they were dropped outright, so clicks
  //      past column ~95 in a desktop vim went nowhere at all.
  //
  //      A desktop context, because a phone viewport has no column 101
  //      to click on. It drives the REAL app (index.html + app.mjs)
  //      with only the wasm component stubbed, and reads the bytes the
  //      stub session was handed -- not the decoded string, which is
  //      precisely the lossy view this leg exists to rule out.
  {
    const wide = await browser.newContext({ viewport: { width: 1600, height: 900 } });
    const widePage = await wide.newPage();
    widePage.on("console", (m) => m.type() === "error" && consoleErrors.push(m.text()));
    widePage.on("pageerror", (e) => consoleErrors.push(String(e)));
    await widePage.goto(`http://127.0.0.1:${PORT}/panel`, { waitUntil: "load" });
    await widePage.waitForFunction(() => window.__woshBoot?.ui, null, { timeout: 15_000 });
    await widePage.evaluate(() => {
      localStorage.setItem("wosh.history.v1", JSON.stringify([{
        id: "c0ffee".padEnd(64, "0"),
        relay: "https://use1-1.relay.n0.iroh.link",
        user: "lann", name: "ivy", at: new Date().toISOString(),
      }]));
      localStorage.setItem("wosh.hostkeys.v1", JSON.stringify({
        ["c0ffee".padEnd(64, "0")]: { fp: "SHA256:synthetic-fingerprint-for-the-gate", at: "2026-08-01" },
      }));
    });
    await widePage.reload({ waitUntil: "load" });
    await widePage.waitForFunction(() => window.__woshBoot?.ui, null, { timeout: 15_000 });
    await widePage.click("#home .histrow");
    const liveWide = await widePage.waitForFunction(
      () => document.body.classList.contains("live"), null, { timeout: 15_000 },
    ).then(() => true, () => false);
    if (!ok(liveWide, "the pinned card did not reach a live session on a desktop viewport")) {
      // nothing to click a report out of
    } else {
      // X10 tracking, DELIBERATELY without 1006: the SGR encoding is
      // all-ASCII and would never exercise onBinary.
      await widePage.evaluate(() => window.__wosh.term.write("\x1b[?1000h"));
      const x10 = await widePage.waitForFunction(
        () => window.__wosh.term.modes.mouseTrackingMode === "vt200", null, { timeout: 5_000 },
      ).then(() => true, () => false);
      await widePage.evaluate(() => { globalThis.__typedBytes = []; });
      const geom = await widePage.evaluate(() => {
        const box = document.querySelector(".xterm-screen").getBoundingClientRect();
        return { x: box.x, y: box.y, w: box.width, h: box.height,
                 cols: window.__wosh.term.cols, rows: window.__wosh.term.rows };
      });
      // 0-based column 100 => 1-based 101 => coordinate byte 133.
      const col0 = 100;
      const row0 = 2;
      const clickPt = {
        x: geom.x + (geom.w / geom.cols) * (col0 + 0.5),
        y: geom.y + (geom.h / geom.rows) * (row0 + 0.5),
      };
      if (!ok(x10, "the app never entered X10 mouse tracking, so leg 25h proves nothing") ||
          !ok(geom.cols > col0 + 1, `the desktop terminal is only ${geom.cols} columns wide: leg 25h needs a column past 95 to click`)) {
        // the click below would land somewhere else entirely
      } else {
        await widePage.mouse.click(clickPt.x, clickPt.y);
        await widePage.waitForTimeout(300);
        const bytes = await widePage.evaluate(() => (globalThis.__typedBytes ?? []).slice());
        // CSI M Cb Cx Cy: find the frame and read its column byte.
        let colByte = null;
        for (let i = 0; i + 4 < bytes.length; i++) {
          if (bytes[i] === 0x1b && bytes[i + 1] === 0x5b && bytes[i + 2] === 0x4d) {
            colByte = bytes[i + 4];
            break;
          }
        }
        const wantByte = 32 + col0 + 1;
        if (ok(colByte !== null,
               `no CSI M mouse frame reached the session: the report was dropped on the way out of xterm -- bytes ${JSON.stringify(bytes)}`) &&
            ok(colByte > 0x7f,
               `leg 25h clicked a column whose coordinate byte (${colByte}) still fits in ASCII: it would pass even with onBinary unwired`) &&
            ok(Math.abs(colByte - wantByte) <= 1,
               `the column byte arrived mangled: got ${colByte}, expected ~${wantByte} (a UTF-8 encode of the same report would have split it in two)`)) {
          console.log(`[25h] a legacy mouse report crosses onBinary byte-exact: column byte ${colByte} (> 0x7f) intact`);
        }
      }
    }
    await wide.close();
  }

  // 26-28. The passkey ceremony ask must be VISIBLE wherever it
  //     arrives: the sheet is top-layer, so it renders over the home
  //     screen AND over a bare terminal (chrome hidden) alike -- the
  //     closed-dialog invisibility bug is unrepresentable.
  await page.waitForFunction(() => globalThis.__ceremonyGate, null, { timeout: 15_000 });
  const raiseCeremony = () => page.evaluate(() => {
    window.__cerState = "pending";
    globalThis.__ceremonyGate().then(
      () => { window.__cerState = "resolved"; },
      () => { window.__cerState = "rejected"; },
    );
  });
  const cerState = () => page.evaluate(() => window.__cerState);

  // 26. Over the home screen: visible, tap resolves, sheet closes.
  await raiseCeremony();
  const askVisible = await page.waitForSelector("#sheet .confirm button", { timeout: 5_000 })
    .then((el) => el.isVisible(), () => false);
  if (!ok(askVisible, "a ceremony ask was not visible over the home screen")) {
    // the taps below would time out; skip them
  } else {
    await page.click("#sheet .confirm button:has-text('touch your passkey')");
    await page.waitForFunction(() => window.__cerState !== "pending", null, { timeout: 5_000 });
    if (ok(await cerState() === "resolved", `the tap did not resolve the gate (${await cerState()})`) &&
        ok(!(await page.evaluate(() => document.getElementById("sheet").open)),
           "the sheet stayed open after the ask was answered")) {
      console.log("[26] a ceremony ask over the home screen resolves and closes");
    }
  }

  // 27. Cancelling fails the gate (which fails the attempt, legibly).
  await raiseCeremony();
  await page.waitForSelector("#sheet .confirm button", { timeout: 5_000 });
  await page.click("#sheet .confirm button:has-text('cancel')");
  await page.waitForFunction(() => window.__cerState !== "pending", null, { timeout: 5_000 });
  if (ok(await cerState() === "rejected", `cancel did not reject the gate (${await cerState()})`)) {
    console.log("[27] cancelling the ceremony fails the gate");
  }

  // 28. With the chrome hidden (a silent reconnect over a bare
  //     terminal): the sheet still owns the top layer.
  await page.evaluate(() => { document.getElementById("chrome").hidden = true; });
  await raiseCeremony();
  const visibleOverTerm = await page.waitForSelector("#sheet .confirm button", { timeout: 5_000 })
    .then((el) => el.isVisible(), () => false);
  if (ok(visibleOverTerm, "a ceremony ask was not visible over the bare terminal")) {
    await page.click("#sheet .confirm button:has-text('touch your passkey')");
    await page.waitForFunction(() => window.__cerState !== "pending", null, { timeout: 5_000 });
    console.log("[28] a ceremony ask renders over a bare terminal too");
  }

  // 28b. esc-watch.mjs gates itself off entirely under a coarse
  //     pointer -- the system "hide keyboard" button on a phone
  //     produces the exact same blur shape a vim-keys extension does,
  //     and there is no way to tell them apart from the page. This
  //     context is touch-only (viewport 390x780, hasTouch), so the
  //     detector must be INERT here: drive the FULL would-be trigger
  //     (arm, then fire -- typing-correlated blur, refocus, typing-
  //     correlated blur again, exactly what would banner on a fine
  //     pointer) and confirm the coarse-pointer gate, not some other
  //     clause, is what's masking it.
  await page.evaluate(() => { document.getElementById("chrome").hidden = true; });
  await page.evaluate(() => window.__wosh.term.focus());
  await page.waitForTimeout(350);
  await page.evaluate(() => { window.__wosh.term.input("x"); window.__wosh.term.textarea.blur(); });
  await page.waitForTimeout(400);
  await page.evaluate(() => window.__wosh.term.focus());
  await page.waitForTimeout(350);
  await page.evaluate(() => { window.__wosh.term.input("x"); window.__wosh.term.textarea.blur(); });
  await page.waitForTimeout(400);
  const escBannerHidden = await page.evaluate(() => document.getElementById("escbanner")?.hidden);
  if (ok(escBannerHidden !== false, "the esc-intercept banner appeared under a coarse pointer (should be inert: soft-keyboard dismiss looks identical)")) {
    console.log("[28b] esc-watch is inert on a coarse pointer: a full arm+fire pattern still shows nothing");
  }

  if (consoleErrors.length) fail(`console errors:\n  ${consoleErrors.join("\n  ")}`);
  if (!process.exitCode) {
    console.log(
      "\nMOBILE GATE PASS: keys fire on a tap not a drag, the keyboard is " +
        "reachable on open, a finger scrolls the terminal instead of the page, " +
        "and where an app owns the wheel that finger is forwarded to it as " +
        "mouse reports -- high coordinate bytes included",
    );
  }
} finally {
  if (!process.argv.includes("--keep")) await browser.close();
  server.close();
}
