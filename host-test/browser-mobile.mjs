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
    const p = join(glob, d, "chrome-linux", "chrome");
    if (existsSync(p)) return p;
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
<script type="module">
  import { initMobile } from "/site/mobile.mjs";
  const term = new Terminal({ fontSize: 14, cursorBlink: false, scrollback: 1000 });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(document.getElementById("term"));
  fit.fit();
  for (let i = 1; i <= 300; i++) term.write("line " + i + "\\r\\n");
  initMobile(term);
  globalThis.wosh = {
    term,
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
    // states the page really reaches (before connect, after detach).
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
// with only the wasm component behind /dist/deltic.js stubbed (all
// capabilities true, synthetic identity lines). What is under test is
// the panel's structure -- what a user sees before touching anything,
// and where the rows that need answers appear.
const DELTIC_STUB = `
// app.mjs imports this DIRECTLY from the module (not off the client):
// the ceremony gate the panel installs. Retained and exposed so the
// gate legs can raise a ceremony exactly the way the store would.
export function setCeremonyGate(fn) { globalThis.__ceremonyGate = fn; }

export async function loadClient() {
  class Session {}
  Session.prototype.authenticateAuto = () => {};
  Session.prototype.pendingPrompts = () => {};
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
  if (path === "/dist/deltic.js") {
    res.writeHead(200, { "content-type": "text/javascript", "cache-control": "no-store" }).end(DELTIC_STUB);
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
  await desktop.close();
  if (!desktopFocused) fail("a fine pointer no longer autofocuses the terminal (a desktop page would open untypable)");
  else if (barShown) fail("the extra-keys bar is visible on a fine pointer (it must stay inert off touch devices)");
  else console.log("[10] a fine pointer still autofocuses the terminal, bar still inert");

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

  if (consoleErrors.length) fail(`console errors:\n  ${consoleErrors.join("\n  ")}`);
  if (!process.exitCode) {
    console.log(
      "\nMOBILE GATE PASS: keys fire on a tap not a drag, the keyboard is " +
        "reachable on open, and a finger scrolls the terminal instead of the page",
    );
  }
} finally {
  if (!process.argv.includes("--keep")) await browser.close();
  server.close();
}
