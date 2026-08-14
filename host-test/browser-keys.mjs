// Gate: the extra-keys bar's tap-vs-drag rule, under real touch input.
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
// Usage: node host-test/browser-keys.mjs [--keep]

import { chromium } from "playwright-core";
import { existsSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname } from "node:path";

const ROOT = new URL("../", import.meta.url).pathname;
const PORT = Number(process.env.WOSH_HTTP_PORT ?? 8101); // one per browser gate: 8098/8099/8102/8123/8129 are taken

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

const server = createServer(async (req, res) => {
  const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (path === "/") {
    res.writeHead(200, { "content-type": "text/html", "cache-control": "no-store" }).end(FIXTURE);
    return;
  }
  if (path === "/favicon.ico") {
    res.writeHead(204).end(); // Chromium asks unprompted; a 404 is not news
    return;
  }
  try {
    const body = await readFile(join(ROOT, path));
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
  // A finger that lands on `label` and travels (dx, dy) before lifting.
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

  if (consoleErrors.length) fail(`console errors:\n  ${consoleErrors.join("\n  ")}`);
  if (!process.exitCode) {
    console.log("\nKEYS-BAR GATE PASS: keys fire on a tap not a drag; a touch device opens with the keyboard reachable");
  }
} finally {
  if (!process.argv.includes("--keep")) await browser.close();
  server.close();
}
