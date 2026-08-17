// Browser links gate: the addon family is wired, and links open on a
// single click ONLY through the confirmation dialog.
//
// What it drives, against the real assembled site (no listener, no
// session -- the terminal's link, width, and image machinery work on
// whatever is in the buffer):
//
//   [1] the addon diagnostics: unicode 11 active, clipboard write-only,
//       links on, image addon present, webgl renderer up. Each is one
//       easily-lost script tag or builder call; this is the gate that
//       can see them.
//   [2] unicode 11 behaviorally: an emoji advances the cursor two
//       cells, matching what a remote pty computes.
//   [3] a click on a painted URL opens the CONFIRMATION, showing the
//       URI verbatim; cancel opens nothing.
//   [4] confirming with "always open" checked opens the link
//       (noopener) and persists the preference;
//   [5] the next click opens directly, no dialog.
//   [6] a sixel lands in the image addon's storage (decode smoke).
//
// Environment:
//   WOSH_HTTP_PORT  static server port (default: 8133)
import { chromium } from "playwright-core";
import { existsSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname } from "node:path";

const ROOT = new URL("../out/", import.meta.url).pathname;
const PORT = Number(process.env.WOSH_HTTP_PORT ?? 8133);
const URL_SHOWN = "https://example.com/probe";

const MIME = { ".html": "text/html", ".mjs": "text/javascript", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm" };
const server = createServer(async (req, res) => {
  try {
    const p = decodeURIComponent(new URL(req.url, "http://x").pathname);
    const f = join(ROOT, p === "/" ? "index.html" : p);
    const b = await readFile(f);
    res.writeHead(200, { "content-type": MIME[extname(f)] ?? "application/octet-stream", "cache-control": "no-store" });
    res.end(b);
  } catch { res.writeHead(404).end(); }
});
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));

function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const glob = `${process.env.HOME}/.cache/ms-playwright`;
  const dirs = readdirSync(glob).filter((d) => d.startsWith("chromium-")).sort();
  for (const d of dirs.reverse()) {
    const p = join(glob, d, "chrome-linux", "chrome");
    if (existsSync(p)) return p;
  }
  throw new Error("no Chromium found; set CHROME_PATH");
}

const browser = await chromium.launch({ executablePath: findChrome(), args: ["--no-sandbox"] });
let failed = false;
const fail = (m) => { console.error(`FAIL: ${m}`); failed = true; };

try {
  const context = await browser.newContext();
  // Opens are observed by stubbing window.open: deterministic, and it
  // works for noopener windows, which never hand back a page object.
  await context.addInitScript(() => {
    window.__opened = [];
    window.open = (uri) => { window.__opened.push(String(uri)); return null; };
  });
  const page = await context.newPage();
  const pageErrors = [];
  page.on("pageerror", (e) => pageErrors.push(String(e)));

  await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: "load" });
  await page.waitForFunction(() => !!window.__wosh?.term && !!window.__wosh?.addons, { timeout: 30_000 });

  // A fresh load shows the home screen over the terminal (there is no
  // session to look at). This gate drives the TERMINAL layer directly
  // -- links painted into xterm, no session -- so lift the chrome out
  // of the way; the home screen's own behavior is browser-mobile's
  // subject.
  await page.waitForFunction(() => !document.getElementById("chrome")?.hidden, null, { timeout: 15_000 });
  await page.evaluate(() => {
    document.getElementById("chrome").hidden = true;
  });

  // [1] the diagnostics: everything wired.
  const addons = await page.evaluate(() => {
    const a = window.__wosh.addons;
    return {
      unicode: a.unicode, clipboard: a.clipboard, links: a.links, image: !!a.image,
      webgl: a.webgl, serialize: a.serialize,
    };
  });
  if (addons.unicode !== "11") fail(`unicode version is ${addons.unicode}, expected "11"`);
  if (addons.clipboard !== "write-only") fail(`clipboard is ${addons.clipboard}, expected write-only`);
  if (!addons.links) fail("web links addon did not load");
  if (!addons.image) fail("image addon did not load");
  if (!addons.webgl) fail("webgl renderer did not load (headless SwiftShader should provide GL)");
  if (!addons.serialize) fail("scrollback serialize addon did not load");
  console.log(`[1] addons wired: ${JSON.stringify(addons)}`);

  // [2] unicode 11, behaviorally: the emoji is two cells wide.
  const cursorX = await page.evaluate(() => new Promise((resolve) => {
    const term = window.__wosh.term;
    term.write("\u{1F642}", () => resolve(term.buffer.active.cursorX));
  }));
  if (cursorX !== 2) fail(`emoji advanced the cursor to ${cursorX}, expected 2 (unicode 11 widths)`);
  else console.log("[2] emoji is two cells wide");

  // Paint a URL on its own row and find where to click it.
  const target = await page.evaluate((url) => new Promise((resolve) => {
    const term = window.__wosh.term;
    term.write(`\r\nsee ${url} done\r\n`, () => {
      // The URL sits on the row before the cursor's; "see " is 4 cells.
      const row = term.buffer.active.cursorY - 1;
      resolve({ row, col: 4 + Math.floor(url.length / 2), cols: term.cols, rows: term.rows });
    });
  }), URL_SHOWN);
  const screen = await page.locator(".xterm-screen").boundingBox();
  const cellW = screen.width / target.cols;
  const cellH = screen.height / target.rows;
  const at = {
    x: screen.x + cellW * (target.col + 0.5),
    y: screen.y + cellH * (target.row + 0.5),
  };
  // Hover first: the linkifier resolves links on pointer movement, and
  // the click must land on an already-live link. The detour makes the
  // approach a real movement even when the pointer is already at the
  // target (a same-point move produces no mousemove, and no mousemove
  // means no re-linkification after a dialog).
  const clickLink = async () => {
    await page.mouse.move(screen.x + screen.width - 4, screen.y + screen.height - 4);
    await page.waitForTimeout(60);
    await page.mouse.move(at.x, at.y);
    await page.waitForTimeout(150);
    await page.mouse.click(at.x, at.y);
  };

  // [3] click -> dialog with the verbatim URI; cancel opens nothing.
  await clickLink();
  await page.waitForFunction(() => document.getElementById("linkdialog")?.open, null, { timeout: 5_000 });
  const shown = await page.evaluate(() => document.querySelector("#linkdialog code")?.textContent);
  if (shown !== URL_SHOWN) fail(`dialog shows "${shown}", expected "${URL_SHOWN}"`);
  await page.click("#linkdialog button:has-text('cancel')");
  await page.waitForFunction(() => !document.getElementById("linkdialog")?.open, null, { timeout: 5_000 });
  let opened = await page.evaluate(() => window.__opened.length);
  if (opened !== 0) fail(`cancel still opened ${opened} window(s)`);
  else console.log("[3] click confirmed, cancel opened nothing");

  // [4] confirm with "always open" checked: opens, and persists.
  await clickLink();
  await page.waitForFunction(() => document.getElementById("linkdialog")?.open, null, { timeout: 5_000 });
  await page.check("#linkdialog #link-remember");
  await page.click("#linkdialog button:has-text('open')");
  await page.waitForFunction(() => window.__opened.length === 1, null, { timeout: 5_000 });
  const first = await page.evaluate(() => window.__opened[0]);
  if (first !== URL_SHOWN) fail(`opened "${first}", expected "${URL_SHOWN}"`);
  const pref = await page.evaluate(() => localStorage.getItem("wosh.links.v1"));
  if (pref !== "open") fail(`preference is ${JSON.stringify(pref)}, expected "open"`);
  console.log("[4] confirmed open landed and the preference stuck");

  // [5] with the preference set, the next click opens directly.
  await clickLink();
  await page.waitForFunction(() => window.__opened.length === 2, null, { timeout: 5_000 });
  if (await page.evaluate(() => document.getElementById("linkdialog")?.open)) {
    fail("the dialog reopened despite the always-open preference");
  } else {
    console.log("[5] preference honored: opened without asking");
  }

  // [6] a sixel decodes into the image addon's storage.
  const usage = await page.evaluate(() => new Promise((resolve) => {
    const term = window.__wosh.term;
    // A 40x12 red block, as DCS q ... ST: color 0 = rgb(100%,0,0),
    // two sixel rows of 40 columns each.
    term.write("\r\n\x1bPq#0;2;100;0;0#0!40~-!40~\x1b\\\r\n", () => {
      resolve(window.__wosh.addons.image.storageUsage);
    });
  }));
  if (!(usage > 0)) fail(`image storage is ${usage} after a sixel, expected > 0`);
  else console.log(`[6] sixel decoded (storage ${usage} MB)`);

  // [7] scrollback persistence is CONTENT-ONLY, both directions.
  //
  // A dump serialized while a tmux session held the terminal (alt
  // screen, mouse tracking on) once replayed those MODES on restore:
  // the next session never re-enabled mouse tracking, so every touch
  // and wheel event was typed into the pty as escape junk instead of
  // scrolling -- "unresponsive until reload". Two contracts pin the
  // fix, on scratch terminals fed a worst-case fixture:
  //   save side: serialize(SCROLLBACK_SERIALIZE_OPTIONS) emits no
  //     mode sequences and no alt-buffer content;
  //   restore side: SCROLLBACK_MODE_RESET written after an OLD-format
  //     dump (modes included) leaves the terminal back at defaults.
  const modes = await page.evaluate(() => new Promise((resolve) => {
    (async () => {
      const app = await import("./app.mjs");
      const mk = () => {
        const t = new window.Terminal({ allowProposedApi: true });
        const host = document.createElement("div");
        document.body.append(host);
        t.open(host);
        return t;
      };
      const writeAll = (t, s) => new Promise((r) => t.write(s, r));
      // The worst case a save can see: mouse tracking, application
      // cursor keys, and the alt screen with content on it.
      const fixture = "normal-line\r\n\x1b[?1000h\x1b[?1h\x1b[?1049halt-only-content";

      const saver = mk();
      const ser = new window.SerializeAddon.SerializeAddon();
      saver.loadAddon(ser);
      await writeAll(saver, fixture);
      const dump = ser.serialize(app.SCROLLBACK_SERIALIZE_OPTIONS);

      const restorer = mk();
      await writeAll(restorer, fixture); // an old-format dump: modes and all
      await writeAll(restorer, app.SCROLLBACK_MODE_RESET);

      // The save gate: a terminal parked on the alternate screen is
      // not worth dumping (tmux/vim repaint it themselves, and the
      // stale normal buffer would overwrite a better dump); one that
      // has come back is. The `saver` terminal is on the alt screen
      // from the fixture; leaving it must flip the verdict.
      const worthOnAlt = app.dumpWorthSaving(saver);
      await writeAll(saver, "\x1b[?1049l");
      const worthOnNormal = app.dumpWorthSaving(saver);

      resolve({
        dumpHasMouse: dump.includes("[?1000h"),
        dumpHasAppCursor: dump.includes("[?1h"),
        dumpHasAlt: dump.includes("[?1049h") || dump.includes("alt-only-content"),
        dumpHasContent: dump.includes("normal-line"),
        resetMouse: restorer.modes.mouseTrackingMode,
        resetAppCursor: restorer.modes.applicationCursorKeysMode,
        resetBuffer: restorer.buffer.active.type,
        worthOnAlt,
        worthOnNormal,
      });
    })();
  }));
  if (modes.dumpHasMouse || modes.dumpHasAppCursor || modes.dumpHasAlt) {
    fail(`serialized dump leaks modes or alt content: ${JSON.stringify(modes)}`);
  } else if (!modes.dumpHasContent) {
    fail("serialized dump lost the normal-buffer content it exists to keep");
  } else if (modes.resetMouse !== "none" || modes.resetAppCursor || modes.resetBuffer !== "normal") {
    fail(`mode reset left state behind: ${JSON.stringify(modes)}`);
  } else if (modes.worthOnAlt || !modes.worthOnNormal) {
    fail(`the alt-screen save gate answered wrong: ${JSON.stringify(modes)}`);
  } else {
    console.log("[7] scrollback dumps carry content only; the restore reset returns a dirtied terminal to defaults; saves wait out the alt screen");
  }

  if (pageErrors.length) fail(`page errors:\n  ${pageErrors.join("\n  ")}`);
  if (!failed) {
    console.log("\nBROWSER LINKS PASS: addon family wired (unicode 11 widths, write-only OSC 52," +
      " webgl, sixel), links open on a single click only through the confirmation" +
      " -- verbatim URI, cancel is free, always-open is opt-in and persists --" +
      " and scrollback dumps are content-only in both directions");
  }
} catch (e) {
  fail(String(e?.stack ?? e));
} finally {
  await browser.close();
  server.close();
}
process.exitCode = failed ? 1 : 0;
