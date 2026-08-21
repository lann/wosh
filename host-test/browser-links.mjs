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

  // [2b] Dragging ACROSS a link is a SELECTION, not an activation. The
  // browser reports a press-move-release as a click on the element the
  // release landed on, so highlighting a line that happens to contain a
  // URL used to throw up the confirmation dialog -- and the reflex when
  // a dialog appears is to dismiss it, which loses the selection the
  // drag was for. Asserted before the click legs, so a regression here
  // cannot hide behind a preference they set.
  {
    await page.mouse.move(screen.x + screen.width - 4, screen.y + screen.height - 4);
    await page.waitForTimeout(60);
    // Start ON the URL and drag along it. That is the gesture xterm
    // actually activates on: its linkifier fires only when the press
    // and the release are on the SAME link, so a drag that begins off
    // the link never reached this code and would prove nothing.
    const from = { x: screen.x + cellW * 5.5, y: at.y };
    await page.mouse.move(from.x, from.y);
    await page.mouse.down();
    for (let i = 1; i <= 6; i++) {
      await page.mouse.move(from.x + ((at.x - from.x) * i) / 6, at.y);
      await page.waitForTimeout(20);
    }
    await page.mouse.up();
    await page.waitForTimeout(400);
    const after = await page.evaluate(() => ({
      dialog: document.getElementById("linkdialog")?.open ?? false,
      selection: window.__wosh.term.getSelection(),
    }));
    if (after.dialog) {
      fail("dragging across a link opened the confirmation dialog instead of selecting");
      await page.evaluate(() => document.getElementById("linkdialog")?.close());
    } else if (after.selection.trim().length < 4) {
      // Both ends land inside the URL (that is the point: press and
      // release must be on the SAME link, which is the only gesture
      // xterm activates on), so the selection is a run of it.
      fail(`the drag selected nothing useful (${JSON.stringify(after.selection)}), so this leg proves nothing`);
    } else {
      console.log("[2b] dragging across a link highlights it and opens nothing");
    }
    await page.evaluate(() => window.__wosh.term.clearSelection());
  }

  // [2c] A tap that DISMISSES a live selection is not a click on
  // whatever it landed on. The touch selection overlay (site/
  // touch-select.mjs) selects real DOM text, which the terminal's own
  // hasSelection() cannot see at all -- so the [2b] guard above is
  // blind to it, and the first tap after selecting something would
  // both clear the highlight and open the link under the finger. The
  // guard that catches it records the selection state at PRESS time,
  // because by activation time the press has already cleared it.
  // Selected here on the page's own status text: any DOM selection
  // outside the terminal exercises the same path, and it needs no
  // touch emulation to build.
  {
    await page.evaluate(() => {
      const sel = window.getSelection();
      sel.removeAllRanges();
      const range = document.createRange();
      range.selectNodeContents(document.getElementById("status"));
      sel.addRange(range);
    });
    const live = await page.evaluate(() => !window.getSelection().isCollapsed);
    if (!live) {
      fail("could not build a DOM selection outside the terminal, so this leg proves nothing");
    } else {
      await clickLink();
      await page.waitForTimeout(400);
      const dismissed = await page.evaluate(() => document.getElementById("linkdialog")?.open ?? false);
      if (dismissed) {
        fail("clicking while a DOM selection was up opened the link as well as dismissing it");
        await page.evaluate(() => document.getElementById("linkdialog")?.close());
      } else {
        // ...and with nothing selected, the very same click still works:
        // the guard declines a dismissing tap, not every tap afterwards.
        await page.evaluate(() => window.getSelection().removeAllRanges());
        await clickLink();
        await page.waitForFunction(() => document.getElementById("linkdialog")?.open, null, { timeout: 5_000 })
          .then(
            async () => {
              await page.click("#linkdialog button:has-text('cancel')");
              await page.waitForFunction(() => !document.getElementById("linkdialog")?.open, null, { timeout: 5_000 });
              console.log("[2c] a click that dismisses a selection opens nothing; the next one still opens");
            },
            () => fail("the press-time selection guard swallowed the following click too: links would stop opening after any selection"),
          );
      }
    }
    await page.evaluate(() => window.getSelection().removeAllRanges());
  }

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
  // [10] The seam after a restore: a dump ends by restoring the cursor
  // where it WAS, which a full-screen redraw leaves ABOVE the last line
  // of content. Everything the page appends next -- the "[wosh]
  // restored scrollback" note and the session start rule -- then landed
  // ON restored lines, leaving their tails sticking out beside it, and
  // the rule (a DECORATION, i.e. an overlay) was drawn across live
  // text. Both halves are pinned here: nothing overwrites restored
  // content, and the rule stands on a blank line.
  const seam = await page.evaluate(() => new Promise((resolve) => {
    (async () => {
      const app = await import("./app.mjs");
      const { markSessionStart } = await import("./separator.mjs");
      const t = new window.Terminal({ allowProposedApi: true, rows: 12, cols: 80 });
      const host = document.createElement("div");
      document.body.append(host);
      t.open(host);
      const write = (s) => new Promise((r) => t.write(s, r));
      // Three lines of "restored" content, then the cursor sent back
      // home -- exactly what a redraw-on-attach leaves behind.
      await write("banner line one\r\n * Documentation:  https://docs.example\r\n * Support: pro\r\n");
      await write("\x1b[H");

      await app.parkBelowContent(t);
      // app.mjs's own seam note, then the bookend.
      await write("\r\n\x1b[2m[wosh] restored scrollback from 2 h ago\x1b[0m\r\n");
      await markSessionStart(t, "lann");
      await write("live session output\r\n");
      await new Promise((r) => setTimeout(r, 150));

      const b = t.buffer.active;
      const line = (i) => b.getLine(i)?.translateToString(true) ?? "";
      const rows = [];
      for (let i = 0; i < b.length; i++) rows.push(line(i));
      // Which buffer row is the rule drawn over? Decorations are
      // overlays positioned in pixels, so measure it the way the eye
      // does.
      const el = document.querySelectorAll(".session-separator");
      const rule = el[el.length - 1];
      const screen = host.querySelector(".xterm-screen").getBoundingClientRect();
      const box = rule?.getBoundingClientRect();
      const cell = screen.height / t.rows;
      const ruleRow = box ? Math.round((box.top - screen.top) / cell) : -1;
      resolve({
        rows: rows.filter((l) => l.trim()),
        ruleText: rule?.textContent ?? "",
        under: ruleRow >= 0 ? line(b.viewportY + ruleRow) : "(no rule)",
      });
    })();
  }));
  {
    const intact = (s) => seam.rows.some((l) => l.trim() === s);
    const damaged = seam.rows.filter((l) => /\[wosh\].*\S/.test(l) && !/\[wosh\] restored scrollback from 2 h ago$/.test(l.trim()));
    if (!intact("banner line one") || !intact("* Documentation:  https://docs.example") ||
        !intact("* Support: pro")) {
      fail(`the restore seam overwrote restored content: ${JSON.stringify(seam.rows)}`);
    } else if (damaged.length) {
      fail(`the seam note landed on top of restored text: ${JSON.stringify(damaged)}`);
    } else if (seam.under.trim() !== "") {
      fail(`the session rule is drawn across "${seam.under.trim()}" instead of a blank line`);
    } else {
      console.log("[10] a restore seam appends: nothing overwritten, the rule stands on a blank line");
    }
  }

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

  // [E] esc-intercept hint (site/esc-watch.mjs): a vim-keys extension
  // suppresses Esc's key events entirely and blurs the field, so the
  // only observable signature is the blur's shape. The gate drives
  // that shape directly with a real, programmatic textarea.blur() --
  // exactly what the detector is built to catch, and the reason it
  // does not check event.isTrusted (see esc-watch.mjs's header).
  const settleWait = () => page.waitForTimeout(350); // past the 300ms explaining-event window

  // [E1] an uncaused blur (no precursor within the window) shows the
  // banner with both of its buttons.
  await page.evaluate(() => window.__wosh.term.focus());
  await settleWait();
  await page.evaluate(() => window.__wosh.term.textarea.blur());
  await page.waitForFunction(() => !document.getElementById("escbanner")?.hidden, null, { timeout: 5_000 })
    .then(
      async () => {
        const buttons = await page.evaluate(() => ({
          dismiss: !!document.querySelector("#escbanner .dismiss"),
          never: !!document.querySelector("#escbanner .never"),
        }));
        if (!buttons.dismiss || !buttons.never) fail(`escbanner missing a button: ${JSON.stringify(buttons)}`);
        else console.log("[E1] an uncaused blur on the terminal shows the esc-intercept banner");
      },
      () => fail("an uncaused blur (no click, no Tab) did not show the esc-intercept banner"),
    );

  // [E2] dismiss hides it and returns focus; the detector then STAYS
  // disarmed for the rest of the page load (one nag per load, not one
  // per Esc -- Esc-in-vim would otherwise nag on every keystroke).
  await page.click("#escbanner .dismiss");
  const afterDismiss = await page.evaluate(() => ({
    hidden: document.getElementById("escbanner").hidden,
    focused: document.activeElement === window.__wosh.term.textarea,
  }));
  if (!afterDismiss.hidden) fail("dismiss did not hide the banner");
  else if (!afterDismiss.focused) fail("dismiss did not return focus to the terminal");
  else console.log("[E2] dismiss hides the banner and returns focus to the terminal");
  await settleWait();
  await page.evaluate(() => window.__wosh.term.textarea.blur());
  await page.waitForTimeout(400);
  if (await page.evaluate(() => document.getElementById("escbanner").hidden)) {
    console.log("[E2] disarmed for the rest of the page load: a second uncaused blur shows nothing");
  } else {
    fail("the banner reappeared after dismiss -- the detector should disarm for the page load");
    await page.evaluate(() => { document.getElementById("escbanner").hidden = true; });
  }

  // [E3] a fresh load, so the detector is armed again: an EXPLAINED
  // blur (a click elsewhere, or Tab-away) must never show the banner,
  // and arming survives explained blurs -- only the next UNCAUSED one
  // fires.
  await page.reload({ waitUntil: "load" });
  await page.waitForFunction(() => !!window.__wosh?.term, null, { timeout: 30_000 });
  await page.evaluate(() => { document.getElementById("chrome").hidden = true; });
  await page.evaluate(() => window.__wosh.term.focus());
  await settleWait();
  // A click on #bar: pointerdown precedes the blur.
  const bar = await page.locator("#bar").boundingBox();
  await page.mouse.click(bar.x + bar.width / 2, bar.y + bar.height / 2);
  await page.waitForTimeout(400);
  let stillHidden = await page.evaluate(() => document.getElementById("escbanner").hidden);
  if (!stillHidden) fail("a click-away blur (pointerdown precedes it) showed the banner");

  await page.evaluate(() => window.__wosh.term.focus());
  await settleWait();
  await page.keyboard.press("Tab"); // keydown:Tab precedes the blur
  await page.waitForTimeout(400);
  stillHidden = await page.evaluate(() => document.getElementById("escbanner").hidden);
  if (!stillHidden) fail("a Tab-away blur (keydown precedes it) showed the banner");
  else console.log("[E3] click-away and Tab-away blurs are explained and never show the banner");

  await page.evaluate(() => window.__wosh.term.focus());
  await settleWait();
  await page.evaluate(() => window.__wosh.term.textarea.blur());
  if (await page.waitForFunction(() => !document.getElementById("escbanner").hidden, null, { timeout: 5_000 }).then(() => true, () => false)) {
    console.log("[E3] arming survives explained blurs: the next uncaused one still shows the banner");
  } else {
    fail("after two explained blurs, an uncaused blur no longer showed the banner");
  }

  // [E4] "don't show again" hides it AND persists the opt-out; a fresh
  // load then never shows the banner again, uncaused blur included.
  await page.click("#escbanner .never");
  const escPref = await page.evaluate(() => localStorage.getItem("wosh.eschint.v1"));
  if (await page.evaluate(() => document.getElementById("escbanner").hidden)) {
    if (escPref !== "off") fail(`"don't show again" did not persist the preference (got ${JSON.stringify(escPref)})`);
    else console.log("[E4] \"don't show again\" hides the banner and persists the preference");
  } else {
    fail("\"don't show again\" did not hide the banner");
  }
  await page.reload({ waitUntil: "load" });
  await page.waitForFunction(() => !!window.__wosh?.term, null, { timeout: 30_000 });
  await page.evaluate(() => { document.getElementById("chrome").hidden = true; });
  await page.evaluate(() => window.__wosh.term.focus());
  await settleWait();
  await page.evaluate(() => window.__wosh.term.textarea.blur());
  await page.waitForTimeout(400);
  if (await page.evaluate(() => document.getElementById("escbanner").hidden)) {
    console.log("[E4] the opt-out sticks across a reload: the banner never returns");
  } else {
    fail("the \"don't show again\" preference did not survive a reload");
  }
  // Clean up so later runs (and other gates sharing localStorage
  // fixtures) are unaffected.
  await page.evaluate(() => localStorage.removeItem("wosh.eschint.v1"));

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
