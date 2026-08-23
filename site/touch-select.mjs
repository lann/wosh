// Native text selection on phones, via an invisible selectable mirror
// of the terminal's rows.
//
// The problem: the terminal screen is a webgl canvas under
// `.xterm { user-select: none }`, and xterm's own selection answers
// only to a mouse -- it has no touch path at all. So a finger on a
// phone cannot select terminal text, and the platform's selection
// machinery (word select on long-press, drag handles, the magnifier,
// the floating Copy toolbar) never engages, because there is no real
// DOM text under the finger for it to bite on.
//
// The fix is to give it some. This mounts an always-present, fully
// transparent `div` holding one text row per terminal row, mirroring
// the buffer character for character, with the font metrics forced so
// that one DOM character advances exactly one terminal cell. The user
// sees the webgl glyphs as always; the platform sees selectable text
// lined up on top of them, and does all the selection work itself.
// Taps and drags keep bubbling through to xterm underneath, so nothing
// else about the terminal changes.
//
// WHERE it mounts is load-bearing: inside `.xterm-screen`. xterm's
// linkifier binds mousemove/mousedown/mouseup on `.xterm-screen`,
// while the selection service and the contextmenu handler bind on
// `.xterm`. A tap on the overlay produces compatibility mouse events
// that bubble from the overlay outward -- so a descendant of
// `.xterm-screen` passes through BOTH. Mounted one level up (on
// `.xterm`, say) the link taps would silently stop working, because
// the linkifier would never see the events.
//
// TWO LEVELS, and why. The `layer` is the clip box: an explicit pixel
// size and `overflow: hidden`, so mirrored scrollback never paints
// over the rest of the page. Its one child, the `sheet`, is what
// actually moves. While a selection is held the mirror stops tracking
// the viewport and anchors itself to BUFFER rows instead -- the rows
// already mirrored keep their text, the sheet is translated so they
// stay glued to the lines they were copied from, and rows are revealed
// at whichever edge the viewport uncovers. Translating the LAYER
// instead would carry its own clip region along with the rows, which
// is the whole reason for the extra level.
//
// That is what lets a selection run past the edge of the screen: pan
// with a finger and the highlight rides with its text, or drag a
// handle onto the top/bottom visible row and the view ratchets a
// couple of lines at a time (see the ratchet below).
//
// Known limits, all deliberate:
//
//   - while a selection is held the mirror is a SNAPSHOT, and that now
//     covers scrolled-to rows as well. Output arriving underneath (or
//     the scrollback trimming at capacity, which shifts every absolute
//     index down) can leave the canvas saying something the frozen
//     mirror does not. What gets COPIED is still exactly the characters
//     the user highlighted; only the glyphs behind the tint can drift.
//     This is the same trade the freeze has always made for the visible
//     viewport.
//   - terminal refits are DEFERRED while a selection is held, and run
//     on release (see `guardRefit`). Starting a native selection blurs
//     xterm's hidden textarea -- the platform steals focus for
//     selection on non-editable text, and that is not cancellable -- so
//     the soft keyboard closes, the visual viewport grows, and a refit
//     would reflow the terminal under a frozen mirror: handles left
//     floating where the content used to be. Refusing the reflow until
//     the selection is released is the only answer that does not
//     require lying about focus (see mobile.mjs's autofocusTerminal).
//     The terminal is top-anchored, so the box growing underneath just
//     adds blank space below the canvas; nothing under the selection
//     moves.
//   - wide (CJK) glyphs drift the highlight. The cell advance is
//     enforced with `letter-spacing`, which is per-GLYPH, not
//     per-CELL, so a double-width character occupies one advance in
//     the mirror where the terminal gives it two, and everything after
//     it on that row slides left of the glyphs it highlights. The
//     COPIED text is still exact -- it comes from the mirror's own
//     characters, which are the buffer's -- only the highlight
//     rectangle lies.

const STYLE_ID = "touch-select-style";

// Device-feel numbers, both for the edge ratchet: how far one step
// carries the view, and how often a step may happen. Two lines is small
// enough that a handle held at the edge reads as a crawl rather than a
// jump, and 80ms is slower than the browser re-extends a selection
// under a jittering finger, which is what arms the next step.
const RATCHET_LINES = 2;
const RATCHET_MS = 80;

// The highlight is drawn by the platform over glyphs that are painted
// by webgl UNDERNEATH us, so the selected text must stay transparent:
// only the tint is ours to contribute.
const STYLE_TEXT = `
.touch-select-layer::selection { background: rgba(74,126,192,0.45); color: transparent; }
`;

const injectStyle = () => {
  if (document.getElementById(STYLE_ID)) return; // once per document
  const el = document.createElement("style");
  el.id = STYLE_ID;
  el.textContent = STYLE_TEXT;
  document.head.appendChild(el);
};

/**
 * Measure the natural advance of one character in a given font, by
 * laying out a run of them offscreen and dividing. Twenty is enough
 * that sub-pixel rounding on the run washes out, and `M` is the widest
 * ASCII glyph -- in the monospace fonts a terminal uses every ASCII
 * character advances identically anyway, so any of them would do.
 */
const measureAdvance = (fontFamily, fontSize) => {
  const probe = document.createElement("span");
  probe.style.cssText =
    "position:absolute;visibility:hidden;white-space:pre;letter-spacing:normal;" +
    `font-family:${fontFamily};font-size:${fontSize}px;`;
  probe.textContent = "M".repeat(20);
  document.body.appendChild(probe);
  const width = probe.getBoundingClientRect().width / 20;
  probe.remove();
  return width;
};

/**
 * Mount the selection mirror on a live terminal.
 *
 * Inert unless the device has a coarse pointer -- desktop selects with
 * the mouse through xterm's own machinery, which works -- and inert
 * against a terminal that has not been opened into the DOM (the gates'
 * stub terminals), which is why nothing is subscribed until the mount
 * has actually succeeded.
 *
 * Returns `{ guardRefit }`: the wrapper the page puts around its refit
 * callbacks. Where the mirror never mounted it is the identity, so
 * desktop refits exactly as it always did.
 */
export const initTouchSelect = (term) => {
  const passthrough = { guardRefit: (fn) => fn };
  if (!matchMedia("(pointer: coarse)").matches) return passthrough;
  const screen = term.element?.querySelector(".xterm-screen");
  if (!screen) return passthrough;

  injectStyle();

  const layer = document.createElement("div");
  layer.className = "touch-select-layer";
  layer.style.cssText = [
    "position:absolute",
    "top:0",
    "left:0",
    // Above both canvases, below `.xterm-helpers` (z-index 5) so
    // xterm's hidden textarea and its decorations keep their layer.
    "z-index:3",
    // `.xterm` sets `user-select: none` on the whole subtree; this is
    // the exemption that makes the mirror selectable at all.
    "user-select:text",
    "-webkit-user-select:text",
    "color:transparent",
    "background:transparent",
    "white-space:pre",
    // The clip box. Rows mirrored from the scrollback -- the far half
    // of a long selection -- are real, laid-out DOM; this is what keeps
    // them from painting over the rest of the page.
    "overflow:hidden",
    "margin:0",
  ].join(";");
  screen.appendChild(layer);

  // The moving part. Nothing that lines characters up with cells lives
  // here: the font, size, letter-spacing and white-space stay on the
  // layer and inherit down, and ::selection inherits through the
  // highlight model, so the extra level costs neither the grid nor the
  // tint.
  const sheet = document.createElement("div");
  sheet.className = "touch-select-sheet";
  sheet.style.cssText = "position:relative;margin:0";
  layer.appendChild(sheet);

  const rows = []; // one div per mirrored row, each with one text node

  // The ABSOLUTE buffer row (the coordinate `buf.getLine` takes) that
  // rows[0] holds. Equal to viewportY whenever the mirror is tracking
  // the viewport; while a selection is held it stays put, and the sheet
  // is translated by the difference instead.
  let top = 0;

  // Recomputed only when something that feeds them changes; the key
  // below is what "changes" means.
  let metricsKey = "";
  let cellH = 0;
  let cellW = 0;

  const rebuildRows = () => {
    while (rows.length > term.rows) rows.pop().remove();
    while (rows.length < term.rows) {
      const div = document.createElement("div");
      div.appendChild(document.createTextNode(""));
      sheet.appendChild(div);
      rows.push(div);
    }
    metricsKey = ""; // fresh divs carry no row height yet
  };

  /**
   * Line the mirror's characters up with the terminal's cells.
   *
   * The cell size is measured off `.xterm-screen`'s own box rather
   * than computed from the font, so it agrees with whatever the
   * renderer actually did. `letter-spacing` then makes up the
   * difference between the font's natural advance and one cell, which
   * is what puts DOM character N over terminal column N.
   */
  const applyMetrics = () => {
    const rect = screen.getBoundingClientRect();
    if (!rect.height) return false; // detached or not laid out yet
    const fontFamily = term.options.fontFamily;
    const fontSize = term.options.fontSize;
    const key = `${rect.width}x${rect.height}/${term.cols}x${term.rows}/${fontFamily}/${fontSize}`;
    if (key === metricsKey) return true;
    metricsKey = key;

    cellW = rect.width / (term.cols || 1);
    cellH = rect.height / (term.rows || 1);
    const advance = measureAdvance(fontFamily, fontSize);

    layer.style.width = `${rect.width}px`;
    layer.style.height = `${rect.height}px`;
    layer.style.fontFamily = fontFamily;
    layer.style.fontSize = `${fontSize}px`;
    layer.style.letterSpacing = `${cellW - advance}px`;
    for (const div of rows) {
      div.style.height = `${cellH}px`;
      div.style.lineHeight = `${cellH}px`;
    }
    return true;
  };

  // While the platform holds a selection over the mirror, the mirror
  // must stop moving. Live output arriving underneath would otherwise
  // rewrite the very characters the highlight is drawn around, and the
  // user would watch their selection silently become a selection of
  // something else -- or copy text they never highlighted.
  let frozen = false;

  const sync = () => {
    if (frozen) return;
    if (rows.length !== term.rows) rebuildRows();
    if (!applyMetrics()) return;
    const buf = term.buffer.active;
    // Back on the viewport: rows[0] IS the top visible line again, so
    // the sheet has nothing left to make up for.
    top = buf.viewportY;
    sheet.style.transform = "";
    for (let r = 0; r < rows.length; r++) {
      const line = buf.getLine(top + r);
      // UNtrimmed: character offsets in the mirror have to map 1:1
      // onto terminal columns, and trimming would shift everything
      // after a short row's end.
      const text = line ? line.translateToString(false) : "";
      const div = rows[r];
      if (div.firstChild.nodeValue !== text) div.firstChild.nodeValue = text;
      // Whether the NEXT buffer line is a continuation of this one --
      // i.e. this row ended in a soft wrap. Recorded here because the
      // copy handler below needs it and the buffer will have moved on
      // by then.
      const next = buf.getLine(top + r + 1);
      if (next?.isWrapped) div.dataset.joinNext = "1";
      else delete div.dataset.joinNext;
    }
  };

  // Renders arrive far faster than they need to be mirrored; coalesce
  // through a frame, the same way initViewportFit does.
  let raf = null;
  const schedule = () => {
    if (raf === null) {
      raf = requestAnimationFrame(() => {
        raf = null;
        sync();
      });
    }
  };

  /**
   * A fresh row div for one ABSOLUTE buffer line, captured as it reads
   * right now.
   *
   * Only ever used while frozen, where the rows that already exist are
   * untouchable: a Range endpoint lives inside a row's text node, and
   * replacing that node's data collapses the Range (the DOM's
   * CharacterData replacement rules). So the frozen mirror may only
   * GROW, at its edges, and never be rewritten.
   */
  const makeRow = (abs) => {
    const buf = term.buffer.active;
    const line = buf.getLine(abs);
    const div = document.createElement("div");
    div.appendChild(document.createTextNode(line ? line.translateToString(false) : ""));
    if (buf.getLine(abs + 1)?.isWrapped) div.dataset.joinNext = "1";
    div.style.height = `${cellH}px`;
    div.style.lineHeight = `${cellH}px`;
    return div;
  };

  /**
   * Keep the frozen mirror glued to the buffer lines it was copied
   * from, after the viewport moved under it.
   *
   * `top` never moves while a selection is held, so the sheet's offset
   * is simply how far the viewport has walked away from it; rows are
   * revealed at whichever edge the viewport now uncovers. Inserting
   * siblings before or after a Range does not move its endpoints, so
   * this is invisible to the selection. Growth is bounded by the
   * scrollback (1000 lines in app.mjs) -- ~1k divs worst case -- and
   * the whole thing is trimmed back to term.rows by the ordinary
   * sync() on release.
   */
  const reAnchor = () => {
    const buf = term.buffer.active;
    const vy = buf.viewportY;
    while (top > vy) {
      top--;
      const div = makeRow(top);
      rows.unshift(div);
      sheet.insertBefore(div, sheet.firstChild);
    }
    while (top + rows.length < vy + term.rows) {
      const div = makeRow(top + rows.length);
      rows.push(div);
      sheet.appendChild(div);
    }
    // CONTRACT: the design states this invariant as
    // translateY((top - viewportY) * cellH) and separately expects a
    // 3-line scroll UP to leave translateY == 3*cellH. Those disagree:
    // revealing upward walks `top` down until it meets viewportY, so
    // the offset is 0 and the already-mirrored rows are carried down by
    // the 3 divs prepended before them -- which is where their glyphs
    // went. The invariant is what is implemented (it is also what the
    // design's own reAnchor pseudocode computes); the gate asserts both
    // directions, and the downward one is where the offset is nonzero.
    sheet.style.transform = `translateY(${(top - vy) * cellH}px)`;
  };

  // --- deferred refits ---------------------------------------------------
  //
  // A refit under a frozen mirror reflows the terminal beneath a
  // highlight that cannot follow it: see the header. The page hands its
  // refit callbacks through guardRefit, which swallows calls while a
  // selection is held and replays them on release -- once, however many
  // were swallowed, since fitting is idempotent and only the final
  // geometry matters.
  const flushes = [];
  const guardRefit = (fn) => {
    let deferred = false;
    flushes.push(() => {
      if (!deferred) return;
      deferred = false;
      fn();
    });
    return (...args) => {
      if (frozen) {
        deferred = true;
        return;
      }
      fn(...args);
    };
  };
  const flushRefits = () => {
    for (const f of flushes) f();
  };

  // The row div the selection's moving end (the dragged handle) was
  // last seen on, and when the ratchet last stepped. Both reset on
  // thaw: a fresh selection must not inherit the previous one's idea of
  // where its handle came from.
  let lastFocusDiv = null;
  let lastRatchetAt = 0;

  rebuildRows();
  sync();

  term.onRender(schedule);
  term.onResize(() => {
    // The refit gate above is what normally keeps a resize from landing
    // under a live selection. If one arrives anyway -- some future
    // ungated path -- it is exactly the floating-handles bug: the
    // mirror is about to be rebuilt at a geometry the highlight knows
    // nothing about, and a rewrap may have moved the characters
    // themselves onto other lines. Dismissing is the honest fallback.
    if (frozen) {
      document.getSelection()?.removeAllRanges();
      frozen = false;
      lastFocusDiv = null;
    }
    rebuildRows();
    metricsKey = ""; // the cell box changed under us
    schedule();
    flushRefits();
  });

  /**
   * Auto-scroll when a handle is dragged onto the top or bottom visible
   * row, so a selection can be extended past the edge of the screen.
   *
   * Keyed on the focus endpoint CHANGING ROWS, not on it sitting on an
   * edge row: there is no way to know whether a handle is still down
   * (the platform swallows the drag's touch events for its own
   * magnifier and hit testing), so a timer keyed on position would run
   * away on a FINISHED selection whose end happens to rest there. A
   * per-transition step is self-limiting instead -- the step moves the
   * anchored text off the edge row, and only the browser re-extending
   * the selection, which is what a real finger's jitter does, arms
   * another one.
   */
  const ratchet = (sel) => {
    const node = sel.focusNode;
    const div = node?.nodeType === Node.TEXT_NODE ? node.parentNode : node;
    const idx = rows.indexOf(div);
    if (idx < 0) {
      lastFocusDiv = null; // an endpoint this handler cannot place
      return;
    }
    const from = lastFocusDiv;
    lastFocusDiv = div;
    if (!from || from === div) return; // a fresh press, or a drag along one row
    const now = performance.now();
    if (now - lastRatchetAt < RATCHET_MS) return;
    // Which row of the SCREEN the handle is on: rows are indexed in
    // buffer space while frozen, and the viewport is not.
    const view = top + idx - term.buffer.active.viewportY;
    if (view !== 0 && view !== term.rows - 1) return;
    lastRatchetAt = now;
    // xterm clamps scrollLines at both ends, so a step against the top
    // or bottom of the buffer is a harmless no-op. The call fires
    // onScroll synchronously, which re-anchors: the insertions leave
    // the Range alone, and the focus div is unchanged, so no loop.
    term.scrollLines(view === 0 ? -RATCHET_LINES : RATCHET_LINES);
  };

  // Cheap on purpose: this fires continuously while a selection handle
  // is being dragged.
  document.addEventListener("selectionchange", () => {
    const sel = document.getSelection();
    const holding = Boolean(sel) && !sel.isCollapsed && layer.contains(sel.anchorNode);
    if (holding !== frozen) {
      frozen = holding;
      if (!frozen) {
        lastFocusDiv = null;
        schedule(); // catch up on everything the freeze skipped
        flushRefits(); // ...and on the reflows it refused
        return;
      }
    }
    if (frozen) ratchet(sel);
  });

  // Scrolling used to dismiss the selection, because the mirror only
  // ever held the visible viewport and a highlight over departed text
  // was a lie about what would be copied. Anchoring to buffer rows
  // makes it true instead: the mirrored rows keep their characters and
  // stay over their own glyphs, and more of them are revealed as the
  // viewport moves. Unfrozen there is nothing to do here -- onRender
  // already schedules the resync.
  term.onScroll(() => {
    if (frozen) reAnchor();
  });

  // stopPropagation, NOT preventDefault: the platform's own long-press
  // menu is exactly what we want, so the event must not be cancelled
  // -- but it must not reach xterm's contextmenu handler on `.xterm`
  // either, which moves and focuses the hidden textarea (and with
  // rightClickSelectsWord set, re-selects a word) and so fights the
  // native selection in the middle of the long-press. A synthetic
  // contextmenu dispatched straight at `.xterm`, and a real mouse
  // right-click on a touchscreen device, never pass through the layer,
  // so that path is untouched.
  layer.addEventListener("contextmenu", (e) => e.stopPropagation());

  // --- copy: soft wraps must not become hard newlines -------------------
  //
  // The mirror is one div per VISUAL row, so the browser's default copy
  // puts a newline at every wrap -- pasting a wrapped command line back
  // into a shell would break it in half. Rebuild the text from the
  // mirror's own characters instead (which is precisely what the user
  // sees highlighted), joining rows that the buffer says were soft-
  // wrapped. A selection held across a scroll may reach rows that are
  // clipped out of sight; they are still mounted and still hold the
  // characters they were highlighted over, so a multi-screenful copy is
  // just a longer walk.

  /**
   * Resolve one Range endpoint to a {row, offset} in the mirror, or
   * null when it is anything this handler does not understand.
   * `atEnd` picks the interpretation of an element container: a range
   * boundary before child N reads as the start of row N going forward,
   * and as the end of row N-1 coming backward.
   */
  const locate = (node, offset, atEnd) => {
    if (!node || !rows.length) return null;
    if (node.nodeType === Node.TEXT_NODE) {
      const row = rows.indexOf(node.parentNode);
      return row < 0 ? null : { row, offset };
    }
    if (node === sheet || node === layer) {
      // Inside the sheet the offset counts rows directly. The layer's
      // only child is the sheet, so a boundary against IT can only mean
      // "before everything" or "after everything".
      const n = node === sheet ? offset : (offset === 0 ? 0 : rows.length);
      if (atEnd) {
        const row = Math.min(n, rows.length) - 1;
        if (row < 0) return { row: 0, offset: 0 };
        return { row, offset: rows[row].textContent.length };
      }
      const row = Math.max(0, Math.min(n, rows.length - 1));
      return { row, offset: 0 };
    }
    const row = rows.indexOf(node);
    if (row < 0) return null;
    if (offset === 0) return { row, offset: 0 };
    if (offset >= node.childNodes.length) return { row, offset: rows[row].textContent.length };
    return null;
  };

  layer.addEventListener("copy", (e) => {
    try {
      const sel = document.getSelection();
      if (!sel || sel.rangeCount !== 1 || sel.isCollapsed) return;
      const range = sel.getRangeAt(0);
      const start = locate(range.startContainer, range.startOffset, false);
      const end = locate(range.endContainer, range.endOffset, true);
      // Any structural surprise falls through to the browser's own
      // copy: hard newlines at the wraps, which is wrong but is text.
      if (!start || !end || end.row < start.row) return;

      let out = "";
      for (let r = start.row; r <= end.row; r++) {
        const div = rows[r];
        const text = div.textContent;
        const from = r === start.row ? start.offset : 0;
        const to = r === end.row ? end.offset : text.length;
        const slice = text.slice(from, to);
        if (r === end.row) {
          out += slice.trimEnd();
        } else if (div.dataset.joinNext) {
          // A soft wrap is not a line break: no trim (the cells run
          // right up to the edge) and no newline.
          out += slice;
        } else {
          out += `${slice.trimEnd()}\n`;
        }
      }
      e.clipboardData.setData("text/plain", out);
      e.preventDefault();
    } catch {
      /* never throw out of a copy: the default copy is the fallback */
    }
  });

  return { guardRefit };
};
