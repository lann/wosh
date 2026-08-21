// Native text selection on phones, via an invisible selectable mirror
// of the visible viewport.
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
// transparent `div` holding one text row per visible terminal row,
// mirroring the viewport character for character, with the font
// metrics forced so that one DOM character advances exactly one
// terminal cell. The user sees the webgl glyphs as always; the
// platform sees selectable text lined up on top of them, and does all
// the selection work itself. Taps and drags keep bubbling through to
// xterm underneath, so nothing else about the terminal changes.
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
// Known limits, both deliberate:
//
//   - selection is confined to the VISIBLE viewport. The mirror only
//     holds the rows on screen, so a selection cannot be dragged into
//     the scrollback; scrolling dismisses it instead (see below).
//   - wide (CJK) glyphs drift the highlight. The cell advance is
//     enforced with `letter-spacing`, which is per-GLYPH, not
//     per-CELL, so a double-width character occupies one advance in
//     the mirror where the terminal gives it two, and everything after
//     it on that row slides left of the glyphs it highlights. The
//     COPIED text is still exact -- it comes from the mirror's own
//     characters, which are the buffer's -- only the highlight
//     rectangle lies.

const STYLE_ID = "touch-select-style";

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
 */
export const initTouchSelect = (term) => {
  if (!matchMedia("(pointer: coarse)").matches) return;
  const screen = term.element?.querySelector(".xterm-screen");
  if (!screen) return;

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
    "overflow:hidden",
    "margin:0",
  ].join(";");
  screen.appendChild(layer);

  const rows = []; // one div per visible terminal row, each with one text node

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
      layer.appendChild(div);
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
    for (let r = 0; r < rows.length; r++) {
      const line = buf.getLine(buf.viewportY + r);
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
      const next = buf.getLine(buf.viewportY + r + 1);
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

  rebuildRows();
  sync();

  term.onRender(schedule);
  term.onResize(() => {
    rebuildRows();
    metricsKey = ""; // the cell box changed under us
    schedule();
  });

  // Cheap on purpose: this fires continuously while a selection handle
  // is being dragged.
  document.addEventListener("selectionchange", () => {
    const sel = document.getSelection();
    const holding = Boolean(sel) && !sel.isCollapsed && layer.contains(sel.anchorNode);
    if (holding === frozen) return;
    frozen = holding;
    if (!frozen) schedule(); // catch up on everything the freeze skipped
  });

  // A highlight over text that has scrolled away is a lie -- the
  // mirror only ever holds the visible viewport, so the characters
  // under the selection are about to become different characters.
  // Dropping the selection is the honest answer. It does mean a
  // selection held while output streams at the bottom gets dismissed
  // by that output; coherent, if unfriendly.
  term.onScroll(() => {
    if (!frozen) return;
    document.getSelection()?.removeAllRanges();
    frozen = false;
    schedule();
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
  // wrapped.

  /**
   * Resolve one Range endpoint to a {row, offset} in the mirror, or
   * null when it is anything this handler does not understand.
   * `atEnd` picks the interpretation of an element container: a range
   * boundary before child N reads as the start of row N going forward,
   * and as the end of row N-1 coming backward.
   */
  const locate = (node, offset, atEnd) => {
    if (!node) return null;
    if (node.nodeType === Node.TEXT_NODE) {
      const row = rows.indexOf(node.parentNode);
      return row < 0 ? null : { row, offset };
    }
    if (node === layer) {
      if (atEnd) {
        const row = Math.min(offset, rows.length) - 1;
        if (row < 0) return { row: 0, offset: 0 };
        return { row, offset: rows[row].textContent.length };
      }
      const row = Math.min(offset, rows.length - 1);
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
};
