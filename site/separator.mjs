// The boundary between sessions, drawn where it belongs: in the
// scrollback, anchored to the line where the new session begins.
//
// A fresh shell over old scrollback is easy to misread -- the eye
// runs the old prompt into the new banner and, worse, attributes old
// output to the new host. The separator is an xterm MARKER (a handle
// that tracks one buffer line through scrolling, reflow and trimming)
// carrying a DECORATION (an HTML overlay positioned on that line), so
// it scrolls with the content it separates, is styled like page
// chrome rather than pty output, and can never be confused with
// something the remote printed -- the remote cannot produce it.
//
// The line under the decoration is deliberately blank: decorations
// overlay buffer lines without reserving space, so the separator
// writes its own empty line to stand on and one more below it, and
// only then does the session's first output flow. Both writes are
// awaited by the caller BEFORE the output pump starts, which is what
// keeps the ordering: nothing of the new session can land between
// the old output and its boundary.

/// Draw a labeled separator at the cursor, unless the buffer is
/// pristine -- a first session has nothing to be separated from.
/// Resolves once the separator's lines are in the buffer; the caller
/// must not start pumping session output before then.
export const markSessionStart = async (term, user) => {
  const buf = term.buffer.active;
  if (buf.baseY === 0 && buf.cursorY === 0 && buf.cursorX === 0) {
    return; // nothing above: an unlabeled top beats a dangling label
  }
  const write = (s) => new Promise((resolve) => term.write(s, resolve));

  // End whatever line the dead session left half-written (a shell
  // prompt, usually), then stand on a blank line of our own.
  await write("\r\n");
  const marker = term.registerMarker(0);
  // The session's first output starts below the separator's line.
  await write("\r\n");
  if (!marker) {
    return; // no marker, no decoration; the blank lines still separate
  }

  const decoration = term.registerDecoration({ marker, width: term.cols });
  if (!decoration) {
    return;
  }
  const when = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  decoration.onRender((element) => {
    // onRender fires on every render of the line; build the element
    // once and let the class carry the styling (index.html).
    if (element.dataset.woshSeparator) {
      return;
    }
    element.dataset.woshSeparator = "1";
    element.classList.add("session-separator");
    element.textContent = `new session — ${user} · ${when}`;
  });
};
