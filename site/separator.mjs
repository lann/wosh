// The session timeline, drawn where it belongs: in the scrollback,
// anchored to the lines where sessions begin and end.
//
// A fresh shell over old scrollback is easy to misread -- the eye
// runs the old prompt into the new banner and, worse, attributes old
// output to the new host. So every session is BOOKENDED: a start rule
// when it opens (first session included -- the timeline starts at the
// top), and an end rule the moment the client knows the session is
// over for good (terminal.wit's close-kind arriving, or a deliberate
// detach). A resumable outage draws nothing: the session is not over,
// and an end mark that might be taken back would be a lie.
//
// Each rule is an xterm MARKER (a handle that tracks one buffer line
// through scrolling, reflow and trimming) carrying a DECORATION (an
// HTML overlay positioned on that line), so it scrolls with the
// content it bounds, is styled like page chrome rather than pty
// output, and can never be confused with something the remote
// printed -- the remote cannot produce it.
//
// The line under a decoration is deliberately blank: decorations
// overlay buffer lines without reserving space, so each rule writes
// its own empty line to stand on and one more below it. The writes
// are awaited by the caller at points where no session output can
// interleave (before the pump starts; after it has stopped), which is
// what keeps every boundary exactly between the outputs it separates.

const draw = async (term, variant, label) => {
  const write = (s) => new Promise((resolve) => term.write(s, resolve));
  // Flush whatever is queued before measuring anything. term.write is
  // asynchronous -- xterm parses on its own schedule -- so a caller
  // that wrote without awaiting leaves term.buffer describing a state
  // the parser has not reached yet. A marker registered against that
  // stale buffer tracks the WRONG line, and a decoration is an overlay,
  // so it then gets drawn across whatever text really lands there. An
  // empty write is the cheapest wait for the queue: its callback runs
  // when the parser reaches it.
  await write("");
  const buf = term.buffer.active;
  // End whatever line is half-written (a dead session's prompt,
  // usually); a pristine buffer has no line to end.
  if (buf.baseY !== 0 || buf.cursorY !== 0 || buf.cursorX !== 0) {
    await write("\r\n");
  }
  const marker = term.registerMarker(0);
  // What follows starts below the rule's line.
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
    // once and let the classes carry the styling (index.html).
    if (element.dataset.woshSeparator) {
      return;
    }
    element.dataset.woshSeparator = variant;
    element.classList.add("session-separator", variant);
    element.textContent = `${label} · ${when}`;
  });
};

/// The opening bookend, drawn before the session's first output.
export const markSessionStart = (term, user) =>
  draw(term, "start", `session start — ${user}`);

/// The closing bookend: `what` names how it ended ("session lost",
/// "session ended", "detached"), because a timeline of connects and
/// disconnects is only as good as its disconnect labels.
export const markSessionEnd = (term, what) => draw(term, "end", what);
