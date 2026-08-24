// Mobile UX for the wosh page. Six pieces, all inert on desktop:
//
//  - visual-viewport fit: soft keyboards don't resize the window on
//    iOS Safari (the keyboard overlays the page and `resize` never
//    fires), so size #wrap off window.visualViewport instead. Android
//    resizes the layout viewport itself (the
//    `interactive-widget=resizes-content` viewport meta); either way
//    the box change lands in app.mjs's ResizeObserver, which refits.
//
//  - extra-keys bar (#keys): soft keyboards have no Esc/Tab/Ctrl/
//    arrows, which makes a shell unusable. The bar injects the byte
//    sequences through term.input(), i.e. the SAME onData path real
//    typing takes, so session wiring never knows the difference. Ctrl
//    and Alt are sticky one-shot modifiers applied to the NEXT key —
//    from the bar or the soft keyboard — inside transformInput(),
//    which app.mjs runs over every onData chunk. The bar is shown by
//    CSS only on coarse-pointer devices; arming is impossible while
//    hidden, so transformInput is the identity everywhere else.
//
//  - keyboard toggle: tapping the terminal focuses xterm's hidden
//    textarea and summons the keyboard, but there is no way to dismiss
//    it or to get it back after the browser hides it; the ⌨ button
//    blurs/refocuses explicitly. Both paths depend on focus meaning
//    "the keyboard is up", which is why autofocusTerminal() below
//    refuses to focus the terminal where that would be a lie.
//
//  - touch scrolling: xterm scrolls for a mouse and a wheel, not for
//    a finger. Its scrollbar is a drawn widget wired to mousedown, and
//    the viewport element is not natively scrollable (scrollHeight ==
//    clientHeight -- the renderer owns the scroll position), so no
//    touch reaches the scrollback at all; the browser then does what it
//    does with any unclaimed gesture and pans the page instead.
//    initTouchScroll drives it from pointer events, and the CSS says
//    (touch-action) that vertical drags in the terminal are ours.
//    Where the SCROLLBACK is not what a drag should move -- an app
//    tracking the mouse, or any alternate-screen program (tmux, vim,
//    less) whose buffer has no history to show -- the same gesture is
//    forwarded instead, as synthetic wheel events on xterm's screen
//    element, so the finger reaches the remote application through
//    xterm's own mouse machinery. Dragging the scrollbar thumb always
//    stays local: it is the escape hatch back to real history.
//
//  - touch selection: the screen is a webgl canvas under
//    `user-select: none` and xterm's selection answers only to a
//    mouse, so a finger cannot select terminal text at all. An
//    invisible, selectable DOM mirror is mounted inside .xterm-screen,
//    and the platform's OWN selection machinery -- long-press word
//    select, drag handles, the magnifier, the floating Copy toolbar --
//    works on that. A held selection anchors the mirror to BUFFER
//    rows, so panning (or ratcheting a handle against the top/bottom
//    row) carries it across screenfuls of scrollback instead of
//    dismissing it. It also DEFERS terminal refits until the selection
//    is released -- starting a native selection blurs the hidden
//    textarea, which closes the soft keyboard, which grows the visual
//    viewport, and a reflow there would leave the platform's handles
//    floating over content that moved. That is what the `guardRefit`
//    handle below is: app.mjs wraps its refit callbacks in it. See
//    touch-select.mjs.
//
//  - long-press selection (the fallback): the overlay above owns real
//    touch long-presses on phones now, since the platform handles
//    those on the DOM text before xterm ever hears about them. What
//    is left for rightClickSelectsWord is every OTHER contextmenu
//    path -- a mouse right-click on a touchscreen device, a synthetic
//    dispatch -- none of which pass through the overlay. Android
//    reports a long-press as a `contextmenu` event, and xterm's own
//    handler for it will select the word under the finger when
//    rightClickSelectsWord is set, mirroring the text into the hidden
//    textarea the platform's Copy toolbar acts on. Off phones the
//    option keeps its default, so desktop right-click behavior does
//    not change.
//
// No framework, no dependencies; loaded by app.mjs next to the
// terminal it drives.

import { initTouchSelect } from "./touch-select.mjs";

// --- sticky one-shot modifiers (Ctrl/Alt) ------------------------------------

const armed = { ctrl: false, alt: false };
const armButtons = { ctrl: null, alt: null }; // filled by initMobile

const renderArmed = () => {
  for (const k of ["ctrl", "alt"]) {
    armButtons[k]?.classList.toggle("armed", armed[k]);
  }
};

const disarm = () => {
  armed.ctrl = armed.alt = false;
  renderArmed();
};

// Plain arrow sequences (normal and application cursor mode) → the
// xterm-style modified form CSI 1;<mod><letter>. mod: 1+shift(1)+
// alt(2)+ctrl(4).
const ARROW = /^\x1b(?:\[|O)([A-D])$/;

// Chunks that come out of xterm's own reporting rather than out of a
// keystroke: SGR mouse reports (CSI < ...), legacy mouse reports
// (CSI M ...), and focus in/out (CSI I / CSI O, exactly).
const REPORT = /^\x1b\[(?:[<M]|[IO]$)/;

/**
 * Apply armed one-shot modifiers to one onData chunk. Identity when
 * nothing is armed (the desktop / gate path). Called by app.mjs on
 * every chunk BEFORE it reaches the session, so the transform covers
 * soft-keyboard input and bar-injected keys alike.
 */
export const transformInput = (s) => {
  if (!armed.ctrl && !armed.alt) return s;
  // An armed modifier belongs to the user's NEXT KEY, and these chunks
  // are not keys -- the terminal emits them itself while a
  // mouse-tracking app is up. Consuming the arming on one is how "arm
  // Ctrl, scroll, type c" quietly lost its Ctrl: the scroll's own
  // reports flow down this same onData path and ate it.
  if (REPORT.test(s)) return s;
  const { ctrl, alt } = armed;
  disarm(); // one-shot: any input consumes the arming, transformed or not

  const arrow = ARROW.exec(s);
  if (arrow) {
    const mod = 1 + (alt ? 2 : 0) + (ctrl ? 4 : 0);
    return `\x1b[1;${mod}${arrow[1]}`;
  }
  if (s.length !== 1) return s; // paste / IME batch: pass through untouched

  let out = s;
  if (ctrl) {
    const c = s === " " ? "@" : s.toUpperCase(); // Ctrl+Space = NUL
    const code = c.charCodeAt(0);
    if (code >= 0x40 && code < 0x80) out = String.fromCharCode(code & 0x1f);
  }
  return alt ? `\x1b${out}` : out; // ESC-prefix is the Alt/Meta convention
};

// --- the bar + viewport glue ---------------------------------------------------

/**
 * Focus the terminal for typing -- where focus means typing at all.
 *
 * A soft keyboard is an overlay the OS raises, and only for a focus
 * change made inside a user gesture; a programmatic focus() cannot
 * summon one. What it CAN do is leave xterm's hidden textarea holding
 * focus with no keyboard behind it, and from that state every way back
 * in is a no-op: a tap on the terminal refocuses what is already
 * focused (xterm's own handler), and ⌨ reads the stale focus as
 * "keyboard is up" and dismisses instead of summoning. That is the
 * bug where a freshly (re)opened app ignores taps on the terminal and
 * on ⌨ until something defocuses the terminal once, after which
 * everything works. Doing nothing leaves the honest state -- nothing
 * focused -- in which the first tap summons.
 *
 * Desktop still autofocuses, so a page that just opened is typable
 * without clicking it first. Gated on the same predicate as the bar,
 * so the mobile layer agrees with itself about what a phone is.
 */
export const autofocusTerminal = (term) => {
  if (!matchMedia("(pointer: coarse)").matches) term.focus();
};

/**
 * Wire the mobile layer to the live terminal. Idempotent-enough for the
 * page's single call; safe when visualViewport or #keys are absent.
 *
 * Returns `{ guardRefit }` for the caller to wrap its refit callbacks
 * in: refits are deferred while a touch selection is held (see
 * touch-select.mjs). Off a phone it is the identity.
 */
export const initMobile = (term) => {
  initViewportFit();
  initTouchScroll(term);
  initKeysBar(term);
  initLongPressSelect(term);
  const { guardRefit } = initTouchSelect(term);
  return { guardRefit };
};

const initViewportFit = () => {
  const wrap = document.getElementById("wrap");
  const vv = window.visualViewport;
  if (!wrap || !vv) return;

  let raf = null;
  const sync = () => {
    raf = null;
    // While pinch-zoomed the visual viewport is a magnifier over the
    // page — reflowing the terminal to it would fight the user; only
    // track the unzoomed viewport (scale 1 ⇒ keyboard/chrome changes).
    if (Math.abs(vv.scale - 1) > 0.01) return;
    wrap.style.height = `${Math.round(vv.height)}px`;
    // iOS scrolls the page to reveal the focused textarea when the
    // keyboard opens; pin the app box back to the visible top. The
    // refit follows from the box change (app.mjs's ResizeObserver).
    wrap.style.transform = `translateY(${Math.round(vv.offsetTop)}px)`;
  };
  const schedule = () => {
    if (raf === null) raf = requestAnimationFrame(sync);
  };
  vv.addEventListener("resize", schedule);
  vv.addEventListener("scroll", schedule);
};

// --- long-press selection -------------------------------------------------------

/**
 * Enable long-press word selection on coarse-pointer devices -- as the
 * FALLBACK path.
 *
 * The touch overlay (touch-select.mjs) owns real long-presses on a
 * phone: the platform's selection machinery acts on its DOM text and
 * the event never reaches xterm (the overlay stops the contextmenu
 * from propagating, precisely so this handler does not fight it). What
 * this option still covers is every contextmenu that does NOT
 * originate on the overlay -- a mouse right-click on a touchscreen
 * device, a synthetic dispatch -- where selecting the word under the
 * pointer remains the only selection a coarse-pointer page can offer.
 *
 * xterm reads `rightClickSelectsWord` at event time (not just at
 * term.open()), so setting it here after the terminal is already open
 * still takes effect on the very next contextmenu. Upstream's handler
 * (rightClickSelect) also preserves an existing selection when the
 * press lands inside it, replacing it only when it lands outside --
 * so a long-press inside a selection the user already made keeps that
 * selection rather than collapsing it to one word.
 *
 * Gated on the same predicate as the rest of the mobile layer, so
 * desktop right-click behavior is untouched (the option keeps whatever
 * default xterm ships).
 */
const initLongPressSelect = (term) => {
  if (matchMedia("(pointer: coarse)").matches) term.options.rightClickSelectsWord = true;
};

// --- touch scrolling ----------------------------------------------------------

// Travel before a finger is scrolling rather than tapping. Below it the
// gesture still belongs to xterm, which focuses the terminal (and so
// summons the keyboard) on a tap.
const SCROLL_SLOP = 8;

/**
 * Scroll the terminal by finger: drag the content, or drag the
 * scrollbar's thumb.
 *
 * xterm offers nothing here. The scrollbar it draws (a vendored VS Code
 * widget) listens for mousedown, its touch-gesture support is never
 * registered, and .xterm-viewport does not scroll natively -- the
 * renderer keeps the scroll position itself. So a finger on the
 * terminal does nothing at all, and the browser, seeing a gesture
 * nobody claimed, pans the page: "drag the scrollbar a little and it
 * scrolls the viewport instead".
 *
 * Both LOCAL gestures move through the SAME public API the wheel uses
 * (scrollLines), so the renderer, the scrollbar's own position and the
 * alt-buffer rules stay consistent.
 *
 * A content drag has a second possible sink. scrollLines only ever
 * moves the scrollback, and there are two situations where that is not
 * what the finger meant: an application that has turned on mouse
 * tracking wants the wheel itself (tmux's pane scroll, less, a mouse-
 * aware vim), and any alternate-screen program has no scrollback to
 * move at all (baseY is pinned at 0, so the local path was a silent
 * no-op -- "touch scroll does nothing in tmux"). In both, the drag is
 * FORWARDED: turned back into wheel events on xterm's screen element
 * and left to xterm to encode and send. The thumb drag is never
 * forwarded -- the scrollbar is only there to be grabbed when a
 * scrollback exists, and dragging it is how you still read local
 * history while an app owns the wheel.
 */
const initTouchScroll = (term) => {
  const host = document.getElementById("term");
  if (!host) return;

  let held = null; // pointerId of the finger that owns the gesture
  let y0 = 0, x0 = 0;
  let scrolling = false; // decided: this gesture is a scroll, and ours
  let declined = false; // decided the other way, and it stays decided
  let onThumb = false; // grabbed the scrollbar, not the content
  let applied = 0; // lines this gesture has scrolled so far
  let travel = 0; // usable thumb travel, for a scrollbar drag
  let forward = false; // this gesture goes to the app, not the scrollback
  let cellPx = 0; // cell height at claim time, for the forwarded sink
  let emitted = 0; // signed cell-steps already sent as wheel events

  const screenEl = () => host.querySelector(".xterm-screen");

  // One wheel event, on the element xterm listens on, at the finger.
  //
  // Synthetic rather than a hand-encoded CSI on purpose: xterm's
  // CoreMouseService owns the whole protocol -- which encoding was
  // negotiated (X10 vs SGR vs URXVT), which events the active mode
  // reports (1000 vs 1002 vs 1003), the alt-screen fallback that turns
  // a wheel into cursor keys when nothing is tracking, and whether
  // DECCKM makes those keys CSI or SS3. Dispatching UPSTREAM of that
  // machinery means a finger and a real wheel are the same input, and
  // the report it produces rides the same onData -> transformInput ->
  // writeInput path as typing does.
  //
  // The coordinates are the finger's, clamped into the screen's box:
  // the report carries the cell under the pointer (tmux routes the
  // wheel to the pane it lands in), and clamping keeps a drag that
  // overshoots the terminal still reporting instead of going quiet.
  const wheel = (step, clientX, clientY) => {
    const el = screenEl();
    if (!el) return;
    const box = el.getBoundingClientRect();
    const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
    el.dispatchEvent(new WheelEvent("wheel", {
      bubbles: true,
      cancelable: true,
      // ONE LINE per event, said in lines rather than in pixels.
      // xterm's CoreMouseService.consumeWheelEvent treats a PIXEL delta
      // as an estimate: it divides by the cell height, damps anything
      // under 50px to 30% ("this is a trackpad, not a wheel"), and
      // carries the remainder in an accumulator -- so a cell's worth of
      // pixels is 0.3 of a line and three of them scroll nothing at
      // all. DOM_DELTA_LINE is passed through untouched, which is the
      // exact, undamped step this wants. (@xterm/xterm 6.0,
      // CoreMouseService#consumeWheelEvent.)
      deltaMode: 1, // WheelEvent.DOM_DELTA_LINE
      // Finger DOWN reveals earlier content, which is a wheel UP, which
      // is a negative deltaY.
      deltaY: -step,
      clientX: clamp(clientX, box.left + 1, box.right - 1),
      clientY: clamp(clientY, box.top + 1, box.bottom - 1),
    }));
  };

  // Finger travel -> wheel events, one per cell of travel. The count
  // matters: with no tracking active on an alt screen xterm answers a
  // wheel with exactly ONE arrow key regardless of how big its deltaY
  // is, so the only way finger distance and lines stay proportional is
  // to send one event per cell rather than one fat event per move.
  // Measured from the gesture's start (like scrollBy) so rounding
  // cannot accumulate across a slow drag.
  const forwardBy = (dy, x, y) => {
    const target = Math.trunc(dy / cellPx);
    while (emitted !== target) {
      const step = target > emitted ? 1 : -1;
      emitted += step;
      wheel(step, x, y);
    }
  };

  // Lines per CSS pixel of finger movement. Content drags move the
  // text with the finger (down = back into history, so viewportY
  // falls); a thumb drag maps the whole scrollback onto the track the
  // thumb can travel, and moves with the thumb.
  const linesPerPixel = () => {
    const base = term.buffer.active.baseY;
    if (onThumb) return travel > 0 ? base / travel : 0;
    const screen = host.querySelector(".xterm-screen");
    const cell = (screen?.getBoundingClientRect().height ?? host.clientHeight) / (term.rows || 1);
    return cell > 0 ? -1 / cell : 0;
  };

  // Where the finger says to be, measured from where the gesture
  // started -- so rounding cannot accumulate -- but applied as a DELTA
  // against the live buffer position. The terminal moves itself while a
  // finger is down (output arriving follows the bottom; scrollback at
  // capacity trims from the top), and a remembered absolute position
  // would answer that by jumping. Clamping to what the buffer can still
  // do, rather than letting the finger run past the ends, keeps a drag
  // that overshoots responsive the moment it turns back.
  const scrollBy = (dy) => {
    const buf = term.buffer.active;
    if (buf.baseY <= 0) return; // nothing scrolled off the top yet
    const lowest = applied - buf.viewportY;
    const highest = applied + (buf.baseY - buf.viewportY);
    const target = Math.max(lowest, Math.min(highest, Math.round(dy * linesPerPixel())));
    if (target !== applied) {
      term.scrollLines(target - applied);
      applied = target;
    }
  };

  host.addEventListener("pointerdown", (ev) => {
    if (ev.pointerType !== "touch" || held !== null) return; // xterm owns the mouse
    held = ev.pointerId;
    x0 = ev.clientX;
    y0 = ev.clientY;
    scrolling = declined = false;
    applied = 0;
    // The scrollbar only takes the gesture when it is actually there to
    // be grabbed: xterm's CSS gives it pointer-events: none while faded
    // out, so this hit test is the browser's, not a guess at its rect.
    const bar = ev.target.closest?.(".xterm-scrollable-element > .scrollbar");
    onThumb = Boolean(bar);
    if (bar) {
      const thumb = bar.querySelector(".slider");
      travel = bar.getBoundingClientRect().height - (thumb?.getBoundingClientRect().height ?? 0);
    }
  });

  host.addEventListener("pointermove", (ev) => {
    if (ev.pointerId !== held) return;
    const dy = ev.clientY - y0;
    const dx = ev.clientX - x0;
    if (declined) return;
    if (!scrolling) {
      if (Math.hypot(dx, dy) < SCROLL_SLOP) return; // still a tap
      // Only vertical drags are ours. A sideways one is the browser's
      // to keep (touch-action leaves it pan-x), which on iOS is how
      // the back gesture starts -- and it starts at the screen edge,
      // i.e. over the terminal. Decided once per gesture: a drag that
      // has already been let go must not be caught halfway through.
      if (Math.abs(dy) <= Math.abs(dx)) {
        declined = true;
        return;
      }
      scrolling = true;
      // Which sink this gesture has, decided once, at the moment it
      // becomes ours. A thumb drag is always local (see the doc
      // comment); a content drag goes to the app when one is tracking
      // the mouse, or when the alt screen means there is no scrollback
      // for the local path to move.
      emitted = 0;
      cellPx = (screenEl()?.getBoundingClientRect().height ?? 0) / (term.rows || 1);
      forward = !onThumb && cellPx > 0 &&
        (term.modes.mouseTrackingMode !== "none" || term.buffer.active.type === "alternate");
    }
    if (forward) forwardBy(dy, ev.clientX, ev.clientY);
    else scrollBy(dy);
  });

  const end = (ev) => {
    if (ev.pointerId !== held) return;
    held = null;
    scrolling = declined = forward = false;
  };
  host.addEventListener("pointerup", end);
  host.addEventListener("pointercancel", end);

  // A scroll must not also land as a tap: a touch that ends without
  // being cancelled leaves compatibility mouse events behind, and xterm
  // reads those as "focus me" -- so the keyboard would leap up at the
  // end of every drag. Cancelling the touch stream once the gesture is
  // a scroll is what suppresses them, for THIS sequence only: a timer
  // around the tap would eventually eat a real one (asked for by the
  // gate, which taps a fraction of a second after scrolling).
  //
  // It matters a second time now that a claimed drag can be forwarded
  // to a mouse-tracking app: the compat events those reports would come
  // from are exactly what would tack a spurious click report onto the
  // end of every scroll.
  //
  // Guaranteed by the spec only when the FIRST touchmove is cancelled,
  // and the slop phase means ours is not; Chromium honors it mid-stream
  // (the gate holds that), and iOS refuses the synthetic click after
  // ~10px of travel anyway -- but that second half is a spec argument
  // this environment cannot run, so it wants a look on a real phone.
  host.addEventListener("touchmove", (ev) => {
    if (scrolling) ev.preventDefault();
  }, { passive: false });
};

const initKeysBar = (term) => {
  const bar = document.getElementById("keys");
  if (!bar) return;

  // Arrows honor DECCKM (application cursor keys) at press time, like
  // the real keyboard handler would.
  const cursor = (ch) => () => (term.modes.applicationCursorKeysMode ? `\x1bO${ch}` : `\x1b[${ch}`);

  // [label, sequence-or-thunk] — thunks re-read terminal modes per press.
  const KEYS = [
    ["esc", "\x1b"],
    ["tab", "\t"],
    ["ctrl", "ctrl"], // sticky
    ["alt", "alt"], // sticky
    ["←", cursor("D")],
    ["↓", cursor("B")],
    ["↑", cursor("A")],
    ["→", cursor("C")],
    ["~", "~"],
    ["/", "/"],
    ["|", "|"],
    ["-", "-"],
  ];

  // Press = down then up WITHOUT travel. The strip scrolls sideways and
  // sits under the thumb, so fingers land on keys on their way
  // somewhere else; firing on pointerdown turned every such drag into a
  // keystroke (a flick to scroll the strip emitted whatever key it
  // started on). So arm on down, fire on up, and drop the press the
  // moment the finger travels past SLOP or the browser claims the
  // gesture for scrolling (pointercancel).
  //
  // pointerdown is still swallowed: the press must never move focus out
  // of xterm's hidden textarea, since a blur would drop the soft
  // keyboard mid-press. That rules out click, which is unreliable after
  // a prevented pointerdown across mobile browsers — but not pointerup,
  // which fires regardless and, for touch pointers, is the event that
  // actually carries user activation (pointerdown does not — see the ⌨
  // key below, which needs a real gesture to summon the keyboard).
  //
  // Touch pointers are implicitly captured by their pointerdown target,
  // so a wandering finger's move/up/cancel keep arriving here; asking
  // for capture explicitly extends that to the mouse. It is deliberately
  // not load-bearing — the travel check below drops the press either
  // way, and capture does not affect scrolling, which touch-action
  // governs.
  const SLOP = 10; // px of travel that still counts as a press, not a drag

  const key = (label, onPress) => {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = label;

    let held = null; // pointerId of the press in flight
    let x0 = 0, y0 = 0;
    const drop = () => {
      held = null;
      b.classList.remove("pressed");
    };

    b.addEventListener("pointerdown", (ev) => {
      ev.preventDefault();
      held = ev.pointerId;
      x0 = ev.clientX;
      y0 = ev.clientY;
      b.classList.add("pressed"); // the only feedback before the key lands
      try {
        b.setPointerCapture(ev.pointerId);
      } catch { /* optional; the press works without it */ }
    });
    b.addEventListener("pointermove", (ev) => {
      if (ev.pointerId === held && Math.hypot(ev.clientX - x0, ev.clientY - y0) > SLOP) drop();
    });
    b.addEventListener("pointerup", (ev) => {
      if (ev.pointerId !== held) return; // dragged away, or never ours
      drop();
      onPress();
    });
    b.addEventListener("pointercancel", (ev) => {
      if (ev.pointerId === held) drop(); // the browser took the gesture
    });
    return b;
  };

  // The key strip scrolls on narrow screens; ⌨ stays pinned beside it.
  const strip = document.createElement("div");
  strip.id = "keys-strip";
  for (const [label, action] of KEYS) {
    const b = key(label, () => {
      if (action === "ctrl" || action === "alt") {
        armed[action] = !armed[action];
        renderArmed();
        return;
      }
      // Through onData like real typing (transformInput applies armed
      // modifiers there — bar keys and soft-keyboard keys uniformly).
      // input() needs no focus, so pressing keys never summons or
      // dismisses the soft keyboard.
      term.input(typeof action === "function" ? action() : action, true);
    });
    if (action === "ctrl" || action === "alt") armButtons[action] = b;
    strip.appendChild(b);
  }
  bar.appendChild(strip);

  // Explicit keyboard summon/dismiss: blur hides the soft keyboard,
  // focus (inside this pointerup user gesture) brings it back.
  bar.appendChild(
    key("⌨", () => {
      if (document.activeElement === term.textarea) term.blur();
      else term.focus();
    }),
  );
};
