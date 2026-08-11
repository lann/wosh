// Mobile UX for the wosh page. Three pieces, all inert on desktop:
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
//    blurs/refocuses explicitly.
//
// No framework, no dependencies; loaded by app.mjs next to the
// terminal it drives.

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

/**
 * Apply armed one-shot modifiers to one onData chunk. Identity when
 * nothing is armed (the desktop / gate path). Called by app.mjs on
 * every chunk BEFORE it reaches the session, so the transform covers
 * soft-keyboard input and bar-injected keys alike.
 */
export const transformInput = (s) => {
  if (!armed.ctrl && !armed.alt) return s;
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
 * Wire the mobile layer to the live terminal. Idempotent-enough for the
 * page's single call; safe when visualViewport or #keys are absent.
 */
export const initMobile = (term) => {
  initViewportFit();
  initKeysBar(term);
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
    ["~", "~"],
    ["/", "/"],
    ["|", "|"],
    ["-", "-"],
    ["←", cursor("D")],
    ["↓", cursor("B")],
    ["↑", cursor("A")],
    ["→", cursor("C")],
  ];

  // Act on pointerdown and swallow it: the tap must never move focus
  // out of xterm's hidden textarea (a blur would drop the soft
  // keyboard mid-press). click after a prevented pointerdown is not
  // reliable across mobile browsers, so pointerdown IS the action.
  const key = (label, onDown) => {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    b.addEventListener("pointerdown", (ev) => {
      ev.preventDefault();
      onDown();
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
  // focus (inside this pointerdown user gesture) brings it back.
  bar.appendChild(
    key("⌨", () => {
      if (document.activeElement === term.textarea) term.blur();
      else term.focus();
    }),
  );
};
