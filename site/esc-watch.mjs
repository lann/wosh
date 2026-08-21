// Detects a vim-keys browser extension (Vimium and its kin) eating
// Esc, and says so -- because this page cannot get the keystroke back.
//
// What those extensions do, measured against real Vimium in headed
// Chromium: when focus is in a text field, they intercept Esc at
// window CAPTURE, before any listener this page could register --
// keydown, keypress AND keyup are all suppressed, and the extension
// then calls blur() on the focused element itself. So the page never
// sees the key at all; the only thing that reaches it is the blur.
// In a terminal, Esc is not a nicety (vim lives on it), so silence is
// the wrong failure mode -- the least this page can do is explain
// what happened and point at the fix (excluding the site in the
// extension's settings).
//
// The blur's shape is the only signal, and it has to be told apart
// from every other reason a text field loses focus. Each predicate
// clause below excludes one alternative, all measured against real
// Vimium and plain browser behavior:
//   - e.relatedTarget === null   -- a click on another element, or a
//     dialog stealing focus, sets relatedTarget to what took it; only
//     an extension's synthetic blur() leaves it null.
//   - no pointerdown/mousedown in the last 300ms -- rules out "the
//     user clicked something else", which also blurs with
//     relatedTarget null in some browsers on some targets.
//   - no keydown in the last 300ms -- rules out Tab-away, which also
//     precedes a blur.
//   - document.hasFocus() === true -- rules out alt-tab / window
//     switch, where the blur is real and the window itself lost focus.
//   - matchMedia("(pointer: coarse)") gates the whole detector off --
//     on phones, the system "hide keyboard" button produces the exact
//     same uncaused, relatedTarget-null blur, legitimately. Fine
//     pointer only.
//
// Deliberately NOT checking event.isTrusted: the gates that pin this
// drive the predicate with a real, programmatic `term.textarea.blur()`
// call, which is exactly the shape an intercepted Esc produces and the
// only source of synthetic blurs this page ever dispatches itself --
// so isTrusted would only ever exclude our own test harness, never a
// real extension: content scripts call the DOM's own blur(), and the
// browser generates the resulting blur event itself, trusted, no
// matter which world asked for it.
//
// Non-modal by design: showing a banner, not a dialog, and no focus
// grabbing. The user may have Vimium on for a reason -- this is
// information, not an error to be dismissed as unwelcome.

const KEY = "wosh.eschint.v1";
const EXPLAIN_WINDOW_MS = 300;

export function initEscWatch(term, { banner, refocus }) {
  if (matchMedia("(pointer: coarse)").matches) return; // soft-keyboard blurs look identical
  let off;
  try {
    off = localStorage.getItem(KEY) === "off";
  } catch {
    off = false; // storage refused: default to showing the hint
  }
  if (off) return;

  let lastExplainedAt = -Infinity;
  const explain = () => {
    lastExplainedAt = performance.now();
  };
  addEventListener("pointerdown", explain, { capture: true });
  addEventListener("mousedown", explain, { capture: true });
  addEventListener("keydown", explain, { capture: true });

  let armed = true;
  addEventListener(
    "blur",
    (e) => {
      if (!armed || e.target !== term.textarea) return;
      if (e.relatedTarget !== null) return; // click-away or a dialog took focus: not a detection, stays armed
      if (!document.hasFocus()) return; // the whole window lost focus (alt-tab): stays armed
      if (performance.now() - lastExplainedAt < EXPLAIN_WINDOW_MS) return; // click or Tab explained it: stays armed
      // Detected: disarm for the rest of the page load. The trigger is
      // every Esc press in vim, and nagging once per keystroke would
      // be worse than the bug itself -- one hint per load is enough.
      armed = false;
      banner.hidden = false;
    },
    { capture: true },
  );

  const dismiss = () => {
    banner.hidden = true;
    refocus();
  };
  banner.querySelector(".dismiss").addEventListener("click", dismiss);
  banner.querySelector(".never").addEventListener("click", () => {
    try {
      localStorage.setItem(KEY, "off");
    } catch {
      /* storage refused: the preference just does not stick */
    }
    dismiss();
  });
}
