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
//   - no Tab keydown in the last 300ms -- rules out Tab-away, which
//     also precedes a blur. Only Tab: ordinary typing must not mask
//     the blur an eaten Esc inflicts mid-flow.
//   - document.hasFocus() === true -- rules out alt-tab / window
//     switch, where the blur is real and the window itself lost focus.
//   - matchMedia("(pointer: coarse)") gates the whole detector off --
//     on phones, the system "hide keyboard" button produces the exact
//     same uncaused, relatedTarget-null blur, legitimately. Fine
//     pointer only.
//
// But that shape alone is not enough: a real false positive was
// reported against a single-shot version of this detector. Dismissing
// 1Password's native "save this password?" popup -- browser-level UI,
// no page events at all -- returns focus to the page (hasFocus() is
// true) and then the extension's content script does a cleanup
// blur()/refocus() dance. Identical shape, zero eaten keystrokes.
// Other extensions plausibly do similar one-off fixups. So one
// unattributed blur is never evidence by itself; it takes a PATTERN,
// told apart from a one-off fixup by two things a fixup lacks:
//   - it interrupts typing -- the eaten key (Esc) arrives seconds
//     after real input was flowing through onData, whereas a fixup
//     blur follows a popup interaction the user's hands were on, not
//     the terminal, so nothing reached onData beforehand.
//   - it repeats -- a user whose Esc did nothing tries again shortly,
//     so a second unattributed blur follows within seconds, whether
//     or not more typing happened in between.
// So the trigger is two-stage: the first typing-correlated
// unattributed blur only ARMS (no banner -- it alone still looks like
// a fixup); a second one that is either typing-correlated itself or
// within RETRY_WINDOW_MS of the armed one FIRES. A lone blur, or a
// string of blurs none of which ever followed typing, never arms and
// so never fires -- exactly the 1Password shape.
//
// Accepted misses, in trade for that false-positive immunity: the
// very first eaten Esc never banners (it only arms), and an Esc
// pressed as the first key after a long idle doesn't correlate with
// typing either -- but the next attempt (typing-correlated, or within
// the retry window of the first) catches both. The hint may land one
// attempt late; it should never land wrong.
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
const INPUT_WINDOW_MS = 5000; // an unattributed blur this soon after typing is "interrupted", not a fixup
const RETRY_WINDOW_MS = 30000; // a second unattributed blur this soon after the first is a retried Esc, not a coincidence

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
  // Only Tab explains a blur by keyboard: it is the one key that
  // legitimately moves focus off the textarea (and even then the blur
  // carries relatedTarget, so this is a backstop). Ordinary typing must
  // NOT count -- the eaten Esc lands mid-flow, and a keystroke 200ms
  // earlier would otherwise mask the very blur it inflicts.
  addEventListener(
    "keydown",
    (e) => {
      if (e.key === "Tab") explain();
    },
    { capture: true },
  );

  let lastInputAt = -Infinity;
  term.onData(() => {
    lastInputAt = performance.now();
  });

  let detecting = true; // disarmed for the rest of the page load once we've fired
  let armed = false; // stage one done: a typing-correlated unattributed blur has been seen
  let lastShapeBlurAt = -Infinity;
  addEventListener(
    "blur",
    (e) => {
      if (!detecting || e.target !== term.textarea) return;
      if (e.relatedTarget !== null) return; // click-away or a dialog took focus: not our shape
      if (!document.hasFocus()) return; // the whole window lost focus (alt-tab): not our shape
      if (performance.now() - lastExplainedAt < EXPLAIN_WINDOW_MS) return; // click or Tab explained it: not our shape
      const t = performance.now();
      const typingCorrelated = t - lastInputAt < INPUT_WINDOW_MS;
      if (armed && (typingCorrelated || t - lastShapeBlurAt < RETRY_WINDOW_MS)) {
        // Stage two: this is either itself typing-correlated, or it
        // followed the arming blur within the retry window -- a
        // pattern, not a one-off fixup. Detected: disarm for the rest
        // of the page load. The trigger is every Esc press in vim,
        // and nagging once per keystroke would be worse than the bug
        // itself -- one hint per load is enough.
        detecting = false;
        banner.hidden = false;
      } else if (typingCorrelated) {
        // Stage one: interrupted real typing, but alone this still
        // looks like a fixup (1Password et al.) -- arm, don't fire.
        armed = true;
      }
      lastShapeBlurAt = t;
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
