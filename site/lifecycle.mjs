// Page lifecycle -> session, in one place.
//
// A phone takes the network away when the page goes to the background
// and hands it back on return, and there is no way to hold a socket
// through that: iOS suspends the process, Android throttles the page's
// timers and then freezes it. The session survives anyway, by design --
// the listener parks it, holding the sshd leg open (`--resume-grace`,
// 600s by default) -- but only if the client spends its resume budget
// where it can be spent well:
//
//   - away: stop redialing. A suspended device cannot complete a dial,
//     and every attempt is a radio wake-up whose only result is to burn
//     the budget before the page comes back to see it.
//   - back: redial NOW, rather than sitting out a backoff that was
//     sized for a page that could watch it. Coming back to a terminal
//     that reconnects in a moment is the whole point.
//
// "Away" arrives under three different names and they overlap: a tab
// going hidden, `pagehide` (bfcache, navigation), and `freeze` (the
// Page Lifecycle API). Which of them a platform sends, and in what
// order, varies -- iOS often skips `freeze` entirely -- so all three
// say the same thing, and the client's suspend/wake are idempotent so
// that saying it twice is free.
//
// Deliberately not mobile-gated: a desktop tab left in the background
// for ten minutes has exactly the same problem, and the same fix.

/**
 * Wire the page's lifecycle to whatever session is current.
 *
 * `session()` is called at event time rather than captured, because
 * the current session changes underneath this (connect, detach,
 * reconnect) and a stale handle would suspend a session nobody has.
 *
 * `onPaint` is the pre-existing "flush the screen before the page
 * stops painting" hook; it stays attached to the same moment.
 */
export const initLifecycle = (session, onPaint = () => {}) => {
  // Never let a lifecycle handler throw: it runs on the browser's path
  // out of the page, there is nobody to report to, and a rejected
  // promise here would surface as an unhandled rejection in a page
  // that is on its way to being frozen.
  const away = () => {
    try {
      session()?.suspend()?.catch?.(() => {});
    } catch { /* no session, or a session already torn down */ }
  };
  const back = () => {
    try {
      session()?.wake()?.catch?.(() => {});
    } catch { /* ditto */ }
  };

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      // Paint what is queued while there is still a frame to do it in
      // -- inside the guard, because a throwing painter must not also
      // cost the session its suspend.
      try {
        onPaint();
      } catch { /* the screen is the least of it on the way out */ }
      away();
    } else {
      back();
    }
  });
  addEventListener("pagehide", away);
  // Also fires once on an ordinary load, which is a wake at a moment
  // when there is no session to wake. Harmless by construction, and
  // cheaper than trusting `event.persisted` to tell a restored page
  // from a fresh one on every platform.
  addEventListener("pageshow", back);
  document.addEventListener("freeze", away);
  document.addEventListener("resume", back);
};
