// Transient centered status overlay for the terminal — flashes
// "80×24" on resize, connection-state changes, and similar one-shot
// facts that don't merit a persistent status line (which ellipsizes on
// phones anyway). Ported from ttyd's OverlayAddon
// (https://github.com/tsl0922/ttyd, html/src/components/terminal/xterm/
// addons/overlay.ts, MIT), itself ported from hterm's showOverlay
// (Chromium OS libapps, BSD-3-Clause). Deviations from ttyd: plain ESM
// with no decorator/framework deps, and `pointer-events: none` instead
// of a mousedown-suppression listener — the overlay must never steal a
// tap from the terminal (on mobile that would drop the soft keyboard).
//
// Duck-types xterm's ITerminalAddon: load with term.loadAddon(...);
// showOverlay(msg, ms) flashes for ms milliseconds, or sticks until
// hide()/the next show when ms is omitted.

export class OverlayAddon {
  constructor() {
    this.terminal = null;
    this.timer = null;
    this.node = document.createElement("div");
    this.node.style.cssText = [
      "border-radius: 15px",
      "font: bold 22px system-ui, sans-serif",
      "color: #101010",
      "background: #f0f0f0",
      "opacity: 0.75",
      "padding: 0.2em 0.5em",
      "position: absolute",
      "user-select: none",
      "-webkit-user-select: none",
      "transition: opacity 180ms ease-in",
      "pointer-events: none",
      "z-index: 10",
      "white-space: nowrap",
    ].join(";");
  }

  activate(terminal) {
    this.terminal = terminal;
  }

  dispose() {
    this.hide();
    this.terminal = null;
  }

  /** Show msg centered over the terminal; fade after `timeout` ms, or
   *  stick (until hide()/next show) when `timeout` is omitted. */
  showOverlay(msg, timeout) {
    const el = this.terminal?.element; // .xterm is position:relative
    if (!el) return;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.node.textContent = msg;
    this.node.style.opacity = "0.75";
    if (!this.node.parentNode) el.appendChild(this.node);
    const host = el.getBoundingClientRect();
    const box = this.node.getBoundingClientRect();
    this.node.style.top = `${(host.height - box.height) / 2}px`;
    this.node.style.left = `${(host.width - box.width) / 2}px`;
    if (!timeout) return;
    this.timer = setTimeout(() => {
      this.node.style.opacity = "0";
      this.timer = setTimeout(() => this.hide(), 200);
    }, timeout);
  }

  hide() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.node.remove();
    this.node.style.opacity = "0.75";
  }
}
