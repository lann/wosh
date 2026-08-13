// Camera QR scanning for the connect panel.
//
// The listener prints a QR of its connect LINK, and the fragment of
// that link is the connection string -- so on a phone that already has
// the page open (the installed PWA, or a second session), pointing the
// camera at the operator's screen beats retyping forty base64 chars.
// Nothing here interprets the payload: it hands back whatever text the
// code carried, and boot.mjs decides what a connection string is.
//
// Two decoders, in preference order:
//
//   1. BarcodeDetector -- the platform's own, no bytes to download and
//      markedly better on the hard cases (angled or glare-y screens).
//      Present on Chrome/Edge for Android, ChromeOS and macOS; absent
//      on iOS Safari, Firefox, and desktop Linux Chrome, and present-
//      but-useless where the platform lists no formats, hence the
//      getSupportedFormats() check rather than a bare `in` test.
//   2. jsQR -- pure JS, fetched only when the native path is missing,
//      so the platforms that have a detector never pay for it.
//
// The camera is a resource with a light on it: every exit path
// (decode, cancel button, abort signal, failure to start) stops the
// tracks and removes the preview.

/** Where scripts/site-deploy-tree.sh puts the jsQR UMD bundle. */
const JSQR_SRC = "./vendor/jsqr.js";

/** How often a frame is examined. Fast enough to feel instant, slow
 *  enough that the jsQR path does not pin a phone's CPU. */
const INTERVAL_MS = 120;

/** Longest edge jsQR is given. A QR filling a fraction of a 1080p
 *  frame still decodes at this size, and the scan stays interactive on
 *  a mid-range phone; the native detector gets the full frame. */
const MAX_EDGE = 720;

/**
 * Why scanning cannot work here, or null when it can -- and the answer
 * is deliberately NOT used to hide the button. A missing camera API
 * almost always means the page is on plain http (the LAN address of a
 * dev server is the usual way to land here, and it is exactly how
 * someone tries to scan from a phone), and a button that silently
 * vanishes teaches nobody that. Permission is NOT probed: asking for
 * the camera before the user has expressed any interest in it is the
 * prompt everyone hates.
 */
export function scanUnavailable() {
  if (typeof navigator !== "undefined" && navigator.mediaDevices?.getUserMedia) return null;
  if (typeof window !== "undefined" && window.isSecureContext === false) {
    return "the camera needs a secure page: open this site over https " +
      "(plain http only counts as secure on localhost)";
  }
  return "this browser exposes no camera to the page";
}

/** The platform detector, or null if it cannot decode QR here. */
async function nativeDetector() {
  if (!("BarcodeDetector" in globalThis)) return null;
  try {
    const formats = await globalThis.BarcodeDetector.getSupportedFormats();
    if (!formats.includes("qr_code")) return null;
    const detector = new globalThis.BarcodeDetector({ formats: ["qr_code"] });
    return async (video) => {
      const found = await detector.detect(video);
      return found[0]?.rawValue || null;
    };
  } catch {
    return null; // constructor rejects the format set: treat as absent
  }
}

/** The jsQR fallback, loaded on first use. */
async function jsqrDetector() {
  if (!globalThis.jsQR) {
    await new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = JSQR_SRC;
      script.addEventListener("load", resolve);
      script.addEventListener("error", () => reject(new Error(`could not load ${JSQR_SRC}`)));
      document.head.append(script);
    });
  }
  const jsQR = globalThis.jsQR;
  if (!jsQR) throw new Error(`${JSQR_SRC} loaded but defined no decoder`);

  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  return (video) => {
    const vw = video.videoWidth;
    const vh = video.videoHeight;
    if (!vw || !vh) return null; // no frame yet
    const scale = Math.min(1, MAX_EDGE / Math.max(vw, vh));
    const w = Math.max(1, Math.round(vw * scale));
    const h = Math.max(1, Math.round(vh * scale));
    if (canvas.width !== w || canvas.height !== h) {
      canvas.width = w;
      canvas.height = h;
    }
    ctx.drawImage(video, 0, 0, w, h);
    // dontInvert: a QR on a screen or on paper is dark-on-light, and
    // trying the inverse doubles the per-frame cost for nothing.
    return jsQR(ctx.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: "dontInvert" })
      ?.data || null;
  };
}

/** getUserMedia's DOMExceptions, in words a user can act on. */
function cameraError(e) {
  const name = e?.name ?? "";
  if (name === "NotAllowedError" || name === "SecurityError") {
    return new Error("camera permission was denied; allow it in the browser's site settings");
  }
  if (name === "NotFoundError" || name === "OverconstrainedError") {
    return new Error("no camera available on this device");
  }
  if (name === "NotReadableError") {
    return new Error("the camera is already in use by another app");
  }
  return new Error(`could not open the camera: ${e?.message ?? e}`);
}

/**
 * Scan until a QR code is read. Renders a preview and a cancel button
 * into `container`, and resolves with the code's text -- or null if the
 * user cancelled or `signal` aborted. Rejects only when scanning could
 * not start at all (camera refused, no decoder); the caller shows that
 * message. The camera is released before this settles, every time.
 */
export async function scanQr(container, { signal } = {}) {
  // No camera API at all: say so before anything is rendered, so the
  // caller's error path explains the http-vs-https case instead of the
  // button appearing to do nothing.
  const unavailable = scanUnavailable();
  if (unavailable) throw new Error(unavailable);

  // One controller for every way out, armed BEFORE anything is awaited:
  // the cancel button is on screen while the permission prompt is up
  // and while jsQR is still downloading, and a button that does nothing
  // when pressed is worse than no button. Each await below rechecks it,
  // so a cancel that lands mid-flight still ends with the camera off.
  const stop = new AbortController();
  const abort = () => stop.abort();
  const cancelled = () => stop.signal.aborted;
  signal?.addEventListener("abort", abort, { once: true });

  const view = document.createElement("div");
  view.className = "scan-view";
  const video = document.createElement("video");
  video.playsInline = true; // iOS: otherwise the preview goes fullscreen
  video.muted = true;
  video.autoplay = true;
  const hint = document.createElement("div");
  hint.className = "hint";
  hint.textContent = "point the camera at the listener's QR code";
  const cancelBtn = document.createElement("button");
  cancelBtn.textContent = "cancel";
  cancelBtn.addEventListener("click", abort);
  view.append(video, hint, cancelBtn);
  container.append(view);

  const teardown = () => {
    signal?.removeEventListener("abort", abort);
    view.remove();
  };

  if (cancelled()) {
    teardown();
    return null;
  }

  let stream;
  try {
    // ideal, not exact: a laptop with only a front camera still scans.
    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: "environment" } },
    });
  } catch (e) {
    teardown();
    if (cancelled()) return null; // gave up while the prompt was up
    throw cameraError(e);
  }

  const release = () => {
    for (const track of stream.getTracks()) track.stop();
    video.srcObject = null;
    teardown();
  };

  // Cancelled while the permission prompt was up: the stream arrives
  // anyway, and has to be put straight back down.
  if (cancelled()) {
    release();
    return null;
  }

  let detect;
  try {
    detect = (await nativeDetector()) ?? (await jsqrDetector());
    video.srcObject = stream;
    await video.play().catch(() => {}); // autoplay policy: muted+inline is allowed
  } catch (e) {
    release();
    if (cancelled()) return null;
    throw e;
  }

  return new Promise((resolve) => {
    let timer = null;
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      if (timer !== null) clearTimeout(timer);
      timer = null;
      stop.signal.removeEventListener("abort", onStop);
      release();
      resolve(value);
    };
    const onStop = () => finish(null);
    stop.signal.addEventListener("abort", onStop, { once: true });
    if (cancelled()) return void finish(null);

    const tick = async () => {
      timer = null;
      let found = null;
      try {
        found = await detect(video);
      } catch {
        // A single bad frame (or a detector that dislikes one) is not
        // a reason to end the scan: keep looking.
      }
      // The await above yields: a cancel may have landed meanwhile,
      // and the camera is already released.
      if (done) return;
      if (found) return void finish(found);
      timer = setTimeout(tick, INTERVAL_MS);
    };
    tick();
  });
}
