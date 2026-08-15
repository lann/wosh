// Link opening, confirmed: the terminal's web links activate on a
// SINGLE click or tap, and land here instead of opening directly.
//
// Single-tap is a deliberate choice. A modifier-click convention does
// not exist on a phone, and this page treats touch as a first-class
// input (see mobile.mjs) -- so links must work from one tap, which
// means an accidental tap on the wrong cell must be cheap. The
// confirmation is what makes that arithmetic work: a stray tap costs
// one dismissal, never a navigation to whatever a hostile `cat` just
// painted into the scrollback. The dialog therefore shows the URI
// VERBATIM and in full -- the URI is the thing being confirmed --
// before anything leaves the page.
//
// The checkbox turns future confirmations off. Opt-in, persisted in
// this browser only, and honored solely for http(s): the scheme guard
// below runs before the preference is even consulted, so "always
// open" can never be leveraged into opening something that is not a
// web link. Opens are `noopener,noreferrer`: the target page gets no
// handle back into this one (reverse tabnabbing), and no referrer.

/// The stored preference. "open" means: confirmed once with the
/// checkbox, open http(s) links without asking from now on.
const PREF_KEY = "wosh.links.v1";

const prefersDirect = () => {
  try {
    return localStorage.getItem(PREF_KEY) === "open";
  } catch {
    return false; // storage refused: every link asks, which is the safe side
  }
};

const rememberDirect = () => {
  try {
    localStorage.setItem(PREF_KEY, "open");
  } catch {
    /* storage refused: the preference just does not stick */
  }
};

const open = (uri) => {
  window.open(uri, "_blank", "noopener,noreferrer");
};

/**
 * Build the handler `WebLinksAddon` calls on link activation.
 *
 * `dialog` is the page's #linkdialog element (owned and filled here,
 * the same division of labour #panel has with boot.mjs). `refocus` is
 * called when the dialog closes, however it closes, so the terminal
 * gets the keyboard back -- passed in rather than imported because
 * whether focusing is even wanted is the terminal owner's decision
 * (on a phone it is not; see mobile.mjs).
 */
export const linkHandler = (dialog, { refocus = () => {} } = {}) => (event, uri) => {
  void event; // one activation path for mouse and touch alike
  // Only web links, decided before the preference or the dialog: a
  // URI that does not parse, or parses to any other scheme, opens
  // nothing no matter what is stored or clicked.
  let scheme = "";
  try {
    scheme = new URL(uri).protocol;
  } catch {
    return;
  }
  if (scheme !== "http:" && scheme !== "https:") {
    return;
  }

  if (prefersDirect()) {
    open(uri);
    return;
  }

  dialog.replaceChildren();
  const title = document.createElement("div");
  title.textContent = "open this link?";
  const shown = document.createElement("code");
  shown.textContent = uri;

  const remember = document.createElement("input");
  remember.type = "checkbox";
  remember.id = "link-remember";
  const rememberLabel = document.createElement("label");
  rememberLabel.htmlFor = "link-remember";
  rememberLabel.append(remember, " always open links without asking");

  const openBtn = document.createElement("button");
  openBtn.textContent = "open";
  const cancelBtn = document.createElement("button");
  cancelBtn.textContent = "cancel";

  const row = document.createElement("div");
  row.className = "row";
  const spacer = document.createElement("div");
  spacer.className = "spacer";
  row.append(rememberLabel, spacer, openBtn, cancelBtn);

  dialog.append(title, shown, row);

  openBtn.addEventListener("click", () => {
    // The preference is recorded only on a CONFIRMED open: checking
    // the box and then cancelling stores nothing.
    if (remember.checked) {
      rememberDirect();
    }
    dialog.close();
    open(uri);
  });
  cancelBtn.addEventListener("click", () => dialog.close());
  // Esc arrives as the dialog's native cancel -> close; both buttons
  // funnel through close too, so this is the one exit point.
  dialog.addEventListener("close", refocus, { once: true });

  dialog.showModal();
  // A modal steals focus to its first control -- that is the remember
  // checkbox, and a stray Enter must not toggle-and-open. Cancel is
  // the safe default owner of the keyboard.
  cancelBtn.focus();
};
