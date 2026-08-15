// What this page knows about session managers, as pure data and pure
// functions: no DOM, no imports, nothing that touches a connection.
//
// Two consumers, deliberately: the panel (site/boot.mjs) builds its
// preset select, its templated command lines and its session picker out
// of this module, and a plain-node gate (host-test/sessions-parse.mjs)
// feeds the parsers golden samples of what the four tools actually
// print. Keeping the knowledge here is what makes the second one
// possible at all -- the parsing rules are the part most likely to be
// subtly wrong, and they are the part a browser gate can least easily
// reach.
//
// The whole surface is best-effort by construction. These strings come
// from four different tools' HUMAN-facing output, across versions and
// distributions that have never agreed on a column layout; the honest
// contract is "a list when it parses, no list otherwise", never an
// exception and never an invented row.

/** Names allowed inside a templated command line. */
//
// The name lands verbatim in a shell command the TARGET's shell parses,
// so this is the whole defence: a whitelist of characters that cannot
// mean anything to a shell (no quotes, no $, no spaces, no slashes)
// beats quoting theatre, which only has to be wrong once. 32 characters
// is well past any real session name and short of any path limit.
export function validName(s) {
  return /^[A-Za-z0-9_-]{1,32}$/.test(s ?? "");
}

// The DEFAULT detach keybinding of each tool -- and only the default.
// Every one of these is remappable (dtach -e, abduco -e, tmux's
// prefix, screen's escape), and a remapped target simply receives the
// sequence as ordinary input: inert junk typed into whatever is running
// inside. There is no way to ask the target which binding is in force,
// which is why every use of these falls back to a hard detach when the
// session does not actually close (see app.sendDetachKeys).
//
//   dtach   ^\      (the literal detach character, not a prefix)
//   abduco  ^\      (same)
//   tmux    ^B d    (prefix, then d)
//   screen  ^A d    (escape, then d)

/**
 * The session managers this page knows how to drive, in the order the
 * select offers them. Each entry owns everything that differs between
 * the tools: the create-or-attach command line, the default detach
 * keys, the command that lists sessions, and the parser for whatever
 * that command prints.
 *
 * `command(name)` assumes a name that already passed `validName`.
 */
export const PRESETS = [
  {
    id: "dtach",
    label: "dtach",
    // mkdir first: dtach will not create the socket's directory, and a
    // missing ~/.wosh is otherwise a confusing "no such file" on the
    // very first connect. -r winch makes dtach redraw by asking the
    // program to redraw (a SIGWINCH), which is the closest thing it has
    // to screen state.
    command: (name) =>
      `mkdir -p "$HOME/.wosh" && exec dtach -A "$HOME/.wosh/${name}.dtach" -r winch "$SHELL"`,
    detachKeys: "\x1c",
    // A socket per session, in one directory we own. `|| true` so a
    // host that has never run this reads as zero sessions instead of an
    // error the picker would have to explain.
    listCommand: 'ls -1 "$HOME/.wosh" 2>/dev/null || true',
    parseList: (text) => parseDtachList(text),
  },
  {
    id: "abduco",
    label: "abduco",
    command: (name) => `exec abduco -A ${name} "$SHELL"`,
    detachKeys: "\x1c",
    listCommand: "abduco 2>/dev/null || true",
    parseList: (text) => parseAbducoList(text),
  },
  {
    id: "tmux",
    label: "tmux",
    command: (name) => `exec tmux new-session -A -D -s ${name}`,
    detachKeys: "\x02d",
    // The one tool with a machine-readable format; use it. \t is a
    // separator no session name can contain.
    listCommand:
      "tmux ls -F '#{session_name}\\t#{session_attached}\\t#{session_created}' 2>/dev/null || true",
    parseList: (text) => parseTmuxList(text),
  },
  {
    id: "screen",
    label: "screen",
    command: (name) => `exec screen -D -R -S ${name}`,
    detachKeys: "\x01d",
    listCommand: "screen -ls 2>/dev/null || true",
    parseList: (text) => parseScreenList(text),
  },
];

/** The preset with this id, or undefined. */
export function presetById(id) {
  return PRESETS.find((p) => p.id === id);
}

/** Every tool `detectCommand` reports on, in the presets' order. */
export const TOOLS = PRESETS.map((p) => p.id);

// One POSIX line, no bashisms: `command -v` is the only portable
// "is this installed" (which/type are neither reliable nor uniform),
// and the redirects keep its own output off the wire -- the echo is the
// answer. The trailing `true` is load-bearing: the loop exits with the
// status of its LAST `command -v`, so a host missing only `screen`
// would otherwise make the whole probe look like a failure.
export const detectCommand =
  'for t in dtach abduco tmux screen; do command -v "$t" >/dev/null 2>&1 && echo "$t"; done; true';

/**
 * `detectCommand`'s output as `{ dtach: bool, abduco: bool, tmux:
 * bool, screen: bool }`. Anything unrecognized on a line is ignored --
 * a shell that printed a warning first must not turn into a missing
 * tool.
 */
export function parseDetect(text) {
  const found = new Set(String(text ?? "").split("\n").map((l) => l.trim()));
  const out = {};
  for (const t of TOOLS) out[t] = found.has(t);
  return out;
}

// The reverse direction: a command line back to the preset and name
// that would have produced it. Loose on purpose -- these have to keep
// recognizing the lines phase 1 wrote (dtach's fixed `main.dtach`
// socket, tmux's fixed `-s wosh`), and a line a user hand-edited in
// ways that do not change what it runs. Anything not recognized is
// simply `null`: a plain shell and an unrecognizable custom command
// are the same thing to the picker, which is "nothing to list".
const MATCHERS = [
  ["dtach", /dtach\s+-A\s+"?\$HOME\/\.wosh\/([A-Za-z0-9_-]+)\.dtach/],
  ["abduco", /abduco\s+(?:-\S+\s+)*-A\s+([A-Za-z0-9_-]+)/],
  ["tmux", /tmux\s+new(?:-session)?\s+(?:-\S+\s+)*-s\s+([A-Za-z0-9_-]+)/],
  ["screen", /screen\s+(?:-\S+\s+)*-S\s+([A-Za-z0-9_-]+)/],
];

/**
 * `{ preset, name }` for a command line this page understands, else
 * null.
 */
export function matchCommand(command) {
  const s = String(command ?? "");
  if (!s.trim()) return null;
  for (const [id, re] of MATCHERS) {
    const m = re.exec(s);
    if (m && validName(m[1])) return { preset: presetById(id), name: m[1] };
  }
  return null;
}

// --- the list parsers -------------------------------------------------
//
// Shared contract, and the reason each of these is written defensively
// rather than strictly: return an array of `{ name, attached, at }`,
// `[]` for empty or unparseable input, and NEVER throw. `attached` is
// `null` where the tool does not say (a dtach socket file says nothing
// about whether anyone is attached to it), and `at` is epoch
// milliseconds or `null`. The picker degrades to "no list" rather than
// to a broken panel, so a version of one of these tools that prints
// something unexpected costs a feature, not the page.

const lines = (text) =>
  String(text ?? "").split("\n").map((l) => l.replace(/\r$/, "")).filter((l) => l.trim());

/**
 * tmux with our own -F format: name \t attached-count \t created.
 * `session_attached` is a COUNT of attached clients, so anything but
 * "0" means someone is looking at it.
 */
function parseTmuxList(text) {
  const out = [];
  for (const line of lines(text)) {
    const f = line.split("\t");
    const name = (f[0] ?? "").trim();
    if (!name || f.length < 2) continue; // not our format: a warning, an error
    // The same whitelist every other parser applies: a listed name
    // flows back into a command line when the user taps [attach], and
    // validName is the whole defence there. A session named out of
    // band with shell metacharacters is simply not offered.
    if (!validName(name)) continue;
    const created = Number(f[2]);
    out.push({
      name,
      attached: f[1].trim() !== "0",
      at: Number.isFinite(created) && created > 0 ? created * 1000 : null,
    });
  }
  return out;
}

/**
 * abduco's bare listing: a header line, then one row per session,
 * roughly `* Fri 2026-08-15 12:01:02 12345 name` -- the leading `*`
 * marks an attached session, and the column layout varies enough
 * between versions that only two things are safe to read: that marker,
 * and the LAST whitespace-separated token as the name. The timestamp
 * is deliberately left as null rather than parsed out of a format that
 * is not stable and carries no timezone.
 */
function parseAbducoList(text) {
  const rows = lines(text);
  const out = [];
  for (const line of rows.slice(1)) { // [0] is the header ("Active sessions")
    const tokens = line.trim().split(/\s+/);
    const name = tokens[tokens.length - 1];
    if (!name || !validName(name)) continue;
    out.push({ name, attached: line.trimStart().startsWith("*"), at: null });
  }
  return out;
}

/**
 * dtach has no listing at all: what we have is our own socket
 * directory. A socket file is evidence a session was created, and
 * NOTHING about whether it is attached or even still alive (dtach
 * leaves the socket behind if it dies badly) -- hence `attached: null`,
 * and hence the picker's copy hedging for this tool.
 */
function parseDtachList(text) {
  const out = [];
  for (const line of lines(text)) {
    const m = /^(.*)\.dtach$/.exec(line.trim());
    if (!m || !validName(m[1])) continue; // other files in the directory
    out.push({ name: m[1], attached: null, at: null });
  }
  return out;
}

/**
 * `screen -ls`: a header, rows like `\t12345.name\t(Detached)` (some
 * versions insert a creation date in its own parentheses first), then
 * a summary line. Read the pid.name token and the LAST
 * Attached/Detached parenthetical; skip anything without both, which
 * is exactly the header and the summary.
 */
function parseScreenList(text) {
  const out = [];
  for (const line of lines(text)) {
    const m = /(?:^|\s)\d+\.(\S+)/.exec(line);
    if (!m) continue;
    const states = [...line.matchAll(/\((Attached|Detached|Multi,\s*attached|Multi,\s*detached)\)/gi)];
    if (states.length === 0) continue;
    const state = states[states.length - 1][1].toLowerCase();
    const name = m[1];
    if (!validName(name)) continue;
    out.push({ name, attached: state.includes("attached"), at: null });
  }
  return out;
}
