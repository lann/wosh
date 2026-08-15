// The session-manager knowledge module, against golden inputs.
//
// A plain node gate: site/sessions.mjs is pure (no DOM, no imports),
// precisely so the part most likely to be subtly wrong -- parsing four
// different tools' human-facing output -- can be tested without a
// browser, a listener, or an SSH server. What a browser gate cannot
// reach at all is the shape of `screen -ls` on a machine that has three
// sessions in three different states; these samples are that machine.
//
//   node host-test/sessions-parse.mjs
//
// Prints one PASS line, or exits nonzero naming the failure.

import {
  PRESETS,
  TOOLS,
  detectCommand,
  matchCommand,
  parseDetect,
  presetById,
  validName,
} from "../site/sessions.mjs";

let failures = 0;
const fail = (name, detail) => {
  failures++;
  console.error(`FAIL ${name}: ${detail}`);
};
const eq = (name, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g !== w) fail(name, `\n  got  ${g}\n  want ${w}`);
};

const list = (id, text) => presetById(id).parseList(text);

// --- tmux -------------------------------------------------------------
// Our own -F format, so the only variability is what tmux itself puts
// in the fields: an attached count (not a boolean) and a unix second.
eq("tmux: two sessions, one attached",
  list("tmux", "main\t1\t1755259262\nbuild\t0\t1755255000\n"),
  [
    { name: "main", attached: true, at: 1755259262000 },
    { name: "build", attached: false, at: 1755255000000 },
  ]);
eq("tmux: two clients attached is still attached",
  list("tmux", "main\t2\t1755259262"),
  [{ name: "main", attached: true, at: 1755259262000 }]);
eq("tmux: no server running prints nothing", list("tmux", ""), []);
// `tmux ls` on a host with no server writes to stderr, which the list
// command drops -- but a shell profile that prints a banner does not.
eq("tmux: a stray banner line is not a session",
  list("tmux", "Welcome to example.net\nmain\t0\t1755259262"),
  [{ name: "main", attached: false, at: 1755259262000 }]);
eq("tmux: a garbage created field leaves the time unknown",
  list("tmux", "main\t0\tnot-a-number"),
  [{ name: "main", attached: false, at: null }]);

// --- abduco -----------------------------------------------------------
// A header line, then rows whose columns move between versions. Only
// the leading marker and the last token are load-bearing.
const ABDUCO = [
  "Active sessions:",
  "* Fri 2026-08-15 12:01:02   12345  main",
  "  Fri 2026-08-15 09:14:55   12002  build",
  "",
].join("\n");
eq("abduco: header skipped, marker read, last token is the name",
  list("abduco", ABDUCO),
  [
    { name: "main", attached: true, at: null },
    { name: "build", attached: false, at: null },
  ]);
eq("abduco: no sessions at all", list("abduco", "Active sessions:\n"), []);
eq("abduco: nothing printed", list("abduco", ""), []);

// --- dtach ------------------------------------------------------------
// Not a listing: our own socket directory, so anything else in it is
// somebody else's file and not a session.
eq("dtach: sockets become names, other files are ignored",
  list("dtach", "main.dtach\nbuild.dtach\nREADME\nnotes.txt\n"),
  [
    { name: "main", attached: null, at: null },
    { name: "build", attached: null, at: null },
  ]);
eq("dtach: no ~/.wosh at all (ls failed, || true)", list("dtach", ""), []);
eq("dtach: a socket whose name could not have come from this page",
  list("dtach", "weird name with spaces.dtach\n"), []);

// --- screen -----------------------------------------------------------
// The most decorated output of the four: a header, a date column in
// some versions, a state parenthetical, and a summary line.
const SCREEN = [
  "There are screens on:",
  "\t12345.main\t(08/15/2026 12:01:02 PM)\t(Detached)",
  "\t12002.build\t(08/15/2026 09:14:55 AM)\t(Attached)",
  "\t11888.shared\t(Multi, attached)",
  "3 Sockets in /run/screen/S-alice.",
  "",
].join("\n");
eq("screen: names off the pid, state from the last parenthetical",
  list("screen", SCREEN),
  [
    { name: "main", attached: false, at: null },
    { name: "build", attached: true, at: null },
    { name: "shared", attached: true, at: null },
  ]);
eq("screen: nothing running", list("screen", "No Sockets found in /run/screen/S-alice.\n\n"), []);
eq("screen: nothing printed", list("screen", ""), []);

// --- every parser survives garbage ------------------------------------
// The whole contract: these strings come from tools this page does not
// control, so an unrecognized shape is an empty list, never a throw and
// never an invented row.
const GARBAGE = [
  "", "\n\n\n", "\t\t\t", "%%%%", "\u0000\u0001\u0002",
  "Permission denied\n", "-bash: tmux: command not found\n",
  "a".repeat(10_000),
];
for (const p of PRESETS) {
  for (const g of GARBAGE) {
    let out;
    try {
      out = p.parseList(g);
    } catch (e) {
      fail(`${p.id}: parseList threw on garbage`, `${JSON.stringify(g.slice(0, 20))}: ${e}`);
      continue;
    }
    if (!Array.isArray(out)) fail(`${p.id}: parseList returned a non-array`, JSON.stringify(out));
  }
  // A parser must also survive the absence of any string at all: the
  // caller reaches these with whatever a probe came back with.
  try {
    eq(`${p.id}: parseList(undefined)`, p.parseList(undefined), []);
    eq(`${p.id}: parseList(null)`, p.parseList(null), []);
  } catch (e) {
    fail(`${p.id}: parseList threw on a missing string`, `${e}`);
  }
}

// --- detection --------------------------------------------------------
if (!/command -v/.test(detectCommand) || !/; true$/.test(detectCommand)) {
  fail("detectCommand", `lost its portable shape or its trailing true: ${detectCommand}`);
}
eq("parseDetect: two of four", parseDetect("dtach\ntmux\n"),
  { dtach: true, abduco: false, tmux: true, screen: false });
eq("parseDetect: nothing installed", parseDetect(""),
  { dtach: false, abduco: false, tmux: false, screen: false });
eq("parseDetect: a shell banner is not a tool", parseDetect("MOTD: hello\nscreen\n"),
  { dtach: false, abduco: false, tmux: false, screen: true });
eq("parseDetect: no output at all", parseDetect(undefined),
  { dtach: false, abduco: false, tmux: false, screen: false });
eq("TOOLS mirrors the presets", TOOLS, PRESETS.map((p) => p.id));

// --- names ------------------------------------------------------------
for (const good of ["main", "a", "build-2", "with_underscore", "x".repeat(32)]) {
  if (!validName(good)) fail("validName", `rejected ${JSON.stringify(good)}`);
}
// Everything a shell could act on, plus the empty and the overlong.
for (const bad of [
  "", " ", "x".repeat(33), "with space", "semi;colon", "dollar$sign", "quote\"d",
  "back`tick`", "slash/es", "new\nline", "..", "*", "$(whoami)", undefined, null,
]) {
  if (validName(bad)) fail("validName", `accepted ${JSON.stringify(bad)}`);
}

// --- command recognition ----------------------------------------------
// Phase 1 wrote fixed lines; they must keep being recognized, or a
// returning user's history entry reads as an unrecognizable custom
// command and loses the picker.
const P1_DTACH =
  'mkdir -p "$HOME/.wosh" && exec dtach -A "$HOME/.wosh/main.dtach" -r winch "$SHELL"';
const P1_TMUX = "exec tmux new-session -A -D -s wosh";
const P1_ABDUCO = 'exec abduco -A wosh "$SHELL"';
const P1_SCREEN = "exec screen -D -R -S wosh";
const named = (command) => {
  const m = matchCommand(command);
  return m ? { preset: m.preset.id, name: m.name } : null;
};
eq("phase-1 dtach line", named(P1_DTACH), { preset: "dtach", name: "main" });
eq("phase-1 tmux line", named(P1_TMUX), { preset: "tmux", name: "wosh" });
eq("phase-1 abduco line", named(P1_ABDUCO), { preset: "abduco", name: "wosh" });
eq("phase-1 screen line", named(P1_SCREEN), { preset: "screen", name: "wosh" });
// Unquoted $HOME and `tmux new` are both spellings a user may have
// typed by hand for the same thing.
eq("dtach without the quotes",
  named("exec dtach -A $HOME/.wosh/build.dtach -r winch $SHELL"),
  { preset: "dtach", name: "build" });
eq("tmux's short subcommand", named("exec tmux new -A -D -s build"),
  { preset: "tmux", name: "build" });
eq("plain shell is not a session", named(""), null);
eq("whitespace is not a session", named("   "), null);
eq("an unrecognizable custom command", named("exec htop"), null);
eq("a command mentioning a tool but not attaching", named("tmux kill-server"), null);
eq("no command at all", named(undefined), null);

// Round trip: what the fold writes is what the picker reads back.
for (const p of PRESETS) {
  for (const name of ["main", "build-2", "x_1"]) {
    eq(`${p.id}: command(${name}) round-trips`, named(p.command(name)),
      { preset: p.id, name });
  }
  if (typeof p.detachKeys !== "string" || !p.detachKeys.length) {
    fail(`${p.id}: detachKeys`, `not a keystroke: ${JSON.stringify(p.detachKeys)}`);
  }
  if (!/2>\/dev\/null \|\| true$/.test(p.listCommand)) {
    fail(`${p.id}: listCommand`,
      `must swallow its own failure so a missing tool parses as zero sessions: ${p.listCommand}`);
  }
}

if (failures) {
  console.error(`sessions-parse: ${failures} failure(s)`);
  process.exit(1);
}
console.log("PASS sessions-parse: presets, name validation, command matching, detection and all four list parsers");
