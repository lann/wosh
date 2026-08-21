// Gate: the command the page asks a machine to run when it installs an
// `authorized_keys` line, executed against a REAL shell and a real
// directory.
//
// This is the half of that feature a browser gate cannot judge. The
// mobile gate pins the command's SHAPE against a stub; what it cannot
// tell you is whether the thing actually works -- whether `umask 077`
// lands on both the directory and the file, whether the missing-newline
// guard really prevents two keys from being concatenated, whether the
// quoting survives a comment someone typed. Those are shell questions,
// so this asks a shell.
//
// Plain node, no browser, no network: site/authorized-keys.mjs is
// DOM-free precisely so this can import the real function rather than a
// copy of it (the same arrangement sessions.mjs has with
// host-test/sessions-parse.mjs).
//
// Usage: node host-test/install-command.mjs

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { cleanComment, installCommand } from "../site/authorized-keys.mjs";

let failures = 0;
const fail = (msg) => {
  console.error(`FAIL: ${msg}`);
  failures++;
};
const ok = (cond, msg) => cond || (fail(msg), false);

/// Run the page's command in `home`, the way the target's shell would:
/// one string, `sh -c`, with HOME set and nothing else assumed.
const install = (home, line) => {
  const out = execFileSync("sh", ["-c", installCommand(line)], {
    cwd: home,
    env: { ...process.env, HOME: home },
    encoding: "utf8",
  });
  return out.trim();
};
const fresh = () => mkdtempSync(join(tmpdir(), "wosh-copyid-"));
const keysOf = (home) => readFileSync(join(home, ".ssh/authorized_keys"), "utf8");
const mode = (p) => (statSync(p).mode & 0o777).toString(8);

const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTKEYFORTHEGATE wosh-browser";

// 1. A home with no ~/.ssh at all -- the first-ever install.
{
  const home = fresh();
  const said = install(home, KEY);
  ok(said === "WOSH_ADDED", `a first install should say WOSH_ADDED, said ${JSON.stringify(said)}`);
  ok(keysOf(home).trim() === KEY, `the key did not land: ${JSON.stringify(keysOf(home))}`);
  // sshd IGNORES authorized_keys, silently, if these are loose. This is
  // what `umask 077` is in the command for, and a permission bug here
  // looks exactly like a key that "just does not work".
  ok(mode(join(home, ".ssh")) === "700", `~/.ssh should be 700, is ${mode(join(home, ".ssh"))}`);
  ok(
    mode(join(home, ".ssh/authorized_keys")) === "600",
    `authorized_keys should be 600, is ${mode(join(home, ".ssh/authorized_keys"))}`,
  );
  console.log("[1] a fresh home gets ~/.ssh 700 and authorized_keys 600, with the key in it");
  rmSync(home, { recursive: true, force: true });
}

// 2. The same key twice: reported, not duplicated.
{
  const home = fresh();
  install(home, KEY);
  const said = install(home, KEY);
  ok(said === "WOSH_ALREADY", `a repeat install should say WOSH_ALREADY, said ${JSON.stringify(said)}`);
  ok(keysOf(home).trim().split("\n").length === 1, `the key was added twice:\n${keysOf(home)}`);
  // ...and the comment is not what makes a key "the same": the blob is.
  const renamed = install(home, KEY.replace("wosh-browser", "renamed on another day"));
  ok(renamed === "WOSH_ALREADY", "a key already present under another comment must still count as present");
  console.log("[2] the same key is recognised (by its blob, not its comment) and not added twice");
  rmSync(home, { recursive: true, force: true });
}

// 3. THE ONE ssh-copy-id exists to remember: an authorized_keys with no
//    trailing newline. A plain `>>` concatenates the new key onto the
//    last line and breaks BOTH.
{
  const home = fresh();
  mkdirSync(join(home, ".ssh"), { recursive: true, mode: 0o700 });
  const existing = "ssh-rsa AAAAEXISTINGKEY somebody-else";
  writeFileSync(join(home, ".ssh/authorized_keys"), existing); // deliberately no \n
  const said = install(home, KEY);
  ok(said === "WOSH_ADDED", `should have added, said ${JSON.stringify(said)}`);
  const lines = keysOf(home).trim().split("\n");
  ok(lines.length === 2, `expected 2 keys, got ${lines.length}:\n${keysOf(home)}`);
  ok(lines[0] === existing, `the existing key was corrupted: ${JSON.stringify(lines[0])}`);
  ok(lines[1] === KEY, `the new key was corrupted: ${JSON.stringify(lines[1])}`);
  console.log("[3] a file with no trailing newline gains a key without either one being mangled");
  rmSync(home, { recursive: true, force: true });
}

// 4. Comments people type. The comment is the third field of the line
//    and rides inside a single-quoted shell word, so a quote or a
//    newline in it would end the word -- or the LINE, appending a key
//    nobody asked for. cleanComment is the whole defence; this checks it
//    against a real shell rather than against a regex's reputation.
{
  const hostile = [
    ["my phone", "my phone"],
    ["' ; rm -rf ~ ; echo '", "rm -rf"],
    ["a\nssh-rsa AAAAINJECTED attacker", "a-ssh-rsa"],
    ["../../etc/passwd", "..-..-etc-passwd"],
    ["'\"$(id)`id`", "id-id"],
  ];
  for (const [typed] of hostile) {
    const home = fresh();
    const comment = cleanComment(typed);
    ok(!/['\r\n]/.test(comment), `cleanComment let a quote or newline through: ${JSON.stringify(comment)}`);
    const line = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTKEYFORTHEGATE ${comment}`;
    install(home, line);
    const written = keysOf(home);
    ok(
      written.trim().split("\n").length === 1,
      `a typed comment produced more than one line:\n${written}`,
    );
    ok(written.trim() === line, `the line was not written verbatim: ${JSON.stringify(written)}`);
    // Nothing the comment said should have RUN: the home is otherwise
    // untouched.
    ok(
      statSync(home).isDirectory(),
      "the home directory did not survive a comment, which means something ran",
    );
    rmSync(home, { recursive: true, force: true });
  }
  console.log(`[4] ${hostile.length} typed comments, quotes and newlines included, produce one literal line`);
}

// 5. The command is one line. A newline in what the page sends would be
//    a second command to the remote shell.
{
  const cmd = installCommand(KEY);
  ok(!/[\r\n]/.test(cmd), "the install command contains a newline");
  console.log("[5] the command is a single line");
}

if (failures) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log(
  "\nINSTALL-COMMAND PASS: the page's ssh-copy-id command creates ~/.ssh 700 / " +
    "authorized_keys 600, refuses to duplicate a key, appends safely to a file with " +
    "no trailing newline, and cannot be talked into running a typed comment",
);
