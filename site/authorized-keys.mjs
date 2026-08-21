// Installing an `authorized_keys` line on a machine, the way
// `ssh-copy-id` does it -- as pure functions, so the command can be run
// against a real shell by a plain-node gate
// (host-test/install-command.mjs) instead of only being eyeballed.
//
// No DOM, no imports, nothing that touches a connection: the same shape
// sessions.mjs has, and for the same reason. The command below is the
// part that has to be right, and the only way to know it is right is to
// run it.

/// Install an authorized_keys line on the machine this session is
/// connected to, the way `ssh-copy-id` does it.
///
/// The mechanism is the point. ssh-copy-id does NOT type into your
/// shell -- it opens a second channel and runs one command there --
/// and wosh has exactly that already (`probe`, the no-pty channel the
/// session picker asks its questions on). So this cannot land in a
/// pager, an editor or a password prompt, whatever the terminal
/// happens to be doing.
///
/// The command is ssh-copy-id's, minus the parts that only make sense
/// for a local key file, and each piece is there for a reason it
/// learned the hard way:
///
///   umask 077        sshd IGNORES authorized_keys, silently, if it
///                    or ~/.ssh is group- or world-writable.
///   tail -1c ...     if the existing file does not end in a newline,
///                    a plain append concatenates onto its last line
///                    and corrupts BOTH keys. Command substitution
///                    strips trailing newlines, so an empty result
///                    means "ends with a newline, or is not there".
///   restorecon       on SELinux a .ssh created in the wrong context
///                    is unusable, and the failure looks like a
///                    rejected key.
///
/// Plus one thing ssh-copy-id gets by probing the server instead: it
/// refuses to add a key that is already there, matched on the key
/// BLOB (the comment may differ and does not make it a new key).
export const installCommand = (line) => {
  const blob = line.split(/\s+/)[1] ?? "";
  return [
    "cd || exit 1",
    "umask 077",
    "mkdir -p .ssh || exit 1",
    `if grep -qsF '${blob}' .ssh/authorized_keys; then echo WOSH_ALREADY; exit 0; fi`,
    `{ [ -z "$(tail -1c .ssh/authorized_keys 2>/dev/null)" ] || echo >> .ssh/authorized_keys; } || exit 1`,
    `printf '%s\\n' '${line}' >> .ssh/authorized_keys || exit 1`,
    "if command -v restorecon >/dev/null 2>&1; then restorecon -F .ssh .ssh/authorized_keys 2>/dev/null; fi",
    "echo WOSH_ADDED",
  ].join("; ");
};

/// A comment is the third field of an authorized_keys line, and it
/// rides inside a single-quoted shell word: a quote or a newline in
/// it would end the word (or the LINE, appending a second key). The
/// whitelist is the whole defence -- the same posture as session
/// names in sessions.mjs.
export const cleanComment = (s) =>
  String(s ?? "")
    .replace(/[^\w.@+ -]+/g, "-") // spaces stay: the word is quoted, and "my phone" reads better
    .replace(/\s+/g, " ")
    // Trim dashes and spaces TOGETHER, not one then the other:
    // stripping either can expose the other ("' ; echo" folds to
    // "- - echo", whose leading run is dash, space, dash).
    .replace(/^[-\s]+|[-\s]+$/g, "")
    .slice(0, 64)
    .replace(/[-\s]+$/, ""); // the slice can leave a new trailing edge
