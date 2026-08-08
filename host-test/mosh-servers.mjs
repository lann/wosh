// Shared mosh-server launcher for the M1 conformance driver and the
// M2 browser-smoke bridge. Spawns either the stock C mosh-server or
// the mosh-go wrapper (moshgo-server/), parses the MOSH CONNECT line,
// and returns { port, key, stop }.

import { spawn } from "node:child_process";
import path from "node:path";

export async function startServer(kind) {
  const goBin = path.join(process.env.HOME, ".local/go/bin");
  const env = {
    ...process.env,
    LC_ALL: "C.UTF-8",
    TERM: "xterm-256color",
    PATH: `${goBin}:${process.env.PATH}`,
  };

  let child;
  if (kind === "c") {
    child = spawn(
      "mosh-server",
      ["new", "-i", "127.0.0.1", "-c", "256", "--", "bash", "--noprofile", "--norc", "-i"],
      { env, detached: true },
    );
  } else if (kind === "go") {
    child = spawn("go", ["run", "."], {
      cwd: path.join(import.meta.dirname, "moshgo-server"),
      env: { ...env, MOSHGO_SHELL: "/bin/sh" },
      detached: true,
    });
  } else {
    throw new Error(`unknown server kind ${kind}`);
  }

  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (d) => (stdout += d));
  child.stderr.on("data", (d) => (stderr += d));

  const deadline = Date.now() + 15_000;
  let m;
  while (!(m = stdout.match(/MOSH CONNECT (\d+) (\S+)/))) {
    if (Date.now() > deadline)
      throw new Error(`server never printed MOSH CONNECT.\nstdout: ${stdout}\nstderr: ${stderr}`);
    await new Promise((r) => setTimeout(r, 25));
  }
  const port = Number(m[1]);
  const key = m[2];

  // The C server detaches (parent exits); the real pid is on stderr.
  let detachedPid = null;
  if (kind === "c") {
    const dm = stderr.match(/detached, pid =\s*(\d+)/);
    if (dm) detachedPid = Number(dm[1]);
  }

  const stop = () => {
    try {
      if (detachedPid) process.kill(detachedPid, "SIGKILL");
    } catch {}
    try {
      process.kill(-child.pid, "SIGKILL"); // whole process group (go run)
    } catch {}
  };
  return { port, key, stop };
}
