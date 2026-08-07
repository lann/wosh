// Async spike, node leg (JSPI). Asserts the subset that works on the
// pinned lann/jco fork and records the known-broken pieces:
//
//   works:  sync exports; async-lifted exports (callback ABI) including
//           internal goroutine+channel concurrency
//   broken: [async-lower] imports called from the guest — jco's subtask
//           bookkeeping rejects or hangs them (same defect family as
//           polymorph-iroh#10 / lann/jco#11)
//
// wasmtime runs the full set except Go-native timers in async exports
// (go1.25.5-wasi-on-idle-v2 limitation; explicit WaitFor works there).
import assert from "node:assert/strict";
import { asyncProbes } from "./generated-async/async-probe.js";

assert.equal(asyncProbes.chanPipeline(4, 100), 5350n);
assert.equal(await asyncProbes.spinPipeline(4, 100), 5350n);
console.log("sync export + async-lifted export (goroutines, channels): OK");

// Known-broken: guest-called [async-lower] import. The failure escapes
// through a microtask (unhandled rejection or hang), so probe it in a
// subprocess with a timeout rather than in-process.
import { spawnSync } from "node:child_process";
const probe = spawnSync(
  process.execPath,
  [
    "--experimental-wasm-jspi",
    "-e",
    `import("./generated-async/async-probe.js").then(m => m.asyncProbes.waitForEcho(10)).then(v => { console.log("value:" + v); process.exit(0); });`,
  ],
  { cwd: import.meta.dirname, timeout: 5000, encoding: "utf8" },
);
const waitForWorks = probe.status === 0 && probe.stdout.includes("value:");
console.log(
  `[async-lower] import from guest: ${waitForWorks ? "WORKS NOW (jco fixed - update findings!)" : "broken on jco fork (known)"}`,
);

console.log("async spike node leg: OK (bounded expectations)");
