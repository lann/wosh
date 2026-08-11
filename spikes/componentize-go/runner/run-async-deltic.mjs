// Async spike, deltic leg: componentize-go's async-ABI exports runtime-
// linked by deltic on Deno (no JSPI flags — deltic handles component-model
// async natively; asyncness comes from the binary's ABI, not a host flag).
// Retires the jco node (--experimental-wasm-jspi) + browser legs.
//
// Every export is Promise-shaped under deltic (sync-lifted funcs too), so
// this driver awaits every call including the plain `chan-pipeline` sync
// export.
import assert from "node:assert/strict";
import { loadArtifacts, deadline, describeError } from "../../../host-test/deltic-host.ts";
import { instantiate } from "@deltic/runtime/embedder";
import { wasiShims } from "@deltic/wasi-shims";

const artifacts = await loadArtifacts("../async/main.wasm");
const shims = wasiShims({ cli: { args: ["async-spike"] } });
const instance = await instantiate(artifacts, { ...shims });

const probes = instance.exports["experiment:spike/async-probes"];

assert.equal(await probes.chanPipeline(4, 100), 5350n);
assert.equal(await probes.spinPipeline(4, 100), 5350n);
console.log("sync export + async-lifted export (goroutines, channels): OK");

// The jco leg's known-broken shape: a guest-called [async-lower] import
// (wasi:clocks/monotonic-clock@0.3.0 wait-for). Under deltic this is a
// first-class async-ABI call, not a JSPI hack, so it is expected to just
// work — bound it with a deadline anyway: a wedged suspension names itself
// instead of hanging the gate.
try {
  const v = await deadline(probes.waitForEcho(10n), 5_000, "waitForEcho(10)");
  console.log(`[async-lower] import from guest: WORKS under deltic -> ${v}`);
} catch (e) {
  console.log(`[async-lower] import from guest: FAILED under deltic — ${describeError(e)}`);
  throw e;
}

console.log("async spike deltic leg: OK");
