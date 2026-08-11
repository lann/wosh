// Sync spike, deltic leg: the componentize-go component runtime-linked by
// deltic on Deno, exports driven from JS. Asserts the same answers the
// wasmtime leg gives. Replaces the retired jco node + browser legs (see
// justfile "--- M0 spikes ---" section).
//
// Every export call is Promise-shaped under deltic (host-test/run-conformance.mjs
// comment, ported here); resource classes are PascalCase with camelCase
// methods (probes.tickBatch, new counters.Counter(...), etc).
import assert from "node:assert/strict";
import { loadArtifacts } from "../../../host-test/deltic-host.ts";
import { instantiate } from "@deltic/runtime/embedder";
import { wasiShims } from "@deltic/wasi-shims";

const artifacts = await loadArtifacts("../sync/main.wasm");
const shims = wasiShims({ cli: { args: ["sync-spike"] } });
const instance = await instantiate(artifacts, { ...shims });

const probes = instance.exports["experiment:spike/probes"];
const counters = instance.exports["experiment:spike/counters"];

assert.equal(await probes.add(2, 3), 5);

const echoed = await probes.echoBytes(new Uint8Array([1, 2, 250]));
assert.deepEqual([...echoed], [1, 2, 250]);

assert.equal(
  await probes.hashHex(new Uint8Array()),
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
);

const batch = await probes.tickBatch(3);
assert.equal(batch.length, 3);
assert.deepEqual([...batch[1]], [1, 0, 0xab, 0xcd]);

// Exported resource: construct, mutate, read, drop.
const c = new counters.Counter(41);
assert.equal(await c.increment(), 42);
assert.equal(await c.value(), 42);
const c2 = new counters.Counter(0);
assert.equal(await c2.increment(), 1);
assert.equal(await c.value(), 42); // instances independent
if (c[Symbol.dispose]) c[Symbol.dispose]();

// M7 probe: goroutines parked on channels survive across export calls
// and resume when fed + scheduler-pumped (the ssh engine's shape).
await probes.spawnParked();
assert.equal(await probes.parkedResult(), 0, "chain must still be parked");
await probes.poke(20);
assert.equal(await probes.parkedResult(), 42, "chain must have run: (20+1)*2");

// M7 probe: Go-native timer in a plain goroutine (sync world). The
// interesting answer is whatever it is — record it, don't assume.
await probes.spawnSleeper(5);
assert.equal(await probes.sleepResult(), 0, "sleeper must not finish instantly");
await new Promise((r) => setTimeout(r, 25));
await probes.pump();
console.log(
  `sync spike: parked-goroutine chain OK; sleeper after 25ms wall + pump: ${
    (await probes.sleepResult()) ? "FIRED" : "still parked"
  }`,
);

console.log("sync spike deltic leg: OK");
