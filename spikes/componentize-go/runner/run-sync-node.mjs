// Sync spike, node leg: the componentize-go component transpiled by the
// pinned lann/jco fork, exports driven from JS. Asserts the same answers
// the wasmtime leg gave.
import assert from "node:assert/strict";
import { probes, counters } from "./generated-sync/sync-probe.js";

assert.equal(probes.add(2, 3), 5);

const echoed = probes.echoBytes(new Uint8Array([1, 2, 250]));
assert.deepEqual([...echoed], [1, 2, 250]);

assert.equal(
  probes.hashHex(new Uint8Array()),
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
);

const batch = probes.tickBatch(3);
assert.equal(batch.length, 3);
assert.deepEqual([...batch[1]], [1, 0, 0xab, 0xcd]);

// Exported resource: construct, mutate, read, drop.
const c = new counters.Counter(41);
assert.equal(c.increment(), 42);
assert.equal(c.value(), 42);
const c2 = new counters.Counter(0);
assert.equal(c2.increment(), 1);
assert.equal(c.value(), 42); // instances independent
if (c[Symbol.dispose]) c[Symbol.dispose]();

console.log("sync spike node leg: OK");
