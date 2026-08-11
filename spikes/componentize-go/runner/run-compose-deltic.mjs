// Composition spike, deltic leg: the wac-composed component (Rust adapter
// + componentize-go engine) runtime-linked by deltic on Deno, driven from
// JS. Same assertions as the wasmtime leg (retired jco node + browser
// legs — see justfile "--- composition spike (D7) ---" section).
//
// Every export call is Promise-shaped under deltic; result<T, string> err
// surfaces as a WitError with a `.payload` (host-test/run-conformance.mjs
// comment, ported here).
import { loadArtifacts, describeError, WitError } from "../../../host-test/deltic-host.ts";
import { instantiate } from "@deltic/runtime/embedder";
import { wasiShims } from "@deltic/wasi-shims";

const artifacts = await loadArtifacts("../../compose/composed.wasm");
const shims = wasiShims({ cli: { args: ["compose-spike"] } });
const instance = await instantiate(artifacts, { ...shims });

const driver = instance.exports["experiment:compose-spike/driver"];

const eq = (a, b, what) => {
  if (a !== b) throw new Error(`${what}: ${a} !== ${b}`);
};

// Cross-component function call, through the fused boundary.
const version = await driver.versionViaEngine();
if (!version.includes("mosh-go v0.5.3-0.20260405220648-8dca5c67ec8e")) {
  throw new Error(`unexpected engine version through composition: ${version}`);
}

// Resource construct + methods + drop across the boundary.
const report = await driver.sessionRoundTrip("AAAAAAAAAAAAAAAAAAAAAA", 80, 24);
eq(report.datagrams, 2, "datagrams (association + keystroke state)");
eq(report.sentNum, 1n, "sent-num");
if (!(report.firstDatagramLen > 24 && report.firstDatagramLen < 200)) {
  throw new Error(`implausible first datagram len: ${report.firstDatagramLen}`);
}

// Error propagation from the engine through the adapter.
let threw = null;
try {
  await driver.sessionRoundTrip("notakey!", 80, 24);
} catch (e) {
  threw = e;
}
if (!threw) throw new Error("bad key did not error through composition");
const msg = threw instanceof WitError ? String(threw.payload) : describeError(threw);
if (!msg.includes("bad key")) throw new Error(`unexpected bad-key error: ${msg}`);

console.log(
  `compose spike deltic leg: OK (version=${version.slice(0, 30)}…, first-dgram=${report.firstDatagramLen}B)`,
);
