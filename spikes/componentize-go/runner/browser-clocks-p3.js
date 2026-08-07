// Browser stand-in for @bytecodealliance/preview3-shim/clocks (that
// package ships node-only): wasi:clocks@0.3.0 monotonic-clock over
// performance.now/setTimeout.
const originNs = () => BigInt(Math.round(performance.now() * 1e6));

export const monotonicClock = {
  now: originNs,
  resolution: () => 1_000_000n,
  getResolution: () => 1_000_000n,
  waitFor: (ns) => new Promise((r) => setTimeout(r, Number(ns / 1_000_000n))),
  waitUntil: (when) =>
    new Promise((r) => setTimeout(r, Math.max(0, Number((when - originNs()) / 1_000_000n)))),
};
