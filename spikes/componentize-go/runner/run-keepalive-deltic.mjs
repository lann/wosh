// Keep-alive probes, deltic lane (finding 31, wosh#25): the goroutine
// workaround evaluated against deltic's settlement pump (deltic#121,
// embedder-api amendment A11 — between-calls guest liveness; in the main
// deltic pin since a2f84a5).
//
// Deliberately self-contained (no host-test/deltic-host.ts): this runner
// needs none of the polymorph host modules, and instantiating bare keeps
// the probe's between-calls idle window free of unrelated machinery.
import assert from "node:assert/strict";
import { Translator } from "@deltic/runtime/shim";
import { instantiate } from "@deltic/runtime/embedder";
import { wasiShims } from "@deltic/wasi-shims";

const shimPath = Deno.env.get("DELTIC_TRANSLATOR");
if (!shimPath) throw new Error("DELTIC_TRANSLATOR unset (justfile _translator-next)");
const translator = await Translator.create(await Deno.readFile(shimPath));
const bytes = await Deno.readFile("../async/main.wasm");
const { plan, adapters } = translator.translate(bytes);

const load = async () => {
  const instance = await instantiate({ plan, componentBytes: bytes, adapters }, {
    ...wasiShims({ cli: { args: ["keepalive-spike"] } }),
  });
  return instance.exports["experiment:spike/async-probes"];
};

const deadline = (p, ms, what) =>
  Promise.race([
    p,
    new Promise((_, rj) => setTimeout(() => rj(new Error(`TIMEOUT ${ms}ms: ${what}`)), ms)),
  ]);

const probes = await load();

// 1. Guard converts the finding-3a EXIT trap into WAIT parking: plain
//    time.Sleep inside an async export completes.
const g = await deadline(probes.sleepGuarded(30n), 5_000, "sleep-guarded(30)");
assert.ok(g >= 30n && g < 200n, `sleep-guarded elapsed ${g}ms`);
console.log(`ok: sleep-guarded(30) -> ${g}ms (guard period 5ms)`);

// 2. select + time.After fires under the guard (Go-native timeouts work).
const sel = await deadline(
  probes.selectTimeoutGuarded(30n),
  5_000,
  "select-timeout-guarded(30)",
);
assert.equal(sel, true);
console.log("ok: select-timeout-guarded(30) took the timeout arm");

// 3. THE AMBIENT PROBE. spawn-bg arms the eternal ticker, spawns a
//    background goroutine (sleep 50ms, record ms-from-spawn at fire), and
//    returns immediately — the goroutine outlives its task. We then idle
//    300ms making NO calls. The discriminator is guest-side:
//
//      ambient (settlement pump drives ticker slices) -> marker ~= 50-70
//      driver-gated (pre-A11: frozen until the next call) -> marker ~= 300+
await deadline(probes.spawnBg(50n), 5_000, "spawn-bg(50)");
await new Promise((r) => setTimeout(r, 300));
const marker = await deadline(probes.readMarker(), 5_000, "read-marker");
console.log(`read-marker: background goroutine fired ${marker}ms after spawn`);
assert.ok(marker !== 0n, "background goroutine never fired");
assert.ok(
  marker < 200n,
  `NOT ambient: fired at ${marker}ms — driver-gated (settlement pump regression?)`,
);
console.log("ok: ambient between-calls liveness (settlement pump / A11) confirmed");

// 4. The canary, LAST (a trap poisons the instance): bare time.Sleep in an
//    async export must still trap (finding 3a). When this starts passing,
//    upstream integrated Go timers with the CM event loop — retire the
//    keepalive helpers (wosh#25) and update the finding.
let canary;
try {
  canary = await deadline(probes.sleepEcho(10n), 5_000, "sleep-echo canary");
} catch (e) {
  console.log(`ok(canary): sleep-echo still traps -> ${String(e).split("\n")[0]}`);
}
if (canary !== undefined) {
  throw new Error(
    `CANARY RETIRED: sleep-echo(10) returned ${canary} — upstream integrated ` +
      `Go timers; retire the keepalive helpers (wosh#25) and update finding 31`,
  );
}

console.log("keepalive spike deltic-next leg: OK");
// The eternal ticker keeps a wait-for timer pending forever (leak-by-design,
// keepalive.EnsureTicker) — the event loop never drains; exit explicitly.
Deno.exit(0);
