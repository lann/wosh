# Task state

Point-in-time working state for resuming this effort. The full plan is
`PLAN.md`; the design record and findings live in `README.md`; this
file says where work stopped and what comes next. Update it at the end
of each session.

## Status: DELTIC CUTOVER COMPLETE — browser leg live (2026-08-10)

2026-08-11 addendum: the client now deploys to GitHub Pages on every
main merge (`.github/workflows/pages.yml`; repo went public), `just
proxy-personal` runs the proxy against n0's public relays with QR/RP
defaults pointing at the Pages client, the **WebRTC upgrade leg
landed** (finding 27): both sides enable the wire, the glue offers the
upgrade hint, `client-session.path` observes it, and m5-browser-e2e
hard-asserts the relay→webrtc move (Deno lane logs it, ~0.8 s) — and
the **M6 browser ceremony leg landed** (finding 28, `just
m6-browser`): persist/reattach from the real page against the real RP,
PRF wrap/unwrap in the page, floor-jump re-escrow per reattach.

Post-cutover pin bump (same day, finding 26): deltic @ a18be734
(includes the hop-atomicity fix lann/deltic#82 our M2 gate found, the
timer re-arm #78, smoke-c0 path fix #79), polymorph-iroh @ d8fdd039
(their jco host retired #40, parking kernel adopted #43, event-driven
endpoint wakeups #44 — the jco-era polling latency workaround is
gone). One wosh-side fix rode along: drive_ssh drains to quiescence
on exit-status (exit can beat the final stdout through the engine's
buffers under the new arrival coalescing).

This session (owner instruction: "rebuild, replacing jco with
lann/deltic; update all polymorph dependencies") replaced the JS host
wholesale and shipped the previously A3-blocked browser leg:

- **jco is gone.** deltic (runtime linker, Deno + browsers) hosts
  every JS-side component: M1 conformance (Deno lane), M2 browser
  smoke, all three spikes (single deltic leg each; the jco node +
  browser legs retired — the real M2/M5 gates cover browsers with the
  actual workload). No transpile step, no generated trees, no JSPI
  flag. Root `deno.json` = the one import map; `deno.lock` + npm deps
  via `deno install --allow-scripts=npm:node-datachannel` (setup.sh).
- **Pins.** `.deps/polymorph-iroh` → f46a80df (deltic-leg merge; its
  nested webcrypto/websocket/webrtc pins carry the deltic host
  modules). NEW `.deps/deltic` clone; translator shim built there by
  setup.sh (`just _translator` prints the path; recipes export
  DELTIC_TRANSLATOR). One mechanical native rename rode the bump:
  `WasiWebrtc*` → `Webrtc*` in the wasmtime-impl types (5 files).
- **Browser leg (finding 25):** `just m5` = m5-web + m5-client-deno
  (composed client on the Deno lane vs real proxy) + m5-browser-e2e
  (headless Chromium drives the real page: `/#connstring` → panel
  connect → prompt/echo/resize/stats/detach; wrong-token negative
  first). `web/deltic-entry.ts` → `just web-bundle` →
  `web/dist/deltic.js`; app.mjs has two modes (bridge M2 / iroh M5,
  `connectIroh`); boot.mjs connects for real (pending row has the
  token; saved proxies prompt — tokens deliberately not persisted).
- **Upstream deltic defect found + fixed (finding 25):** FACT callee
  callback re-entries weren't promising-wrapped → `SuspendError` when
  the composed endpoint's `block_on(webcrypto sign)` hit
  `waitable-set.wait` mid-activation. Fixed in lann/deltic#70
  (merged) with a composed-wat regression fixture; wosh pins a rev
  including it.
- **Embedder path policy:** `WOSH_UDP=off` (guest env, no WIT change)
  makes the glue skip the endpoint's UDP bind — required in browsers
  where `wasi:sockets` is the fail-on-call stub profile. Native
  harnesses unchanged (default on).

## Pending / open (carried)

- **M7 in-page ssh leg**: unblocked, pure wosh work — a password
  prompt + host-key UX in the page over the existing connect-ssh
  surface (the M6 ceremony leg landed: finding 28).
- **RefCell borrow hazard** (endpoint guest, upstream-documented):
  never fired in our gates (connects at attempt 1), but
  browser-e2e.mjs keeps an 8-attempt budget. If it starts firing,
  that's upstream polymorph-iroh work (their issue tracker).
- Finding 10 follow-ups: leg-b scroll artifact; predictor not
  RTT-adaptive; RTO clamp 10 s measured live (finding 19) — fork
  patch to C mosh's [50 ms, 1 s] if long sessions stall on idle
  recovery.
- mosh-go throwaway limitation (DEPS.md): C server retains all client
  states, quenches past 1024 — long sessions degrade; candidate patch
  sketched there.
- Escrow refresh: per-reattach floor-jump re-escrow LANDED (finding
  28). Residual: re-escrow *within* a session epoch (immortal
  sessions crossing 2^32 datagrams) needs a retained PRF output or a
  fresh assertion gesture — policy question, not plumbing.
- ssh v0 gaps (deliberate): password auth only; one exec per session;
  no interactive shell/stdin surface; hostkey pinning embedder-side.
  The unextractable-WebCrypto-ssh-key step needs an async engine
  export — no longer blocked (deltic), just unbuilt.
- Upstream courtesies: deltic/polymorph module-identity convergence
  (finding 26 addendum: sibling deltic modules' standalone URL pins
  vs consumer import maps — bless the prefix-mapping pattern in
  deltic docs/consumers.md or drop standalone pins); mosh-go wasip
  build-tag patch; per-path
  datagram-ceiling issue on polymorph-iroh; mosh-go fork patch 4 +
  resume-adoption learning; connection close-reason accessor on the
  endpoint WIT (the Error-then-close race).
- `just m5-netem` not rerun this session (needs passwordless sudo for
  tc; measurement matrix, not a regression gate).

## Environment

- Tools: componentize-go 0.4.1, host Go 1.26.5 at `~/.local/go/bin`
  (PATH-prefixed by recipes), wasmtime 47.0.1 CLI / crate 47.0.3,
  wasm-tools 1.247.0, wac 0.10.1, node 24.18.0 (harness scripts:
  playwright/ws only), **deno 2.9.5** (component hosting), just
  1.54.0, Rust 1.96 + wasm32-wasip2 + wasm32-unknown-unknown (deltic
  translator shim). M6: webauthn-rs 0.5 (proxy),
  webauthn-authenticator-rs 0.5.5 + webauthn-rs-proto 0.5 (harness).
  M7: golang.org/x/crypto v0.49.0 (engine go.mod, unpatched); russh
  0.62.5 (ssh-e2e stand-in).
- `.deps/mosh-go` — committed vendored fork (4 patches, DEPS.md).
  `.deps/polymorph-iroh`, `.deps/deltic` — setup.sh clones at the
  pins in scripts/setup.sh (deltic consumed as a git reference; its
  translator shim built locally, stamp files `.wosh-built-at`).
- The old `../polymorph-iroh` sibling checkout is GONE (the jco
  `file:` dep with it); nothing references it anymore.
- Browser legs: playwright-core + chrome.mjs (Chromium 151).
- mosh-server 1.4.0 at `/usr/bin/mosh-server`.
- Harness ports: :3345 m3, :3347 m4, :3348 m5-client-deno, :3349 m6,
  :3350 m7, :3352 m5-browser-e2e, :3353/:3354 m6-browser
  (relay/page). The user's own `mosh-server -p 0` is NOT ours; never
  kill it.
- This repo: private remote `lann/wosh`. GitHub auth: `gh` as `lann`.

## Entry points

- `just m5` — web modules + Deno-lane client E2E + the browser E2E
  (the deltic showcase); `just m5-browser-e2e` alone for the page
  gate. `just m7 m6 m4 m3` — native gates; `just m2` / `just
  web-serve` — dev bridge; `just m1` — conformance; `just spikes` —
  wasmtime + deltic spike legs.
- `just web-bundle` — rebuild `web/dist/deltic.js` after touching
  `web/deltic-entry.ts` or bumping deltic.
- `just engine-bindings` — regen after `wit/mosh.wit` changes
  (rewrites go.mod deliberately; commit). NOTE:
  `client-core/wit/deps/mosh/mosh.wit` is a HARD LINK to
  `wit/mosh.wit` (same inode) — don't break it.
- `scripts/setup.sh` — toolchain + .deps pins (idempotent; owns the
  polymorph-iroh AND deltic pins + translator build).
- `scripts/web-deploy-tree.sh <dest>` — static deploy tree (now
  includes dist/: bundle + composed client + translator; a static
  host serves a working client).
- `proto/` — control/framing/escrow shapes (`cargo test --lib`).
