# Task state

Point-in-time working state for resuming this effort. The full plan is
`PLAN.md`; the design record and findings live in `README.md`; this
file says where work stopped and what comes next. Update it at the end
of each session.

## Status: DELTIC CUTOVER COMPLETE — browser leg live (2026-08-10)

2026-08-11 addendum: the client now deploys to GitHub Pages on every
main merge (since gated on the CI gates; `.github/workflows/ci.yml`;
repo went public), `just
proxy-personal` runs the proxy against n0's public relays with QR/RP
defaults pointing at the Pages client, and every finding-24 browser
follow-up landed: the **WebRTC upgrade leg** (finding 27,
m5-browser-e2e hard-asserts the relay→webrtc move), the **M6 browser
ceremony leg** (finding 28, `just m6-browser`: persist/reattach from
the real page against the real RP, PRF wrap/unwrap in-page,
floor-jump re-escrow per reattach), and the **M7 in-page ssh leg**
(finding 29, `just m7-browser`: ssh UX in the panel, TOFU host-key
pin, tampered pin refused before the password leaves the page).

Post-cutover pin bump (same day, finding 26): deltic @ a18be734
(includes the hop-atomicity fix lann/deltic#82 our M2 gate found, the
timer re-arm #78, smoke-c0 path fix #79), polymorph-iroh @ d8fdd039
(their jco host retired #40, parking kernel adopted #43, event-driven
endpoint wakeups #44 — the jco-era polling latency workaround is
gone). One wosh-side fix rode along: drive_ssh drains to quiescence
on exit-status (exit can beat the final stdout through the engine's
buffers under the new arrival coalescing).

2026-08-11, later: issue #7 landed (finding 30) — TRUE first-contact
ssh now parks at the host-key gate and the page confirms the
fingerprint BEFORE the password moves (two-phase `ssh-flow`; engine
password deferred; `just m7` grew flow decline/confirm phases,
`just m7-browser` grew the prompt/decline/confirm legs). Full gate
suite swept green. Also fixed en route: a pre-existing torn-buffer
race on the ssh exec output (engine `lockedBuf`).

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
  sketched there. Now tracked upstream: unixshells/mosh-go#3.
- Escrow refresh: per-reattach floor-jump re-escrow LANDED (finding
  28). Residual: re-escrow *within* a session epoch (immortal
  sessions crossing 2^32 datagrams) needs a retained PRF output or a
  fresh assertion gesture — policy question, not plumbing.
- ssh v0 gaps (deliberate): password auth only; one exec per session;
  no interactive shell/stdin surface. Triaged into issues: #7 DONE
  (finding 30 — first-contact fingerprint confirm BEFORE the password
  moves: two-phase ssh-flow begin/host-key/authenticate/decline, the
  engine's password deferred behind the host-key gate, panel prompt
  UX, native + browser gate legs; the user name rides begin because
  x/crypto snapshots its config pre-handshake — sent only post-gate),
  #8 (publickey auth with a non-extractable WebCrypto key over the
  polymorph signing-key handle; the async engine import is the work —
  unblocked since deltic), #9 (keyboard-interactive, riding #7's now-
  landed park→verdict→resume prompt plumbing). Interactive-shell
  fallback and multi-exec stay unfiled: product-scope decisions
  awaiting a concrete need.
- Upstream courtesies: ALL FILED 2026-08-11 — deltic module-identity
  convergence (lann/deltic#108); mosh-go wasip build tags
  (unixshells/mosh-go#1), pending-diff races + resume-adoption notes
  (#2), throwaway_num quench (#3); polymorph-iroh per-path datagram
  ceiling (polymorph-iroh#47) and peer close-info accessor for the
  Error-then-close race (polymorph-iroh#48).
- **deltic A11 family convergence: DONE** (2026-08-12, findings 31-33).
  The whole family now names `@deltic/*@0.1.0-pre.ga2f84a5` (A11, the
  settlement pump): deltic main went green after a node-datachannel
  prebuild flake on x64 was re-run and the release job published the
  prerelease; sibling bumps webcrypto#380 / websocket#51 / webrtc#157;
  polymorph-iroh#62 (sibling pins + own configs — lock regen must
  follow the sibling checkouts, not precede them: the lockfile links
  section records the siblings' @deltic/runtime dependency); wosh
  flipped the root deno.json version, folded the keep-alive spike onto
  the root config, and deleted deno-local-deltic.json. The local
  .deps/deltic checkout remains for exactly one thing: the
  translator-shim build, at the same commit the jsr prerelease names.
  Next bump of this shape: sed the version in root deno.json + sibling
  configs' repos, setup.sh BEFORE deno install, spikes+m1+m4+m5
  locally, CI for the rest.
- `just m5-netem` rerun 2026-08-11: all five cells green (RTO adapts
  250→684 ms under 100 ms delay; dial survives 10% loss). Needs
  passwordless sudo for tc; measurement matrix, not a regression
  gate.

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
  (relay/page), :3355 m7-browser. The user's own `mosh-server -p 0`
  is NOT ours; never kill it.
- This repo: private remote `lann/wosh`. GitHub auth: `gh` as `lann`.

## Entry points

- `just m5` — web modules + Deno-lane client E2E + the browser E2E
  (the deltic showcase); `just m5-browser-e2e` alone for the page
  gate. `just m6-browser m7-browser` — the in-page ceremony and
  inner-ssh legs. `just m7 m6 m4 m3` — native gates; `just m2` /
  `just web-serve` — dev bridge; `just m1` — conformance; `just
  spikes` — wasmtime + deltic spike legs.
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
