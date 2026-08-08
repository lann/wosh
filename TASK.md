# Task state

Point-in-time working state for resuming this effort. The full plan is
`PLAN.md`; the design record and findings live in `README.md`; this
file says where work stopped and what comes next. Update it at the end
of each session.

## Status: M2 complete (browser gate passed), M3 next

- M0 `4003320`..`59d9b8f`; M1 `fe86742` (wire-compat gate, findings
  7–10); D7 `1929ae2` (composition ruling + spike, finding 11). This
  session: M2 — browser mosh over the throwaway ws bridge.
- **M2 gate PASSED** (findings 12–13): `just m2` — xterm.js + the
  jco-transpiled engine in headless Chromium; prompt, echo, resize
  green; prediction paints locally underlined at ~145 ms vs 300 ms
  RTT under a 150 ms/way bridge delay. `just web-serve` = manual mode
  (one mosh-server + shell per tab; ?delay=150 to feel prediction).
- **Finding 13 (M6 design input)**: a fresh engine instance can never
  rejoin a running mosh-server (SSP replay + OCB nonce reuse). The D4
  escrow blob must be `{key, seq-floor}` bumped strictly forward each
  attach; engine grows an initial-seq connect option + current-seq
  stat at M6. PLAN workstream E updated.
- **D7 recap**: client wasm components will be wac-composed (engine
  stays pure sync; Rust glue owns async recv/tick — B2 in PLAN;
  composed core is M4's native E2E vehicle; browser composed leg
  rides A3; JS orchestration is the recorded fallback). Composition
  mechanics proven sync-only (finding 11, `spikes/compose/`).
- mosh-go is a **vendored fork** at `.deps/mosh-go` (rev
  8dca5c67ec8e + patches; ledger in its `DEPS.md`): wasm build tags on
  `server.go`, `maxFragmentPayload` 1300→1100. Engine additionally
  sends `Resize` as the first user state (C server sends nothing until
  the client's first state — finding 8b).
- engine-go generated bindings are **committed**; `componentize-go
  bindings` rewrites go.mod (drops the replace directive), so
  regeneration is the explicit `just engine-bindings` recipe (it
  reapplies replace + pins). Don't re-run bindings casually.

## Pending / open

- **D7 follow-through**: B2 client-core glue (Rust) starts once #28's
  datagram surface exists (M3); composed async under jco is the
  unproven half — expect to exercise it at M5, file jco issues if new
  defects surface (PLAN risk 6). Control-channel-in-glue vs -in-JS:
  decide by M5.
- **Finding 9 (M3/M4 decision)**: stock C mosh-server emits datagrams
  up to 1252 B — over the ~1162 B iroh ceiling. M4 forwarder needs
  tunnel-layer sub-framing, or #28 grows path-dependent
  `max-datagram-size` (relay/WebRTC paths have no real 1200 B MTU).
- Finding 10 follow-ups, revisit when they bite: leg-b scroll artifact
  (`99` for `299`; mosh-go server vs our tracker unattributed — M2's
  xterm.js path showed no such artifact in its phases, weak signal
  toward the mosh-go server); mosh-go RTO clamp 10 s vs C mosh 1 s
  (patch candidate for M5 feel measurements); mosh-go predictor is
  not RTT-adaptive (predicts on every printable — finding 12; flicker
  patch candidate if netem shows it).
- Finding 13 (M6): escrow blob `{key, seq-floor}`; engine
  initial-seq connect option + current-seq stat.
- D4 sub-policy, decide during M6: runtime authenticator without `prf`
  ⇒ refuse persistence (lean) vs plaintext-with-warning.
- polymorph-iroh#10 (jco scheduler defect): gates the browser endpoint
  leg (M5) and browser-side ssh-in-engine (M7). Watch lann/jco#11 /
  polymorph-iroh PR #27. Everything before M5 is deliberately
  independent of it.
- Upstream issues filed, PRs to come from this experiment:
  polymorph-iroh#28 (datagram WIT surface — M3),
  polymorph-iroh#29 (injectable identity — M5). Branch in the sibling
  `../polymorph-iroh` checkout; follow its AGENTS.md (issue-first, one
  decision per PR, conformance is the gate).
- Upstream courtesy when convenient: offer mosh-go the wasip build-tag
  patch (and later fragment-size/RTO learnings) as issues/PRs.

## Next: M3 — polymorph-iroh datagram surface (#28), native legs

Upstream work in the sibling `../polymorph-iroh` checkout, per its
AGENTS.md: issue-first (#28 already filed), one decision per PR,
conformance is the gate. Design per PLAN A1: `max-datagram-size` /
`send-datagram` (sync, drop-on-full) / `recv-datagram` (async) on
`connection`; pump plumbing for `DatagramReceived` /
`DatagramsUnblocked` in both endpoint impls; native legs green (the
jco leg rides #10/A3 and is explicitly out of scope for the PR gate).

Feed in the M1/M2 findings where the surface design touches them:

1. Finding 9: stock mosh-server emits up to 1252 B datagrams — either
   `max-datagram-size` must be honest per-path (relay websocket and
   WebRTC data channels have no physical 1200 B MTU) or the M4
   forwarder sub-frames; raise on the issue before implementing.
2. After the PR: start B2 client-core glue against the new surface
   (compose with the engine; native wasmtime leg first — that
   composition is M4's E2E vehicle).

Then: M4 proxy (+ composed-core native E2E over iroh) → M5 (#29 +
browser client proper; A3-gated) → M6 passkeys (escrow `{key,
seq-floor}`, finding 13; engine grows initial-seq option) → M7 inner
ssh. Milestone table in README.

## Environment

- Tools: componentize-go 0.4.1 (`go install`; native binary cached in
  `~/.cache/componentize-go`), host Go 1.26.5 at `~/.local/go/bin` (not
  on default PATH — setup.sh and just recipes prefix it), patched
  `go1.25.5-wasi-on-idle-v2` auto-downloaded for async builds, wasmtime
  47.0.1, wasm-tools 1.247.0, wac 0.10.1, node 24.18.0, just 1.54.0.
- M1 adds: stock mosh-server 1.4.0 at `/usr/bin/mosh-server` (setup.sh
  now checks); mosh-go vendored at `.deps/mosh-go`; vt-go v0.1.0.
- D7 spike adds: Rust 1.96.0 + `wasm32-wasip2` target (setup.sh adds
  the target if rustup is present), wit-bindgen 0.59, wac 0.10.1.
- M2 adds: `@xterm/xterm` 5.5 + `@xterm/addon-fit` (web/), `ws` +
  `playwright-core` (host-test).
- jco: lann/jco fork @ 30186b2, consumed from
  `../polymorph-iroh/.deps/jco/packages/jco-transpile` as a `file:` dep
  of `spikes/componentize-go/runner` and `host-test`.
- Browser legs: playwright-core + `chrome.mjs` findChrome (playwright
  cache Chromium 151 at `~/.cache/ms-playwright/chromium-1234`;
  `CHROME_PATH` overrides).
- gh authed as `lann`; ADMIN on polymorph-components/* and
  lann/lann.github.io.
- This repo: local-only by decision (D-repo); rename before publishing.

## Entry points

- `just m2` — browser smoke gate; `just web-serve` — manual browser
  mosh (URL printed; one shell per tab; `?delay=150` for prediction).
- `just m1` — engine build + wasmtime smoke + both conformance legs.
- `just spikes` — every spike leg (M0 sync/async + D7 compose), gate
  order.
- `just engine-bindings` — regenerate bindings after `wit/mosh.wit`
  changes (rewrites go.mod deliberately; commit the result).
- `scripts/setup.sh` — idempotent toolchain setup.
- `host-test/run-conformance.mjs` — the conformance driver (`--server
  c|go`); `host-test/browser-smoke.mjs` — M2 bridge + gate;
  `host-test/mosh-servers.mjs` — shared server launcher;
  `host-test/moshgo-server/` — leg-b server wrapper.
- `web/app.mjs` — the browser client pump (engine drive contract).
- `engine-go/export_experiment_mosh_engine/{engine,tracker}.go` — the
  handwritten engine (tracker cribbed from mosh-go `cmd/mosh-wasm`).
- `web/prf-probe/` — M0 capability probe (deployed copy at
  https://lann.github.io/prf-probe/).
