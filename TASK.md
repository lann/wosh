# Task state

Point-in-time working state for resuming this effort. The full plan is
`PLAN.md`; the design record and findings live in `README.md`; this
file says where work stopped and what comes next. Update it at the end
of each session.

## Status: M1 complete (wire-compat gate passed), D7 composition ruling revised, M2 next

- M0 at `4003320`..`59d9b8f` (spikes, PRF probe, plan). This session:
  M1 — engine WIT + Go implementation + conformance harness — then D7.
- **M1 gate PASSED** (findings 7–10): `just m1` — wasmtime version
  smoke, then the jco-transpiled engine driven from node over loopback
  UDP against (a) stock C mosh-server 1.4.0 and (b) mosh-go's server.
  Echo, resize, 4 KB multi-fragment paste, server bulk, stats, size
  bound (ours ≤ 1138 B) all green on both legs.
- **D7 (revised)**: client wasm components will be **wac-composed**
  into one client core (owner preference: advance the component
  model). Engine stays pure sync; a Rust glue component will own async
  recv/tick (B2 in PLAN); composed core becomes M4's native E2E
  vehicle; browser composed leg rides A3 with JS orchestration as the
  recorded fallback. **Finding 11**: composition mechanics (sync Rust
  adapter + engine via `wac plug`) green under wasmtime, jco/node,
  jco/browser — `spikes/compose/`, `just spike-compose-*`.
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
  (`99` for `299`; mosh-go server vs our tracker unattributed — M2
  xterm.js adds signal); mosh-go RTO clamp 10 s vs C mosh 1 s (RTO
  observed pinned at 10 s after bulk; patch candidate for M2/M5 feel
  measurements).
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

## Next: M2 — browser mosh (no iroh yet)

Gate: the engine runs under jco in a real browser, driving xterm.js.
Composition is deliberately not required for this gate (D7): the page
drives the engine's sync surface directly, same as the conformance
harness; the composed client core enters at M3/M4 (glue) and M5
(browser).

1. Throwaway ws↔UDP datagram bridge in node (each ws binary message =
   one datagram, no framing beyond that; spawn mosh-server like the
   conformance driver does — reuse its startServer).
2. `web/` static page: xterm.js + browser-transpiled engine
   (preview2-shim `dist/browser` worked in M0 finding 1), ws datagram
   pump, 8 ms tick, rAF-coalesced terminal writes; keystrokes from
   xterm.js `onData` → `feed-keys`; fit-addon resize → `resize`.
3. Browser leg of the harness via playwright-core findChrome (crib
   `spikes/componentize-go/runner/chrome.mjs` + `run-sync-browser.mjs`)
   asserting the same echo/resize markers through the page.
4. First prediction-feel observation on real keystrokes (predictor
   engages only under RTT; netem measurements are M5, not here).
5. Append findings; update this file.

Then: M3 (#28 datagram PR, native legs) → M4 proxy → M5 (#29 + browser
E2E over iroh) → M6 passkeys → M7 inner ssh. Milestone table in README.

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

- `just m1` — engine build + wasmtime smoke + both conformance legs.
- `just spikes` — every spike leg (M0 sync/async + D7 compose), gate
  order.
- `just engine-bindings` — regenerate bindings after `wit/mosh.wit`
  changes (rewrites go.mod deliberately; commit the result).
- `scripts/setup.sh` — idempotent toolchain setup.
- `host-test/run-conformance.mjs` — the conformance driver (`--server
  c|go`); `host-test/moshgo-server/` — leg-b server wrapper.
- `engine-go/export_experiment_mosh_engine/{engine,tracker}.go` — the
  handwritten engine (tracker cribbed from mosh-go `cmd/mosh-wasm`).
- `web/prf-probe/` — M0 capability probe (deployed copy at
  https://lann.github.io/prf-probe/).
