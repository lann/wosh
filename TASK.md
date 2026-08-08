# Task state

Point-in-time working state for resuming this effort. The full plan is
`PLAN.md`; the design record and findings live in `README.md`; this
file says where work stopped and what comes next. Update it at the end
of each session.

## Status: M2 complete; upstream #28+#29 landed (evaluated suitable); M3 = B2 glue

- M0 `4003320`..`59d9b8f`; M1 `fe86742`; D7 `1929ae2`; M2 `601f799`.
  This session: upstream suitability evaluation (finding 14).
- **Upstream moved (2026-08-08)**: polymorph-iroh merged PR #30
  (datagram surface, closes #28) and PR #31 (identity resource,
  closes #29) — both evaluated **suitable as-is** (finding 14): the
  datagram WIT is exactly the planned B2 contract (sync send
  drop-oldest, async recv accept-family, ceiling ≈ 1156–1176 B ≥ our
  1138 B); identity constructors preserve the crypto split, browser
  persistence stays embedder-side. Our A1/A2 PR work evaporates; M3
  is now purely B2. Finding 9 was NOT addressed upstream (no comments
  on #28): M4 forwarder sub-frames; file a fresh per-path-ceiling
  issue when concrete.
- **jco repin evaluated**: upstream moved to dbad4d7d ("all-fixes");
  scratch-built it and re-ran our spikes — sync + composed-sync green
  on node/browser (forward-compat proven), componentize-go
  async-lower **still broken** (now hangs instead of throwing).
  #10 / lann/jco#11 still open ⇒ A3 still gates M5/M7 browser legs
  and composed-async. Runner deps restored to the sibling pin after
  the experiment.
- **Sibling checkout caveat**: `../polymorph-iroh` sits on branch
  `port-noq` (diverges from main, declares the old jco pin 30186b2 —
  which our transpiles ride via `.deps/jco`). B2 needs the endpoint
  from main: use a worktree (evaluation used
  `git worktree add /tmp/opencode/piroh-main origin/main` +
  `SKIP_NODE=1 scripts/setup.sh`; endpoint builds clean, 2.0 MB) or
  wait for the checkout to advance — don't move the user's branch.
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

- **D7 follow-through**: B2 client-core glue is now the active work
  (see Next). Composed async under jco is the unproven half — expect
  to exercise it at M5, file jco issues if new defects surface (PLAN
  risk 6; finding 14: async-lower still broken at dbad4d7d, hang
  variant). Control-channel-in-glue vs -in-JS: decide by M5.
- **Finding 9 (M4)**: stock C mosh-server emits datagrams up to
  1252 B — over the ~1156–1176 B iroh ceiling (finding 14 refines).
  Upstream did not address it (#28 closed without it being raised):
  M4 forwarder sub-frames at the tunnel layer; file a fresh upstream
  issue (per-path ceiling on relay/WebRTC paths) once the forwarder
  makes the need concrete.
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
  leg (M5) and browser-side ssh-in-engine (M7). Watch lann/jco#11;
  both still open as of 2026-08-08 (finding 14 — the dbad4d7d
  "all-fixes" pin did not clear our async-lower probe). Everything
  before M5 is deliberately independent of it.
- ~~Upstream issues #28/#29~~ **resolved upstream** (PRs #30/#31,
  finding 14) — no PRs to write from this experiment for A1/A2.
- Upstream courtesy when convenient: offer mosh-go the wasip build-tag
  patch (and later fragment-size/RTO learnings) as issues/PRs.

## Next: M3 — B2 client-core glue, composed native leg

The upstream surface is merged; M3 is entirely our side now (PLAN B2 +
milestone M3). Gate: engine+glue+endpoint wac-composed, talking mosh
over real iroh datagrams under wasmtime.

1. `client-core/` Rust component (wit-bindgen 0.59 + async feature,
   mirror upstream's guest conventions — see the exec-model guest in
   polymorph-iroh): imports `experiment:mosh/engine` and
   `polymorph:iroh/endpoint`; exports a driver interface
   (attach(connection, key, cols, rows), feed-keys, resize,
   drain-output, stats, detach). Owns the recv-datagram loop and the
   wait-for tick (~8 ms); forwards engine tick output via
   send-datagram (sync→sync, legal); logs `max-datagram-size` at
   attach (confirm ≥ 1138, finding 14).
2. wac-compose engine + glue + endpoint (their demo composes the same
   way: `wac plug`; multiple --plug args work). Native leg: wasmtime
   host cribbing polymorph-iroh's host-wasmtime endpoint-demo driver
   (webcrypto/websocket/sockets host shims), against a real
   mosh-server through a UDP↔datagram pump — effectively the M1
   conformance suite with iroh in the middle.
3. Endpoint source: build from polymorph-iroh main via worktree until
   the sibling checkout advances (see status caveat).
4. Findings; decide whether the M4 proxy consumes the same composed
   artifact (likely) before starting workstream C.

Then: M4 proxy (+ sub-framing for 1252 B server datagrams) → M5
browser client (A3-gated) → M6 passkeys (escrow `{key, seq-floor}`,
finding 13) → M7 inner ssh. Milestone table in README.

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
