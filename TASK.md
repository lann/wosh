# Task state

Point-in-time working state for resuming this effort. The full plan is
`PLAN.md`; the design record and findings live in `README.md`; this
file says where work stopped and what comes next. Update it at the end
of each session.

## Status: M3 complete (composed native gate passed), M4 next

- M0 `4003320`..`59d9b8f`; M1 `fe86742`; D7 `1929ae2`; M2 `601f799`;
  upstream evaluation `fda916b`. This session: M3 — client-core glue
  + composed native leg (finding 15).
- **M3 gate PASSED**: `just m3` — engine+glue+endpoint wac-composed
  (7.3 MB), under wasmtime CM-async, dialing an **upstream-iroh** peer
  (UDP direct + home relay) that forwards datagrams to a stock C
  mosh-server. Prompt/echo/resize/stats green; live
  `max-datagram-size` = **1162 B** (engine max 1138 B → 24 B
  headroom); composed-async proven on the wasmtime path (risk 6 is
  jco-only now).
- `client-core/`: `client` interface (dial + methods, engine-types
  only) and `embed.attach(connection, …)` split deliberately — native
  hosts bindgen `client` without resolving fused-away endpoint types;
  M5's jco path consumes `embed`. Driver surface is uniformly async
  (mixed sync/async exports generate two host calling conventions).
- `.deps/polymorph-iroh` cloned+built by setup.sh at the finding-14
  pin `bcaed0f2`; iroh-relay needs `enable_metrics = false`.
- Sibling checkout still on `port-noq` (old jco pin) — our transpiles
  ride it; unchanged, fine.
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

- **D7 follow-through**: composed-async is proven on wasmtime
  (finding 15); the jco half rides A3 and is exercised at M5 — file
  jco issues if new defects surface (PLAN risk 6).
  Control-channel-in-glue vs -in-JS: decide during M4 step 3 (the
  proxy's control channel forces the client side's hand).
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

## Next: M4 — the proxy

Workstream C. Gate: native E2E over iroh with the real proxy binary —
the composed client core (already proven, `just m3`) connecting
through the proxy to `mosh-server -i 127.0.0.1` it spawned.

1. `proxy/` Rust binary. Per **D1** it embeds wasmtime + the
   polymorph-iroh **endpoint component** (not the upstream iroh crate
   — the harness used upstream iroh deliberately, for interop; the
   proxy must exercise our own stack, and browsers reach the
   WebRTC-direct path only via polymorph signaling). The
   composed-e2e harness seeds the code: Ctx/linker/shims, relay
   config, accept loop, UDP pump. Host-side endpoint driving means
   bindgen against the `iroh-endpoint` world + host-side resource
   handling (new vs the harness, which kept iroh native).
2. Sessions: spawn `mosh-server -i 127.0.0.1` per session (interim
   mode/D2 — proxy runs as the target user), parse MOSH CONNECT, hand
   the key over the control channel.
3. Control channel: one bi stream per connection, ALPN
   `experiment-mosh/ctl/0`, versioned CBOR (ciborium): hello(pairing
   token), TOFU state, session new/list/attach/detach, key delivery.
   Client side: decide control-in-glue vs control-in-JS *now* — for
   the native leg the harness can drive either; the D7 sub-question
   (PLAN B2) says decide by M5.
4. Terminal UX: QR (unicode half-blocks) + connection string
   (version ‖ endpoint-id ‖ relay ref ‖ pairing token, base64url —
   exact format is an M5 concern, v0 can be plain fields); TOFU
   store (`known_clients`) + accept prompt; unknown-without-token
   silently rejected.
5. **Sub-framing** (finding 9): stock server datagrams up to 1252 B >
   1162 B ceiling — tunnel-layer fragmentation for oversized
   datagrams (both tunnel ends are ours: proxy forwarder ↔ client
   glue). Then file the per-path-ceiling issue upstream with data.
6. E2E: composed client (dial or attach) ↔ proxy ↔ mosh-server;
   M1-suite assertions + a large-screen-update phase that exercises
   sub-framing. Findings; update this file.

Then: M5 browser client (A3-gated; identity persistence, bootstrap,
composed-in-browser) → M6 passkeys (escrow `{key, seq-floor}`,
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

- `just m3` — composed client core vs upstream iroh + stock
  mosh-server (native gate); `just compose-client` — build+fuse.
- `just m2` — browser smoke gate; `just web-serve` — manual browser
  mosh (URL printed; one shell per tab; `?delay=150` for prediction).
- `just m1` — engine build + wasmtime smoke + both conformance legs.
- `just spikes` — every spike leg (M0 sync/async + D7 compose), gate
  order.
- `just engine-bindings` — regenerate bindings after `wit/mosh.wit`
  changes (rewrites go.mod deliberately; commit the result).
- `scripts/setup.sh` — idempotent toolchain setup (now also clones and
  builds `.deps/polymorph-iroh` at the pinned rev).
- `client-core/src/lib.rs` — the D7 glue; `client-core/wit/world.wit`
  — driver surface (`client` + `embed`).
- `host-test/composed-e2e/` — the M3 harness (M4 proxy seed);
  `host-test/run-conformance.mjs` — M1 driver;
  `host-test/browser-smoke.mjs` — M2 bridge + gate.
- `web/app.mjs` — the browser client pump (engine drive contract).
- `engine-go/export_experiment_mosh_engine/{engine,tracker}.go` — the
  handwritten engine (tracker cribbed from mosh-go `cmd/mosh-wasm`).
- `web/prf-probe/` — M0 capability probe (deployed copy at
  https://lann.github.io/prf-probe/).
