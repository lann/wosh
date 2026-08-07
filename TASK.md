# Task state

Point-in-time working state for resuming this effort. The full plan is
`PLAN.md`; the design record and findings live in `README.md`; this
file says where work stopped and what comes next. Update it at the end
of each session.

## Status: M0 complete, D4 + D5 gates resolved, M1 next

- M0 committed at `4003320`; this session adds probe hardening, the D4
  resolution, and this file.
- All six spike legs pass: `just spikes` (wasmtime / jco-node /
  jco-browser × sync / async, bounded expectations encoded in the
  runners).
- **D5 gate PASSED**: componentize-go viable for the engine (findings
  1–5). No TinyGo fallback needed.
- **D4 resolved (finding 6)**: PRF probe passed on Firefox mobile
  Nightly (private window) ⇒ mosh key at rest is PRF-wrapped,
  ciphertext escrowed on the proxy. Probe stays deployed at
  https://lann.github.io/prf-probe/ (repo lann/lann.github.io,
  `prf-probe/` subdir).

## Pending / open

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

## Next: M1 — engine + native conformance harness

1. `wit/mosh.wit`: `experiment:mosh` engine world — sync sans-I/O
   `session` resource (constructor with key+cols+rows, `feed-keys`,
   `resize`, `handle-datagram`, `tick -> list<datagram>`,
   `drain-output -> list<u8>`, `stats`). No imports beyond the wasi 0.2
   baseline componentize-go adds itself.
2. `engine-go/`: wrap mosh-go `DialConnRaw` with an in-memory `Conn`
   (Write → outbox drained by tick; Read → inbox pop or immediate
   timeout error; `RecvRaw(0)` after each `handle-datagram`). Dep
   `github.com/unixshells/mosh-go`, rev-pinned. Crib output/prediction
   handling from its `cmd/mosh-wasm/state.go`.
3. `host-test/`: wasmtime harness (Rust or a node driver — node is less
   new code: jco-transpile the engine and bridge UDP from node) driving
   the engine against (a) stock C `mosh-server`, (b) mosh-go
   `mosh-server`. Assert keystroke echo and screen bytes; verify
   outbound datagram size ≤ ~1162 (expect ~500).
4. Append findings; gate = wire compatibility with C mosh-server.

Then: M2 browser smoke (throwaway ws-datagram bridge) → M3 (#28 PR) →
M4 proxy → M5 (#29 PR + browser E2E over iroh) → M6 passkeys (PRF arm)
→ M7 inner ssh. Milestone table in README.

## Environment

- Tools: componentize-go 0.4.1 (`go install`; native binary cached in
  `~/.cache/componentize-go`), host Go 1.26.5 at `~/.local/go/bin` (not
  on default PATH — setup.sh and just recipes prefix it), patched
  `go1.25.5-wasi-on-idle-v2` auto-downloaded for async builds, wasmtime
  47.0.1, wasm-tools 1.247.0, wac 0.10.1, node 24.18.0, just 1.54.0.
- jco: lann/jco fork @ 30186b2, consumed from
  `../polymorph-iroh/.deps/jco/packages/jco-transpile` as a `file:` dep
  of `spikes/componentize-go/runner`.
- Browser legs: playwright-core + `chrome.mjs` findChrome (playwright
  cache Chromium 151 at `~/.cache/ms-playwright/chromium-1234`;
  `CHROME_PATH` overrides).
- gh authed as `lann`; ADMIN on polymorph-components/* and
  lann/lann.github.io.
- This repo: local-only by decision (D-repo); rename before publishing.

## Entry points

- `just spikes` — every spike leg, gate order.
- `scripts/setup.sh` — idempotent toolchain setup.
- `spikes/componentize-go/{sync,async}` — probe components;
  `runner/` — jco transpile config + node/browser drivers.
- `web/prf-probe/` — capability probe (source of truth for the
  deployed copy).
