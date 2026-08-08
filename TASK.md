# Task state

Point-in-time working state for resuming this effort. The full plan is
`PLAN.md`; the design record and findings live in `README.md`; this
file says where work stopped and what comes next. Update it at the end
of each session.

## Standing instruction (owner, 2026-08-08)

Owner is offline; instruction is to **complete the entire plan
autonomously** (M4 → M7), with A3-blocked browser legs documented
rather than waited on, and a summary of significant design decisions
at the end. Deliver findings-first; commit per milestone.

## Status: M5 DONE to its A3 boundary (committed with this file); next M6

Commit history: M0 `4003320`..`59d9b8f`; M1 `fe86742`; D7 `1929ae2`;
M2 `601f799`; upstream eval `fda916b`; M3 `a20c531`; M4 checkpoints
`4ededc6`, `e3215ba`, `0cc01a4`, M4 `308e304`; M5 = the commit
carrying this file version.

### How M5 closed

- Unblocked parts all built + gated (`just m5`): `web/connstring.mjs`
  / `storage.mjs` / `idb-keys.mjs` / `boot.mjs` + panel in
  `index.html`; node + headless-Chromium tests
  (`host-test/web-tests.mjs`). Ed25519 identity generated
  non-extractable, persists through IndexedDB across reloads,
  signs after retrieval (finding 17). The M2 bridge page stays green
  (`just m2`); a bridgeless static serve idles honestly.
- The A3-blocked leg was *probed*, not faked (`just m5-jco-probe`):
  composed client under jco/JSPI throws at instantiation — composed
  resource-class TDZ, a NEW defect class ahead of the known scheduler
  defects. Minimal repro built (`spikes/compose-async-tdz/`: async
  cross-component `own<resource>` return + the resource type
  re-exported in an exported interface; wasmtime-correct), filed as
  lann/jco#51 (finding 18). The probe classifies
  UNBLOCKED/THROWS/HANGS on each run — it is the unblock detector.
- Netem measurements ran natively over the M3 gate
  (`just m5-netem`, needs passwordless sudo): conformance green
  through delay 100 ms and 10% loss; per-phase timings recorded in
  finding 19. mosh-go's RTO clamp pins at 10 s in every
  non-baseline cell (finding 10b confirmed live) — candidate fork
  patch ([250 ms,10 s] → C mosh's [50 ms,1 s]) if M6/M7 feel it.
- jco-impl note: the webrtc shim needs `node-datachannel` for node
  runs — `npm install` in
  `.deps/polymorph-iroh/.deps/webrtc/jco-impl` (done here; setup.sh
  does not cover it yet).

## Then: M6 — passkeys (buildable; full ceremony E2E A3-gated)

*(This is now the NEXT milestone.)*

- Proxy side: webauthn-rs RP over the control channel (new proto
  messages RegisterStart/Finish, AuthStart/Finish, MakePersistent,
  Reattach{session-id}); escrow store `{credential-id, prf-salt, iv,
  ciphertext}` (tagged variant per D4, `plain` arm kept). Note D9:
  ceremonies transit proxy-core (component); webauthn-rs lives in the
  native shell — host import `webauthn(step-blob) -> blob` keeps
  proxy-core protocol-only.
- Client side: PRF eval + wrap/unwrap module in JS (WebAuthn stays
  in JS per D7); glue surfaces ceremony pass-through on the control
  channel via new driver exports (design when there).
- **Finding 13**: engine grows `initial-seq` connect option +
  `current-seq` stat (WIT change ⇒ `just engine-bindings` dance);
  escrow blob = `{key, seq-floor}`; proxy keeps mosh-server alive on
  detach iff passkey-bound, else kills (v0 behavior today).
- Testing without A3: native control-channel driver for RP+escrow
  flow; browser-side PRF module in Chromium via CDP virtual
  authenticator (verify hmac-secret/prf support; finding either
  way). Full browser↔proxy ceremony E2E waits on A3.
- D4 sub-policy decision due here: no-prf authenticator ⇒ refuse
  persistence (leaning) vs plaintext-with-warning; keep `plain`
  schema arm regardless.

## Then: M7 — inner ssh (native leg; browser leg A3-blocked)

- Proxy: stream-forward pinned to `127.0.0.1:22`; proxy-core gains a
  stream-forward path (client opens second bi stream, first-byte tag
  or a control message announcing it — decide there); `--personal`
  flag keeps interim key-delivery mode; without it the proxy never
  spawns mosh-server or sees keys (deprivileged posture, D2 end
  state).
- Engine: ssh mode — x/crypto/ssh over an imported stream; findings
  2–4 constrain (goroutines-over-CM-async OK on wasmtime; Go-native
  timers TRAP in async exports — audit/shim x/crypto/ssh timer use;
  jco async-lower broken ⇒ browser ssh waits on A3). Engine world
  grows an async variant; `MOSH CONNECT` parsed in-component.
- Native gate: composed client → proxy → sshd stand-in. sshd needs
  root/config; use a russh-based test server (password auth) as the
  sshd stand-in — the gate is ssh-in-component correctness.

## Pending / open (carried)

- Finding 10 follow-ups: leg-b scroll artifact; predictor not
  RTT-adaptive; **RTO clamp 10 s now measured live** (finding 19 —
  pinned in every netem cell with delay ≥ 40 ms) — fork patch to
  C mosh's [50 ms, 1 s] is justified if M6/M7 sessions stall on
  idle recovery.
- A3 upstream: polymorph-iroh#10 / lann/jco#11 open, **plus
  lann/jco#51** (composed-resource TDZ, ours, minimal repro in
  spikes/compose-async-tdz/) — #51 fires before the scheduler
  defects on the composed client. Gates M5 browser E2E, M6 ceremony
  E2E, M7 browser ssh. `just m5-jco-probe` = unblock detector.
- Upstream courtesies: mosh-go wasip build-tag patch; per-path
  datagram-ceiling issue on polymorph-iroh — M4 fragmented data now
  exists (6–7 oversized per bulk screen), file when convenient.
- setup.sh gap: `npm install` in
  `.deps/polymorph-iroh/.deps/webrtc/jco-impl` (node-datachannel)
  needed for `just m5-jco-probe`; done manually this session.
- Sibling `../polymorph-iroh` on `port-noq` (old jco pin) — our jco
  transpiles ride it; don't touch.
- Stray processes to watch on this machine: an iroh-relay `--dev`
  from an older session listens on :3340/:9090 (cwd
  /tmp/opencode/polymorph-iroh — not this repo's). Harnesses use
  :3345 (m3), :3347 (m4), :3348 (jco-probe); no conflict. The user's
  own `mosh-server -p 0` (pid varies) is NOT ours; leave it.

## Environment

- Tools: componentize-go 0.4.1, host Go 1.26.5 at `~/.local/go/bin`
  (PATH-prefixed by recipes), wasmtime 47.0.1 CLI / wasmtime crate
  47.0.3, wasm-tools 1.247.0, wac 0.10.1, node 24.18.0, just 1.54.0,
  Rust 1.96 + wasm32-wasip2 (1.97 auto via polymorph-iroh
  rust-toolchain.toml).
- `.deps/mosh-go` — committed vendored fork (ledger in DEPS.md).
  `.deps/polymorph-iroh` — cloned+built by setup.sh at pin
  `bcaed0f2` (endpoint component, shim crates, iroh-relay;
  `enable_metrics = false` required).
- jco: lann/jco fork @ 30186b2 via `../polymorph-iroh/.deps/jco`.
- Browser legs: playwright-core + chrome.mjs (Chromium 151).
- mosh-server 1.4.0 at `/usr/bin/mosh-server`.
- This repo: local-only by decision (D-repo); rename before
  publishing.

## Entry points

- `just m5` (web module gates) / `just m5-jco-probe` (A3 detector) /
  `just m5-netem` (loopback matrix; passwordless sudo);
  `just m4` — the M4 gate (client ↔ proxy ↔ mosh-server over iroh);
  `just m3` — composed core vs upstream iroh + mosh-server;
  `just m2` / `just web-serve`; `just m1`; `just spikes`.
- `just engine-bindings` — regenerate engine bindings after
  `wit/mosh.wit` changes (rewrites go.mod deliberately; commit).
- `scripts/setup.sh` — toolchain + .deps (idempotent).
- `proto/` — shared control/framing (unit tests: `cargo test --lib`).
- `client-core/` — the glue (`connect-proxy`/`dial`/`attach-proxy`).
- `proxy-core/` — the proxy brain component; `proxy/` — the native
  shell (smoke: relay + `experiment-mosh-proxy --relay
  http://127.0.0.1:<port> --token t --no-qr --yes`).
- `host-test/composed-e2e/` — M3 harness; `host-test/proxy-e2e/` —
  M4 harness (`cargo run --release`, or `just m4`).
