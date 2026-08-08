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

## Status: M4 DONE (committed with this file); next M5

Commit history: M0 `4003320`..`59d9b8f`; M1 `fe86742`; D7 `1929ae2`;
M2 `601f799`; upstream eval `fda916b`; M3 `a20c531`; M4 WIP
checkpoints `4ededc6`, `e3215ba`, `0cc01a4`; M4 = the commit carrying
this file version.

### How M4 closed (context for anyone picking up from the checkpoints)

- The checkpoint-3 teardown bug (proxy never printed the
  per-connection summary after client detach) was the client's
  `detach` not awaiting `wait-closed` after `conn.close`: the harness
  stopped driving the store right after the export returned, so
  CONNECTION_CLOSE never hit the wire and the proxy sat on a pending
  `recv-datagram` until idle timeout. One-line fix in
  `client-core::detach` (`conn.wait_closed().await`); the proxy-side
  pump/join/wake-receiver teardown was correct as written. M3
  regression re-run green after the fix.
- Second (new) gate failure: `fragmented=0` — `seq 1 500` bulk is
  zlib-friendly, so no server datagram exceeded 1162 B and the
  sub-framing assertion had nothing to measure. The TASK/checkpoint-3
  claim that bulk "cannot arrive without fragmentation" was a wrong
  inference. The harness bulk phase now resizes to 220×50 and paints
  base64 noise (~8 KB compressed diffs ⇒ 6–7 oversized ~1252 B
  datagrams per run). Gate green: `just m4` (finding 16).
- Docs landed: D8 (control-in-glue) + D9 (proxy-core component,
  accessor-vs-store-context rationale) in the README decision log;
  finding 16; milestone rows; PLAN workstream C + control-channel
  section; justfile recipes `proxy-core-build`, `compose-proxy`,
  `proxy-build`, `m4`.

## Now: M5 — browser client (A3-gated browser leg)

Unblocked parts to build: connection-string parse (fragment + manual
entry), localStorage schema `{v, proxies[], identityRef, sessions[]}`,
IndexedDB CryptoKey persistence module (structured-clone
non-extractable keys; headless-testable without iroh), web/ UI wiring
for proxy entries. The **browser endpoint leg stays blocked on A3**
(polymorph-iroh#10 / lann/jco#11, re-verified finding 14) — record a
finding + stop that leg; do NOT fake it over the ws bridge. netem
measurements move to the native composed client (real mosh-over-iroh
under loopback netem) as a partial substitute.

## Then: M6 — passkeys (buildable; full ceremony E2E A3-gated)

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

- Finding 10 follow-ups (leg-b scroll artifact; RTO clamp 10 s —
  observed again in M4 runs after bulk, rto=8–10 s; predictor not
  RTT-adaptive) — revisit if netem shows impact.
- polymorph-iroh#10 / lann/jco#11 open: gates M5 browser E2E, M6
  ceremony E2E, M7 browser ssh. File minimal repros if new defect
  classes appear when composed-async-under-jco is exercised.
- Upstream courtesies: mosh-go wasip build-tag patch; per-path
  datagram-ceiling issue on polymorph-iroh — M4 fragmented data now
  exists (6–7 oversized per bulk screen), file when convenient.
- Sibling `../polymorph-iroh` on `port-noq` (old jco pin) — our jco
  transpiles ride it; don't touch.
- Stray processes to watch on this machine: an iroh-relay `--dev`
  from an older session listens on :3340/:9090 (cwd
  /tmp/opencode/polymorph-iroh — not this repo's). Harnesses use
  :3345 (m3) and :3347 (m4); no conflict. The user's own
  `mosh-server -p 0` (pid varies) is NOT ours; leave it.

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

- `just m4` — the M4 gate (client ↔ proxy ↔ mosh-server over iroh);
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
