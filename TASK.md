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

## Status: M4 IN PROGRESS (~60%), checkpointed mid-implementation

Commit history: M0 `4003320`..`59d9b8f`; M1 `fe86742`; D7 `1929ae2`;
M2 `601f799`; upstream eval `fda916b`; M3 `a20c531`. Everything after
`a20c531` is uncommitted work-in-progress described here.

### M4 decisions already made (record in README decision log at commit)

- **D8: control channel lives in the client-core glue**, not the
  embedder. Proxy (native Rust) and glue (wasm Rust) share CBOR
  message types + tunnel framing via the new `proto/` crate
  (ciborium/serde both sides). JS/M5 stays thin; native E2E is
  one-call; M6 WebAuthn ceremonies will surface as driver-level
  events/exports later.
- Connection ALPN `experiment-mosh/0` covers both the control stream
  and the datagram tunnel (PLAN's separate ctl ALPN was a
  conflation — ALPN is per-connection; the control channel is simply
  the **first client-opened bi stream**).
- v0 session model: one mosh session per connection; control EOF or
  connection close ⇒ kill the session (no persistence until M6).
- **Tunnel framing (finding 9)**: every datagram gets a 1-byte header
  (0x00 whole; 0x01/0x02 = first/second fragment + 1-byte id).
  2-fragment limit (covers ≤ 2×1160 B; stock server max ~1252 B).
  Client→proxy never fragments (engine ≤1138+1 ≤ 1162). Reassembly:
  glue-side `Defragmenter` (and proxy-side for symmetry); loss of
  either half drops the datagram — SSP retransmission owns recovery.
- Connstring format v0: `1.<endpoint-id-hex>.<pairing-token>.<relay-url>`
  (dot-separated, splitn(4); relay URL is last so its dots don't
  matter). QR encodes `<qr-base><connstring>`, default qr-base is a
  placeholder until M5 has a real origin.
- TOFU: known peers (hex id in `<state-dir>/known_clients`) pass
  silently; unknown + valid token ⇒ operator y/N prompt (`--yes`
  auto-accepts for harnesses); unknown + bad token ⇒ silent drop.
- Proxy embeds the **endpoint component** under wasmtime (D1), driven
  host-side via bindgen of the `iroh-endpoint` world — first
  host-side resource juggling (M3's harness kept iroh native).

### Done and verified (uncommitted)

- `proto/` crate: control messages (Hello/HelloAck, NewSession/
  SessionReady, Error), u32-LE length-prefixed CBOR encode/decode,
  frame()/Defragmenter. **4 unit tests green** (`cargo test --lib`).
- `client-core/` reworked and **builds green** (322 KB):
  - `client.client-session.connect-proxy(relay, peer-hex, direct?,
    token, cols, rows)` — dial + control handshake + framed pumps.
  - `client.client-session.dial(…key…)` — raw datagrams, unchanged
    contract for the M3 harness.
  - `embed.attach-proxy(conn, token, cols, rows)` — replaces the old
    key-taking attach (key now always arrives via control).
  - Control stream halves held in `Inner` for the session lifetime
    (dropping them would read as detach to the proxy).

### In flight (NOT yet compiling / unfinished)

- `proxy/` crate: `Cargo.toml` done; `src/main.rs` is a **first
  draft, never compiled**. Expect bindgen-name and borrow iteration
  (exported-resource accessor types, `handle_conn` closure borrows,
  `futures::select!` shape). KNOWN BROKEN by design: the
  `PROMPT_AUTO`/`KNOWN_ADD` thread_locals are unwired placeholder
  hacks — replace with plain parameters/state threaded through
  `serve_connection` (e.g. pass `yes: bool` down; return
  "newly-accepted peer" so the caller adds to `KnownClients` — avoid
  the thread_local entirely).
- `host-test/proxy-e2e/`: directory exists, crate not written. Plan:
  crib composed-e2e (Ctx/linker/relay/MoshServer helpers), spawn the
  proxy binary (`--yes --no-qr --token test123 --relay …`), parse
  `connstring:`/`direct-addr:` from its stdout, then drive the
  composed client via `connect-proxy`; assertions = M1 suite +
  **bulk phase** (`seq 1 500` at 100 cols) which stalls unless
  proxy→client sub-framing works (oversized datagrams otherwise fail
  send-datagram); also grep proxy stdout for `fragmented=` > 0.
- `client-core/composed-client.wasm` on disk is STALE (pre-rework):
  re-run `just compose-client`, then **re-verify `just m3`** (dial
  path unchanged, must stay green).
- justfile: add `proxy-build`, `m4` recipes; keep `m3` intact.
- Docs at M4 commit: README decision log D8 + finding 16 (proxy +
  E2E results incl. fragmented counts), milestone row M4, PLAN
  workstream C status, this file.

### M4 remaining steps, in order

1. Fix + compile `proxy/` (drop thread_locals; wire `--yes`;
   known_clients add on accept).
2. `just compose-client && just m3` — M3 regression after glue rework.
3. Write `host-test/proxy-e2e/` + `m4` recipe; gate green.
4. Docs + commit ("M4: proxy …").

## Then: M5 — browser client (A3-gated browser leg)

Unblocked parts to build: connection-string parse (fragment + manual
entry + qr-scanner later), localStorage schema `{v, proxies[],
identityRef, sessions[]}`, IndexedDB CryptoKey persistence module
(structured-clone non-extractable keys; testable headless without
iroh), web/ UI wiring. The **browser endpoint leg stays blocked on
A3** (polymorph-iroh#10 / lann/jco#11, re-verified in finding 14) —
record a finding + STOP the browser-E2E leg there; do NOT fake it
over the ws bridge. netem measurements move to the native composed
client (still real mosh-over-iroh, loopback netem) as a partial
substitute; browser feel measurements wait for A3.

## Then: M6 — passkeys (buildable, integration partially A3-gated)

- Proxy: webauthn-rs RP over the control channel (new proto messages:
  RegisterStart/Finish, AuthStart/Finish, MakePersistent,
  Reattach{session-id}); escrow store `{credential-id, prf-salt, iv,
  ciphertext}` per session (tagged variant per D4, `plain` arm kept).
- Client: PRF wrap/unwrap module in JS (webauthn stays in JS per D7;
  ceremonies surfaced… glue exports control-event polling or the
  ceremony rides a JS-visible surface — design when there).
- **Reattach needs finding 13**: engine grows `connect` option
  `initial-seq: u64` + `current-seq` stat (WIT change ⇒
  `just engine-bindings` dance); escrow blob = `{key, seq-floor}`;
  proxy keeps mosh-server alive on detach when a passkey binding
  exists, kills otherwise.
- Testing without A3: native control-channel driver exercises the RP
  + escrow flow with a FAKE authenticator (webauthn-rs has test
  vectors? else store/verify plumbing tested + PRF wrap unit-tested);
  browser-side PRF module tested in Chromium via CDP virtual
  authenticator (hmac-secret/prf support — verify; finding either
  way). Full browser↔proxy ceremony E2E waits on A3.

## Then: M7 — inner ssh (native leg; browser leg A3-blocked)

- Proxy: stream-forward pinned to `127.0.0.1:22` (new control message
  or dedicated uni/bi stream tagging; simplest: client opens a second
  bi stream with a first-byte tag `S`=ssh-forward — decide there).
  Proxy deprivileges in this mode (no mosh-server spawn, no key
  handling; D2 interim becomes "personal mode" flag `--personal`).
- Engine: ssh mode — golang.org/x/crypto/ssh over an imported
  stream. Findings 2–4 constrain: goroutines over CM async work on
  wasmtime; Go-native timers TRAP in async exports (audit/shim
  x/crypto/ssh `time.After` uses — keepalive/timeouts; likely shim
  via wait-for helper goroutine or strip); jco async-lower still
  broken ⇒ browser ssh waits on A3 (record, stop).
- Native gate: composed client → proxy(personal-off) → sshd?
  Requires a local sshd + credentials — use `password` auth against
  a TEST sshd spawned by the harness (sshd -D on high port with
  test user? needs root… alternative: dropbear? Or an in-harness
  ssh SERVER (russh server side) as the sshd stand-in — decide
  there; the gate is engine-side ssh-in-component correctness, the
  peer can be a russh test server).
- MOSH CONNECT parse in-component; then SSP over datagrams as today.

## Pending / open (carried)

- Finding 10 follow-ups (leg-b scroll artifact; RTO clamp 10 s vs 1 s;
  predictor not RTT-adaptive) — revisit if M5-substitute netem
  measurements show impact.
- Finding 13 (M6): implemented as part of M6 above.
- D4 sub-policy (M6): authenticator without `prf` ⇒ refuse
  persistence (lean) vs plaintext-with-warning — decide during M6;
  leaning refuse-persistence with the `plain` schema arm kept for
  emergencies.
- polymorph-iroh#10 / lann/jco#11 still open: gates M5 browser E2E,
  M6 full ceremony E2E, M7 browser ssh. File minimal repros upstream
  if composed-async-under-jco shows NEW defect classes when
  eventually exercised.
- Upstream courtesies when convenient: mosh-go wasip build-tag patch;
  per-path datagram-ceiling issue on polymorph-iroh (file with M4
  fragmented-count data).
- Sibling `../polymorph-iroh` checkout on `port-noq` (old jco pin) —
  our jco transpiles ride it; don't touch its branches.

## Environment

- Tools: componentize-go 0.4.1, host Go 1.26.5 at `~/.local/go/bin`
  (PATH-prefixed by recipes), wasmtime 47.0.1, wasm-tools 1.247.0,
  wac 0.10.1, node 24.18.0, just 1.54.0, Rust 1.96 + wasm32-wasip2
  (+ 1.97 toolchain auto-installed by polymorph-iroh's
  rust-toolchain.toml where needed).
- `.deps/mosh-go` — committed vendored fork (patch ledger in its
  DEPS.md). `.deps/polymorph-iroh` — cloned+built by setup.sh at pin
  `bcaed0f2` (endpoint component, host shim crates, iroh-relay;
  relay needs `enable_metrics = false`).
- jco: lann/jco fork @ 30186b2 via `../polymorph-iroh/.deps/jco`
  (file: dep of spike runner + host-test).
- Browser legs: playwright-core + chrome.mjs findChrome (Chromium 151
  at `~/.cache/ms-playwright/chromium-1234`).
- mosh-server 1.4.0 at `/usr/bin/mosh-server`.
- This repo: local-only by decision (D-repo); rename before publishing.

## Entry points

- `just m3` — composed core vs upstream iroh + mosh-server (native);
  `just m2` / `just web-serve` — browser smoke / manual mosh;
  `just m1` — engine conformance legs; `just spikes` — all spike legs.
- `just engine-bindings` — regenerate engine bindings after
  `wit/mosh.wit` changes (rewrites go.mod deliberately; commit).
- `scripts/setup.sh` — idempotent toolchain + .deps setup.
- `proto/` — shared control/framing (unit tests).
- `client-core/` — the glue (`connect-proxy`/`dial`/`attach-proxy`).
- `proxy/` — the M4 proxy (WIP, see above).
- `host-test/composed-e2e/` — M3 harness; `host-test/proxy-e2e/` —
  M4 harness (to be written).
