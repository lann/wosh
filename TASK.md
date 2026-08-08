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

## Status: M4 IN PROGRESS (~95%) — gate runs end-to-end, one teardown bug left

Commit history: M0 `4003320`..`59d9b8f`; M1 `fe86742`; D7 `1929ae2`;
M2 `601f799`; upstream eval `fda916b`; M3 `a20c531`; M4 WIP
checkpoints `4ededc6`, `e3215ba`. Uncommitted since: proxy `--shell`
flag, `host-test/proxy-e2e/` harness, M3 regression re-run.

### Fresh results (this checkpoint)

- **M3 regression green** after the D8 glue rework
  (`just compose-client && just m3`).
- **proxy-e2e runs the whole gate except the final assertion**
  (`/tmp/opencode/m4-run.log`): relay + proxy up; connstring parsed;
  **wrong pairing token refused** (negative path, proxy logs `peer
  refused`, stays up); real session: TOFU `--yes` accept → mosh-server
  spawned → control channel + key delivery OK → max-datagram-size
  1162 → prompt/echo/resize OK → **bulk over the sub-framed tunnel
  OK** (`seq 1 500` at 100 cols arrived complete — impossible without
  proxy-side fragmentation of >1162 B server datagrams) → stats OK →
  detach.
- **Remaining failure**: after client detach, the proxy never prints
  the per-connection summary line (`… session closed (fragmented=N
  …)`) within the harness's 5 s wait ⇒ `Error: proxy never logged a
  session summary`, rc=1.

### The teardown bug (next thing to fix)

`proxy-core::serve_connection` ends when BOTH pumps end
(`futures::join`), then calls `host::end_session` + logs the summary.
After client `detach` (client-side `conn.close`):

- inbound pump should exit via `recv_datagram` → Err on peer close;
- outbound pump should exit via `alive=false` + `wake_receiver()`
  (zero-length self-datagram; empty payload hits `continue` → `while
  alive.get()` re-check → exit).

One of these is not completing (or close propagation to a pending
`recv-datagram` in the endpoint impl is slower than 5 s). Debug plan:
temporary `host::log` at each pump exit to localize; manual
proxy+connect/detach run to see if the summary appears late;
lengthen the harness wait if it's mere latency; check whether the
client-side `conn.close` actually emits CONNECTION_CLOSE promptly
(client-core detach also stops its own pumps — its endpoint may need
a beat to flush; consider `wait-closed` before harness teardown).
Also note `MoshSession`/proxy `--shell` fix already landed: the proxy
spawns the user's shell by default (correct product behavior; the
first e2e run failed because a starship prompt contains no `$`) and
tests pass `--shell "bash --noprofile --norc -i"`.

**Orphan watch**: the failed run kill_on_drop'ed the proxy, so
`end_session`/Ctx::drop never reaped mosh-server on udp:60002 —
check `pgrep -a mosh-server` for `-i 127.0.0.1` instances before the
next run (the user's own `-p 0` server is NOT ours; leave it).

### M4 remaining steps

1. Fix teardown → summary logged; rerun `cargo run --release` in
   `host-test/proxy-e2e` (expect `fragmented ≥ 1`, gate OK).
2. justfile: `proxy-core-build`, `compose-proxy`, `proxy-build`, `m4`.
3. Docs: README decision log **D8** (control-in-glue) + **D9**
   (proxy-core component; accessor-vs-store-context rationale) +
   finding 16 (M4 gate numbers incl. fragmented count, negative-path
   token test, `--shell` note); milestone row M4; PLAN workstream C.
4. Commit M4; then proceed M5 → M6 → M7 per the standing instruction
   (their plans are unchanged below).

### M4 decisions (record in README decision log at commit)

- **D8: control channel lives in the client-core glue** (see
  checkpoint-1 notes below — unchanged, implemented, glue builds).
- **D9 (new since checkpoint 1): the proxy brain is a component.**
  `proxy-core/` (Rust wasm) owns the accept loop, control channel,
  datagram pumps + sub-framing, and mosh-server UDP I/O (via
  `wasi:sockets` UDP — `UdpWire` cribbed from polymorph-iroh's
  endpoint, incl. the wake-receiver teardown trick); it is wac-fused
  with the endpoint component into `proxy/composed-proxy.wasm`. The
  native `proxy/` binary is a thin shell providing exactly four host
  imports — `authorize` (TOFU policy+prompt+persistence),
  `new-session` (spawn `mosh-server -i 127.0.0.1`), `end-session`
  (reap), `log` — plus bootstrap UX (connstring + QR). WHY: driving
  the endpoint world's mixed sync/async exports host-side hits the
  bindgen accessor-vs-store-context wall (sync exports generate
  store-context calls, unusable interleaved with accessor calls in
  one run_concurrent); guest-internal driving is the proven pattern
  (their demo, our client-core). Bonus: both tunnel ends are now
  components.
- ALPN `experiment-mosh/0`; control = first client bi stream; one
  session per connection (v0); connstring
  `1.<endpoint-id-hex>.<token>.<relay-url>`; tunnel framing 0x00
  whole / 0x01+0x02 two-fragment split (finding 9); TOFU as before.

### Done and verified since checkpoint 1 (uncommitted)

- `proxy-core/` **builds green** (302 KB): start(relay) →
  {endpoint-id-hex, direct-addr}, spawn_local accept loop; per-conn
  control handshake → host authorize → session via host → framed
  pumps → end-session + summary log incl. `fragmented=` count.
- `wac plug proxy-core + endpoint → proxy/composed-proxy.wasm`:
  imports = our `host` + shim family; exports = `proxy` ✓.
- `proxy/` native shell **rewritten from scratch** (checkpoint-1
  draft discarded) and **builds + smoke-passes**: with a relay on
  :3346 it prints `connstring: 1.<id>.t3sttok3n.http://127.0.0.1:3346`,
  `direct-addr`, `ready`. Learned wasmtime-47 bindgen import
  conventions (worth keeping): async WIT imports ⇒
  `HostWithStore<T>` associated fns taking
  `&Accessor<Ctx, Self>` with state via `accessor.with(|mut a|
  a.get()…)`; sync WIT imports ⇒ still `async fn` but taking
  `Access<'_, Ctx, Self>` directly; plus an empty `impl Host for
  &mut Ctx`; wire with
  `bindings::ComposedProxy::add_to_linker::<Ctx, Ctx>(&mut linker,
  |ctx| ctx)`.

## Then: M5 — browser client (A3-gated browser leg)

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
  ceremonies transit proxy-core (component) → surface to the native
  shell via new host imports, or webauthn-rs runs… native-side is
  where webauthn-rs lives — host import `webauthn(step-blob) ->
  blob` keeps proxy-core protocol-only.
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

- Finding 10 follow-ups (leg-b scroll artifact; RTO clamp 10 s;
  predictor not RTT-adaptive) — revisit if netem shows impact.
- polymorph-iroh#10 / lann/jco#11 open: gates M5 browser E2E, M6
  ceremony E2E, M7 browser ssh. File minimal repros if new defect
  classes appear when composed-async-under-jco is exercised.
- Upstream courtesies: mosh-go wasip build-tag patch; per-path
  datagram-ceiling issue on polymorph-iroh (file with M4 fragmented
  data).
- Sibling `../polymorph-iroh` on `port-noq` (old jco pin) — our jco
  transpiles ride it; don't touch.
- Stray processes to watch on this machine: an iroh-relay from the
  M4 smoke test may still listen on :3346; kill before/ignore in
  e2e (use another port).

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

- `just m3` — composed core vs upstream iroh + mosh-server (native);
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
  M4 harness (empty dir, next step).
