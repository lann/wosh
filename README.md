# wosh

A mosh-compatible client and proxy tunneled over iroh: a browser client
(xterm.js, JSPI, wasm components) speaking real mosh SSP end-to-end to a
stock `mosh-server`, through a native proxy that embeds the
[polymorph-iroh](https://github.com/polymorph-components/polymorph-iroh)
endpoint component.

**Status: deltic cutover complete — the browser leg is LIVE.** All
JS hosting moved from jco (AOT transpilation, node) to
[deltic](https://github.com/lann/deltic) (runtime linking, Deno +
browsers); the A3 blocker family is retired, and `just m5` now gates a
real in-browser mosh session (composed client in headless Chromium ↔
proxy over iroh). M0–M7 native milestones unchanged and green.
Every remaining browser leg has landed (findings 27–29): the WebRTC
upgrade, the M6 ceremony E2E, and the M7 inner-ssh E2E all run
in-page. Experiment-grade: no stability, delete-at-will.
CI (`.github/workflows/ci.yml`) runs the gate matrix (spikes,
m1–m7 including the browser legs; netem excluded) on PRs and main,
and the Pages deploy of the browser client only ships from a green
main run. The full plan lives in
[`PLAN.md`](PLAN.md); resumable session state in [`TASK.md`](TASK.md).

## Running the server

The browser client is deployed to <https://lann.github.io/wosh/> on
every green merge to `main` (the CI gates gate the deploy). The part
you run yourself is the proxy, on the
machine you want a shell on:

```sh
scripts/setup.sh     # toolchain + pinned deps (idempotent)
just proxy-personal  # build + run the proxy in personal mode
```

`proxy-personal` builds (`compose-proxy proxy-build`) and runs

```sh
proxy/target/release/wosh-proxy --relay https://use1-1.relay.n0.iroh.link \
  --rp-id lann.github.io --rp-origin https://lann.github.io \
  --personal   # spawns mosh-server as you on connect
```

— the home relay defaults to one of n0's public iroh relays (the same
ones stock iroh uses; `RELAY=<url>` selects another region or your own
relay), the QR base defaults to the Pages client, and extra
`just proxy-personal <flags>` pass through to `wosh-proxy`, later
flags winning.

The proxy prints a connection string and a QR code. Open the QR link
(or open the client and paste the connstring), then accept the pairing
prompt (TOFU) in the proxy's terminal — or pass `--yes`. Without
`--personal` the proxy runs deprivileged: it spawns nothing and only
forwards an inner ssh stream to `--ssh-target` (default
`127.0.0.1:22`); the client authenticates end-to-end over ssh and
boots its own `mosh-server` (M7).

The browser reaches the proxy through the same relay URL the
connstring carries, so the relay must be reachable from the browser
too — the public relays are. If `RELAY` points at your own plain-http
relay (as the e2e gates spawn on loopback), a secure page can only
open `ws:` to loopback: anything non-local needs `wss:`/TLS, or serve
the client tree next to it (`scripts/web-deploy-tree.sh <dir>` + any
static file server) instead of the Pages build.

## Architecture

Layering: mosh SSP (AES-OCB, end-to-end browser↔mosh-server) over QUIC
datagrams on the iroh connection; ssh (end-to-end browser↔sshd) joins in
workstream F. The iroh layer is network access control; the inner
ssh/mosh layer is the strong security boundary.

- The client's wasm pieces are wac-composed into one **client core**
  (D7): the mosh engine (Go, componentize-go) stays a pure sync
  sans-I/O `session` resource wrapping mosh-go `DialConnRaw` (no
  goroutines, no timers); a small Rust glue component owns the async
  parts (datagram recv loop, `wait-for` tick) and exports the driver
  surface JS talks to; the polymorph-iroh endpoint completes the
  composition. On JS hosts the composed artifact is runtime-linked by
  deltic (no transpile step); JS-orchestrating the components
  separately remains a cheap fallback (the engine surface is the same
  either way).
- Control channel: the first client-opened bi stream on the
  connection (ALPN `wosh/0`), length-prefixed CBOR, spoken
  by the client-core glue and the proxy-core component through the
  shared `proto/` crate (D8). Pairing token in the QR/connection
  string; unknown peers without a valid token are silently rejected;
  with one, both sides display both endpoint pubkeys and the proxy
  operator accepts manually (TOFU).
- Bootstrap QR encodes `https://<site>/#<connstring>`; the same string
  is scannable in-browser (qr-scanner) or typed manually.
- v0 sessions: one attached session per connection. Detach without a
  passkey kills the session; with one, the session persists and
  reattach requires a user-presence WebAuthn assertion.

## Decision log

- **D1** Proxy embeds wasmtime + the polymorph-iroh endpoint component
  (not the upstream iroh crate): browsers reach the unreliable direct
  path only via polymorph's WebRTC signaling.
- **D2** Interim auth mode first — proxy (as the target user) spawns
  `mosh-server -i 127.0.0.1` and hands the key over the TOFU-gated
  control channel. Inner ssh (browser→sshd through a forwarded stream)
  becomes the default posture later; interim survives as a "personal
  mode". Rationale: with inner ssh the proxy drops out of the
  authentication TCB and runs unprivileged. *(Realized in M7, finding
  23: deprivileged is the default, `--personal` is the opt-in.)*
- **D3** Upstream-first: the two polymorph-iroh gaps (QUIC datagram WIT
  surface, stable/injectable endpoint identity) are issues+PRs against
  polymorph-iroh, per its conventions (both fall under its issue #3).
- **D4** *(resolved 2026-08-07, finding 6; sub-policy resolved
  2026-08-08, M6)* Mosh key at rest: the M0 PRF probe **passed** on
  Firefox mobile Nightly ⇒ PRF-wrapped key, ciphertext escrowed on the
  proxy; the proxy never sees the plaintext key. Storage schema stays a
  tagged variant (`plain` arm kept for emergencies); `mosh-server`
  binds loopback regardless. Sub-policy (M6): an authenticator without
  `prf` ⇒ **refuse persistence** (the lean arm) — the alternative is
  the mosh key sitting in plaintext on the proxy, which is what the PRF
  arm exists to prevent. The guard lives in code
  (`web/prf-wrap.mjs assertPersistencePermitted`, tested); the `plain`
  schema arm survives for tests and emergencies (the native M6 gate
  exercises it deliberately). Trust note (finding 21): everything
  outside `ct` in a proxy-returned escrow is attacker-controlled — the
  *sealed* `seqFloor` is authoritative at attach; a rolled-back floor
  would mean OCB nonce reuse under traffic the proxy has seen.
- **D5** Engine is big-Go (mosh-go) via componentize-go, sync sans-I/O
  exports. If the componentize-go spike fails the gate: stop and
  discuss — no automatic TinyGo fallback.
- **D6** Firefox mobile Nightly with the JSPI opt-in flag is an
  accepted target configuration.
- **D7** *(2026-08-07, revises the M0-era JS-orchestration ruling)*
  The client's wasm components are **wac-composed** into a single
  client-core component — advancing the component model is a standing
  secondary goal of the polymorph project, and the composed core runs
  headless under wasmtime for full-client conformance (M4). Shape:
  engine unchanged (pure sync, zero non-wasi imports) + a small Rust
  glue component holding the only async parts (recv loop, tick) +
  the endpoint. Composition mechanics validated sync-only the same day
  (finding 11); composed *async* under jco rode A3 exactly like the
  endpoint's browser leg *(resolved 2026-08-10: deltic runs composed
  async on every JS host — findings 24–25)*. Recorded fallback if
  composed-async stalls: JS orchestrates engine and endpoint
  separately — kept permanently cheap because the engine surface is
  identical in both shapes. WebAuthn, UI, storage, bootstrap, and (for
  now) the control channel stay in JS; moving the control channel into
  the glue is an open sub-question for M5 (resolved: D8).
- **D8** *(2026-08-08, M4; resolves D7's open sub-question)* The CBOR
  control channel lives in the **client-core glue**, not the embedder:
  the proxy (proxy-core) and the glue share message types and tunnel
  framing through the `proto/` crate (ciborium both sides), JS/M5
  stays thin, and the native E2E drives a session with one call
  (`connect-proxy`). M6 WebAuthn ceremonies will surface as
  driver-level exports rather than raw control frames. Consequences:
  the connection ALPN is plain `wosh/0` — the plan's
  separate `ctl` ALPN was a conflation (ALPN is per-connection); the
  control channel is simply the first client-opened bi stream.
- **D9** *(2026-08-08, M4)* The proxy brain is a **component**:
  `proxy-core` (Rust wasm) owns the accept loop, control channel,
  TOFU/authorization flow (policy decisions via a host import),
  datagram pumps with tunnel sub-framing (finding 9), and the
  mosh-server UDP leg over `wasi:sockets`; wac fuses it with the
  polymorph-iroh endpoint into `composed-proxy.wasm`. The native
  shell provides exactly four host imports — `authorize`,
  `new-session` (spawn `mosh-server -i 127.0.0.1`), `end-session`,
  `log` — plus bootstrap UX (connstring + QR). WHY: driving the
  endpoint world's mixed sync/async exports host-side hits wasmtime
  bindgen's accessor-vs-store-context wall (sync exports generate
  store-context calls that cannot interleave with accessor calls in
  one `run_concurrent`); guest-internal orchestration is the proven
  pattern (endpoint demo, client-core). Bonus: both tunnel ends are
  components, so the sub-framing code paths are symmetric.

## Layout

- `.deps/mosh-go/` — vendored mosh-go fork at the pinned rev, with the
  wasm build-tag and fragment-size patches (`DEPS.md` there is the
  patch ledger). Other `.deps/` entries — polymorph-iroh and deltic at
  the pins in `scripts/setup.sh` — are cloned by that script, not
  committed. deltic is the JS component host (runtime linker): the
  root `deno.json` maps `@deltic/*` and the polymorph deltic host
  modules into these checkouts, and setup builds deltic's translator
  shim (`just _translator` prints its path).
- `client-core/` — the D7/B2 glue component (Rust): async pumps
  between the sync engine and the endpoint; `composed-client.wasm` is
  the wac-fused artifact (engine+glue+endpoint).
- `spikes/componentize-go/` — M0 feasibility spikes (sync exports;
  async/goroutine abstraction probes).
- `spikes/compose/` — D7 composition spike: sync Rust adapter
  wac-plugged with the engine; wasmtime/deltic legs
  (`just spike-compose-wasmtime spike-compose-deltic`).
  `spikes/compose-async-tdz/` — the minimal repro for lann/jco#51
  (finding 18; historical — the defect class cannot exist in a
  runtime linker).
- `web/prf-probe/` — M0 WebAuthn PRF capability probe page (deploy to
  the target gh-pages origin; run on Firefox mobile Nightly).
- `wit/` — the `experiment:mosh` engine world.
- `engine-go/` — the mosh engine component (generated bindings
  committed; regenerate with `just engine-bindings` after WIT changes).
- `proto/` — control-channel messages + datagram tunnel framing
  shared by the client-core glue and proxy-core (D8; unit tests:
  `cargo test --lib`).
- `host-test/` — M1 conformance harness: the engine component
  runtime-linked by deltic on Deno, driven over loopback UDP against
  stock C `mosh-server` (gate) and mosh-go's server
  (`moshgo-server/`); `deltic-host.ts` — the shared deltic layer
  (translate once, instantiate with WASI shims + polymorph host
  modules); `client-e2e-deno.mjs` — the composed client on the Deno
  lane vs a real proxy (`just m5-client-deno`); `browser-e2e.mjs` —
  the M5 browser gate (`just m5-browser-e2e`); `composed-e2e/` — the
  M3 native gate (composed core under wasmtime vs upstream iroh +
  mosh-server); `proxy-e2e/` — the M4 native gate (composed core ↔
  real proxy ↔ proxy-spawned mosh-server over iroh); `passkey-e2e/` —
  the M6 native gate (ceremonies, escrow, persistent detach,
  fresh-process reattach; webauthn-authenticator-rs soft passkey as
  the user); `ssh-e2e/` — the M7 native gate (deprivileged proxy,
  russh sshd stand-in, inner-ssh flow with host-key/auth negatives).
- `proxy-core/` — the D9 proxy-brain component (accept loop, control
  channel, TOFU via host import, sub-framed datagram pumps,
  `wasi:sockets` UDP to mosh-server, and the M7 SSH_FORWARD
  stream↔TCP forwarder in `src/tcp.rs`); fused into
  `proxy/composed-proxy.wasm`.
- `proxy/` — the native proxy shell: wasmtime + composed proxy-core,
  host imports (authorize/new-session/register-forward/end-session/
  webauthn/escrow/log), connstring + QR bootstrap UX. Deprivileged by
  default since M7 (`--personal` opts back into proxy-spawned
  sessions; `--ssh-target` names the loopback sshd for forwarded
  streams).
- `web/` — the static client site: `index.html` + `app.mjs` (xterm.js
  in front of two session modes: the M2 dev bridge, and the real iroh
  mode — the composed client runtime-linked by deltic in-page,
  `connectIroh`) + `deltic-entry.ts` (the page's deltic host layer,
  bundled to `web/dist/deltic.js` by `just web-bundle`) + the M5
  bootstrap modules — `boot.mjs` (panel: fragment/manual entry,
  explicit save offers, saved proxies, connect with token policy),
  `connstring.mjs`, `storage.mjs`, `idb-keys.mjs` (non-extractable
  CryptoKey persistence) — and the M6 escrow crypto: `prf-wrap.mjs`
  (PRF→HKDF→AES-GCM wrap/unwrap of `{key, seqFloor}`, D4 policy
  guard). Gates: `just m5` = `m5-web` (modules incl. the phase-3
  ceremony tests against the CDP virtual authenticator) +
  `m5-client-deno` + `m5-browser-e2e` (the in-browser session,
  finding 25). `scripts/web-deploy-tree.sh` assembles the static
  deploy tree including `dist/` (bundle, composed client, translator).

## Milestones

| # | Deliverable | Gate |
|---|---|---|
| M0 | scaffold; componentize-go spikes; PRF probe; upstream issues filed | componentize-go fails ⇒ stop and discuss; PRF result selects D4 arm |
| M1 | engine WIT + Go impl; native harness vs C mosh-server over UDP | **DONE** — wire compat (findings 7–10); `just m1` |
| M2 | browser mosh: xterm.js + engine + throwaway ws-datagram bridge | **DONE** — findings 12–13; `just m2` / `just web-serve` |
| M3 | client-core glue; engine+glue+endpoint composed; native leg over real iroh | **DONE** — finding 15; `just m3` |
| M4 | proxy (QR, TOFU, interim sessions, forwarding) + native E2E over iroh | **DONE** — finding 16; `just m4` |
| M5 | identity PR + browser client (bootstrap flows, storage, WebRTC-direct E2E) | **DONE** — findings 17–19 (unblocked parts, jco era) + 24–25 (deltic cutover, browser leg live); `just m5 m5-netem` |
| M6 | passkeys (ceremonies over control channel, gated reattach) | **DONE** — findings 20–21; `just m6` (native) + web-tests phase 3 + `just m6-browser` (browser ceremony E2E, finding 28) |
| M7 | inner ssh (stream forward to sshd; ssh in engine; deprivileged proxy) | **DONE** — findings 22–23; `just m7` (native) + `just m7-browser` (in-page leg, finding 29); first-contact fingerprint confirm before the password moves (two-phase ssh-flow, finding 30); proxy deprivileged by default (`--personal` opts back in) |

## Running

`scripts/setup.sh` checks/installs the toolchain (idempotent). Then:

```
just --list
```

## Findings

Numbered, append-only. Each spike/milestone writes what it found here.

Tested with: componentize-go 0.4.1 (host Go 1.26.5; async builds use the
auto-downloaded patched `go1.25.5-wasi-on-idle-v2`, upstream PR
golang/go#76775, arm64 build available), wasmtime 47.0.1, wasm-tools
1.247.0, node 24.18.0 (harness scripts only), deno 2.9.5, deltic @ the
`scripts/setup.sh` pin (consumed as a git reference per its
docs/consumers.md; translator shim built locally), headless
Chromium 151. M1 adds: stock `mosh-server` 1.4.0 (Debian), mosh-go @
8dca5c67ec8e (vendored fork, see `.deps/mosh-go/DEPS.md`), vt-go
v0.1.0. The D7 compose spike adds: wac 0.10.1, Rust 1.96.0 with the
`wasm32-wasip2` target, wit-bindgen 0.59. M6 adds: webauthn-rs 0.5
(proxy RP), webauthn-authenticator-rs 0.5.5 SoftPasskey +
webauthn-rs-proto 0.5 (harness). M7 adds: golang.org/x/crypto v0.49.0
(engine, unpatched) and russh 0.62.5 (the ssh-e2e sshd stand-in).
The deltic cutover retires the lann/jco fork pin (historical findings
below reference it as the "jco era").

1. **componentize-go sync path: green everywhere (D5 gate PASSED).**
   Sync function exports and exported *resources* work under wasmtime
   (WAVE `--invoke`), jco/node, and jco/browser. The component carries
   the wasi 0.2 baseline import set (cli/stdio, clocks, filesystem
   types/preopens, random) regardless of the world's declared imports;
   all of it is served in-browser by preview2-shim 0.19 `dist/browser`.
   ~2.8 MB unoptimized. `just spike-sync-wasmtime spike-sync-jco
   spike-sync-browser`.

2. **Goroutine-over-CM-async abstraction confirmed on wasmtime.**
   Async-lifted exports (callback ABI, `witAsync.Run`) run plain
   blocking-style Go; generated import bindings expose `[async-lower]`
   imports as plain blocking Go calls (`monotonic-clock.WaitFor`);
   4 goroutines parked concurrently on async imports complete in ~54 ms
   for 50 ms waits (concurrent, not serialized). Goroutines+channels
   also work inside a single sync export (pure compute) and inside
   async lifts.

3. **Two async traps on wasmtime, both bounded.** (a) Go-*native*
   timers (`time.Sleep`) inside an async-lifted export trap
   (`async-lifted export failed to produce a result`): the patched Go
   runtime's timers are not integrated with the CM async event loop;
   explicit `wasi:clocks@0.3 wait-for` is the working substitute.
   Consequence: goroutine code with internal `time.Sleep`/`time.After`
   (x/crypto/ssh internals, mosh-go's `DialConn` sendLoop) cannot run
   unmodified in async exports yet — another reason the engine wraps
   `DialConnRaw`. (b) Calling an async import from a *sync* export
   traps (`unreachable`) — the ABI forbids a sync task yielding; same
   rule as Rust. The engine makes no async host calls by design.

4. **componentize-go async output does not run on the pinned jco fork
   yet.** Async-lifted exports work (node and Chromium, incl. goroutine
   concurrency — `spin-pipeline`), but any guest call of an
   `[async-lower]` import fails (`Missing subtask ... for host import`,
   or hangs): componentize-go's async-lower sequence vs jco's subtask
   bookkeeping, the same defect family as polymorph-iroh#10 /
   lann/jco#11. Consequence: browser-side ssh-in-engine (workstream F)
   waits on the same upstream jco hardening as the endpoint's browser
   leg — they travel together; wasmtime-first ordering is unaffected.
   Also: preview3-shim 0.2.2 is node-only; the browser p3 clock shim is
   ~15 lines (`runner/browser-clocks-p3.js`).

5. **Engine shape ruling validated.** Sync sans-I/O exports driven by a
   JS tick are independent of every broken or blocked path above (jco
   async-lower, jco scheduler, Go timer integration). Nothing in the
   engine's planned surface touches them.

6. **PRF gate PASSED on Firefox mobile Nightly (D4 → PRF arm).**
   https://lann.github.io/prf-probe/ on Firefox mobile Nightly (JSPI
   flag enabled), private window: create-with-prf, 32-byte prf eval at
   get, and the same-salt determinism re-check all pass; JSPI present.
   Two caveats recorded: (a) a password-manager extension wrapping
   `navigator.credentials` broke the first run with a Chrome-only
   `tabs.update` TypeError before WebAuthn ran — the probe now calls
   the `CredentialsContainer.prototype` methods, reports
   `webauthn-unwrapped`, and flags non-WebAuthn errors as extension
   interference; the real client must anticipate wrapped WebAuthn in
   the field. (b) Results hold for the `lann.github.io` origin; rerun
   if the client ships from a different origin.

7. **M1 gate PASSED: the engine is wire-compatible with stock C
   mosh-server 1.4.0.** Prompt render, echo round-trip, resize
   propagation (`stty size`), a 4 KB single-feed paste (multi-fragment
   client diff, reassembled fine by the C server), and server→client
   bulk all pass, against both the C server (gate) and mosh-go's
   server — `just m1`. The harness drives the jco-transpiled engine
   from node (preview2-shim, loopback UDP `dgram`) with the exact
   sans-I/O contract the browser client will use: feed inbound
   datagrams, 8 ms tick → send returned datagrams, drain display
   bytes. Engine component is ~5.1 MB unoptimized (mosh-go + vt-go on
   top of the ~2.8 MB Go baseline).

8. **mosh-go needed three engine-side accommodations (vendored fork,
   `.deps/mosh-go`, patches ledgered in its `DEPS.md`).** (a)
   creack/pty (imported by the server half) does not compile for
   wasip1/wasip2 — build-tag patch on `server.go`. (b) A mosh client
   must announce its terminal size as its **first user state**: the C
   server sends no screen content at all until the client's first
   state arrives (it has no other way to learn cols×rows), and
   mosh-go's `DialConnRaw` does not do this — the engine calls
   `Resize(cols, rows)` at connect; without it the session looks
   connected but stays visually dead. (c) `maxFragmentPayload`
   1300 → 1100 (wire = payload + 38 B: 1338 B upstream vs the ~1162 B
   iroh ceiling; 1138 B patched). Fragment sizing is sender-local in
   SSP; the paste test confirms the C server reassembles our smaller
   fragments.

9. **Ceiling risk is now on the server→client direction: stock C
   mosh-server emits datagrams up to 1252 B observed (fragment payload
   1214 B), over the ~1162 B iroh application ceiling.** We can size
   our own datagrams (finding 8c) but not a stock server's. M4's
   QUIC-datagram↔UDP forwarder must handle it: sub-frame oversized
   datagrams at the tunnel layer (both tunnel ends are ours), or
   negotiate a larger datagram size on paths that aren't real UDP
   (relay websocket, WebRTC data channel) where the 1200 B MTU profile
   is not a physical constraint — design input for polymorph-iroh#28
   (`max-datagram-size` is already part of that surface). Decide in
   M3/M4.

10. **Fidelity observations, non-blocking.** (a) mosh-go's *server*
    dropped a leading digit mid-scroll in the bulk phase (`99` for
    `299` at 100 cols); the C leg rendered the same phase correctly,
    so the conformance assertion pins only the final line — origin
    (mosh-go server diff engine vs our tracker) not yet attributed;
    M2's real xterm.js display will add signal. (b) mosh-go clamps RTO
    to [250 ms, 10 s] where C mosh uses [50 ms, 1 s]; bulk transfers
    inflate RTT samples (send-side hold time is not subtracted from
    the timestamp echo) and the engine's RTO was observed pinned at
    10 s afterwards — sluggish retransmit after bursts. Candidate
    fork patch if M2/M5 latency measurements show impact.

11. **wac composition of the engine works everywhere the sync path
    works (D7 mechanics gate).** A sync Rust adapter (wit-bindgen
    0.59, `wasm32-wasip2` cargo target) importing
    `experiment:mosh/engine`, `wac plug`-ged with the componentize-go
    engine component: cross-component function calls, a static
    returning `result<own<session>, string>`, resource
    construct/methods/drop across the fused boundary, and
    record/nested-list transfer are all correct under wasmtime (WAVE,
    deterministic answers), jco/node, and jco/Chromium on the pinned
    fork — no async anywhere by construction. The engine's exports are
    consumed (not re-exported); both components' wasi baselines merge
    upward and preview2-shim serves them unchanged. Composed *async*
    (the client-core glue's recv/tick) remains unproven under jco and
    rides A3 — deliberately not probed here to keep the signal clean.
    `spikes/compose/`; ~56 KB adapter, composed artifact ~5.2 MB.

12. **M2 gate PASSED: the engine drives xterm.js in a real browser.**
    jco-transpiled engine + preview2-shim browser dist + xterm.js
    5.5 in headless Chromium, datagrams over the throwaway ws↔UDP
    bridge (`host-test/browser-smoke.mjs`; manual mode
    `just web-serve`, one shell per tab). Page pump = the M1 harness
    contract: ws message → `handle-datagram`, 8 ms `tick` → ws sends,
    `drain-output` → rAF-coalesced `term.write`; `onData` →
    `feed-keys` with an immediate drain so predictions paint same-
    frame. Prompt, echo round-trip, and resize (browser → engine →
    server pty, `stty size`) all green. Under a 150 ms/way bridge
    delay, typed keystrokes painted locally ~145 ms after the first
    keypress — half the 300 ms RTT, before any server echo could
    arrive — rendered underlined (9 speculative cells), with
    `stats().predictor-active` observable from the page. Note:
    mosh-go's predictor engages on any printable keystroke (no
    RTT-adaptive gating like C mosh) and resets on control characters;
    if netem work (M5) shows low-RTT flicker, adaptive display is a
    candidate fork patch.

13. **A fresh engine instance can never rejoin a running mosh-server
    — reattach needs a persisted sequence floor (M6 design input).**
    SSP replay protection drops datagrams whose 63-bit nonce sequence
    is ≤ the highest seen, and a restarted client starts at 0; worse,
    reusing a sequence under the same key is OCB nonce reuse. Real
    mosh never hits this because detach/reattach keeps the client
    *process* alive. Consequence discovered while building the M2
    bridge (each ws connection must spawn its own mosh-server): the
    D4 escrow blob must carry `{key, seq-floor}` with the floor bumped
    strictly forward on every attach (large-margin jump is safe —
    sequence gaps are legal; screen state re-converges from mosh's
    diff-from-acked mechanism, which is why the engine's resize-first
    kick works). Engine additions planned with M6: a connect option
    for the initial sequence and a current-sequence stat for
    detach-time persistence.

14. **Upstream evaluation (2026-08-08): #28 and #29 are implemented,
    merged, and suitable as-is; the jco pin bump is not yet the A3
    unblock.** polymorph-iroh PR #30 ships the datagram surface
    exactly in our planned B2 shape — sync `send-datagram` with
    drop-*oldest*-on-full (the right direction for SSP: stale state
    diffs should die first), async `recv-datagram` with the
    accept-family concurrency contract, `max-datagram-size` as
    capability probe — with conformance across relay/UDP/WebRTC plus
    RFC 9221 interop against upstream iroh in both directions.
    Ceiling: 1200 − 1-RTT overhead − frame bound ≈ 1156–1176 B, so
    the patched engine's ≤ 1138 B fits with margin (log the live
    value at B2 first-run). Finding 9 was never raised on #28 (closed
    same-day): stock-server 1252 B datagrams remain over the ceiling —
    M4 forwarder sub-frames; file a fresh upstream issue (per-path
    ceiling on relay/WebRTC, where no physical 1200 B MTU exists) when
    the need is concrete. PR #31 ships identity as a resource with
    per-path constructors (`identity-generate`, `identity-from-keys`
    over polymorph-webcrypto handles; borrowed into an
    `endpoint-options` resource) — crypto-split preserved, browser
    persistence stays embedder-side as we planned. The endpoint
    component builds clean from main (2.0 MB, rust 1.97) and exports
    endpoint + the three identity interfaces. jco: upstream repinned
    30186b2 → dbad4d7d ("all-fixes": sync-start-call, future/stream
    transfer, concurrent task lifetimes, composed guest-to-guest
    tests); re-ran our spikes against a scratch build of dbad4d7d —
    sync and composed-sync green on node + browser (forward-compat
    confirmed for the coming repin), but componentize-go
    **async-lower is still broken** (failure mode now a hang rather
    than the old `Missing subtask` throw). #10 and lann/jco#11 remain
    open; A3 still gates M5/M7 browser legs and composed-async.
    Consequence for the plan: M3's "A1 PR upstream" and M5's "A2 PR"
    are done by upstream — M3 collapses into B2 (client-core glue
    against the merged surface, native-first).

15. **M3 gate PASSED: the wac-composed client core speaks mosh over
    iroh datagrams natively — and interoperates with upstream iroh on
    the wire.** `client-core/` (Rust, wit-bindgen 0.59 async) is the
    D7 glue: it owns the recv-datagram loop and the 8 ms `wait-for`
    tick as `spawn_local` tasks, `dial` binds its own endpoint
    (identity-generate through the fused webcrypto path, UDP direct +
    home relay) or `embed.attach` takes an embedder connection; fused
    with the engine and the polymorph-iroh endpoint via `wac plug`
    (7.3 MB). The native harness (`host-test/composed-e2e`, `just m3`)
    drives it under wasmtime's CM-async host and forwards datagrams to
    a stock C mosh-server through an **upstream-iroh** peer — every
    datagram crosses implementations (RFC 9221 interop, not just
    self-consistency). M1 conformance assertions green end-to-end;
    live `max-datagram-size` = **1162 B exactly** (the plan's original
    estimate): the engine's 1138 B wire max leaves 24 B headroom.
    Composed-async is thereby **proven on the wasmtime path** — risk 6
    narrows to jco-only. Paper cuts worth remembering: (a) mixed
    sync/async exports generate two different host calling conventions
    (store-context vs accessor) — the driver surface went uniformly
    async; (b) a native host can only bindgen against composed exports
    whose signatures avoid fused-away imported types — `attach`
    (naming the endpoint's `connection`) lives in a separate `embed`
    interface outside the harness's bindgen view, consumed instead by
    M5's jco path; (c) `iroh-relay` needs `enable_metrics = false` to
    coexist with anything else on the machine.

16. **M4 gate PASSED: full native E2E over real iroh — composed
    client core (wasmtime) ↔ proxy (thin shell + composed proxy-core,
    D9) ↔ proxy-spawned stock mosh-server.** `just m4`. One
    `connect-proxy` call covers dial, control handshake (hello +
    pairing token, TOFU auto-accept, new-session, key delivery — D8),
    then prompt/echo/resize green through the framed tunnel; negative
    path first: a wrong pairing token is refused without ceremony and
    the proxy stays up. Sub-framing (finding 9) is now *measured*:
    the incompressible bulk phase drove 6–7 oversized (>1162 B)
    server datagrams per run through the 2-fragment tunnel, and the
    detach-time proxy summary reports the count. Lessons: (a) mosh
    zlib-compresses its diffs, so compressible bulk (`seq 1 500`)
    produced `fragmented=0` — the gate paints 220×50 with base64
    noise (~8 KB compressed diffs ⇒ several ~1252 B datagrams,
    consistent with finding 9) and must keep doing so; (b) client
    `detach` has to await `wait-closed` after `close`, or an embedder
    that stops driving the store right after the call can leave
    CONNECTION_CLOSE unsent and the peer discovers the close only via
    idle timeout (this was the checkpoint-3 "summary never printed"
    hang); (c) the proxy spawns the user's shell by default — the
    first run failed because a starship prompt contains no `$` —
    tests pin `--shell "bash --noprofile --norc -i"`. Sizes:
    proxy-core 302 KB, composed proxy 2.3 MB, composed client 7.5 MB,
    native shell 47 MB (embeds wasmtime). wasmtime-47 bindgen
    conventions for the host imports (async WIT import ⇒
    `HostWithStore` fn taking `&Accessor`, sync ⇒ `Access`; empty
    `impl Host for &mut Ctx`) are recorded in proxy/src/main.rs.

17. **M5 unblocked parts built and gated (`just m5`): bootstrap
    modules, storage schema, and IndexedDB identity persistence all
    green in node + headless Chromium.** `web/connstring.mjs` (v1
    format parse/format, fragment extraction incl. percent-encoding
    and the URL-without-fragment case), `web/storage.mjs` (schema v1
    `{v, proxies[], identityRef, sessions[]}`; proxy id = endpoint id;
    pairing tokens deliberately not persisted; session keys are the D4
    tagged variant carrying `seqFloor`, with a forward-only bump
    helper per finding 13), `web/idb-keys.mjs` + boot panel wiring in
    `index.html`/`boot.mjs` (fragment → parse → explicit save offer;
    saved-proxy list; manual entry; honest A3 notice on connect).
    Key result: a **non-extractable Ed25519 WebCrypto key pair
    round-trips through IndexedDB structured clone and survives page
    reloads** in Chromium 151 — generated with `extractable: false`,
    signs after retrieval, private key never exposed — exactly the
    embedder-side persistence PR #31's `identity-from-keys` expects.
    The M2 dev-bridge page (`just m2`) stays green under the new
    layout; without a bridge the terminal idles and says why instead
    of failing.

18. **Composed-async under jco, exercised for real (M5 probe): it
    fails EARLIER than the A3 scheduler — a new defect class, filed
    as [lann/jco#51](https://github.com/lann/jco/issues/51).**
    `just m5-jco-probe` transpiles the composed client (JSPI mode,
    polymorph shims mapped) and drives it at a live proxy; the module
    throws at import time: `Cannot access 'Connection' before
    initialization` — jco emits a `taskReturn` trampoline whose lift
    metadata references a resource class *by value* above the class
    declaration (TDZ). Trigger, minimized in
    `spikes/compose-async-tdz/` (two tiny Rust components): an async
    cross-component call returning `own<resource>` **plus** the same
    resource type re-exported in an exported interface (our `embed`'s
    `connection`); without the re-export the identical composition
    transpiles and runs correctly, and the uncomposed endpoint is also
    fine. Reproduced identically on the dbad4d7d "all-fixes" scratch
    jco; correct under wasmtime (`ok(42)`). Same family as lann/jco#34
    (top-level emission ordering), different site. The probe stays in
    the tree as the A3-unblock detector: it classifies UNBLOCKED /
    THROWS / HANGS on every run, and building the real browser leg
    starts the day it prints UNBLOCKED.

19. **Netem matrix over the M3 gate (`just m5-netem`): the composed
    stack holds to 10% loopback loss with conformance fully green —
    and the finding-10b RTO clamp is confirmed live.** Loopback netem
    (delay on lo counts once per hop: direct-path echo crosses ~4
    hops, so RTT ≈ 4×delay). Numbers (dial / prompt / echo / resize,
    ms): baseline 18/136/134/138; 40 ms 375/324/244/245; 100 ms
    867/548/438/437; 40 ms+3% loss 369/320/219/193; 40 ms+10% loss
    749/1420/186/222. Echo times track physics (4×delay + mosh's
    collation interval); loss shows up in dial/first-paint (handshake
    and initial screen retransmits) while established-flow phases ride
    through. The engine's RTO pinned at **10 s** in every non-baseline
    cell (mosh-go clamps RTO to [250 ms, 10 s] and inflates RTT
    samples on bursts — finding 10b): masked interactively because
    every keystroke triggers an immediate send, but idle-recovery
    after a lost state update can stall up to 10 s — now measured
    grounds for the candidate fork patch (clamp to C mosh's [50 ms,
    1 s]) if M6/M7 sessions feel it.

20. **M6 gate PASSED (`just m6`) — and fresh-process reattach needed a
    second protocol lesson beyond finding 13: SSP state numbers are a
    separate counter, and they must be adopted live, not persisted.**
    The gate: connect → real registration ceremony (webauthn-rs RP in
    the proxy, webauthn-authenticator-rs SoftPasskey as the user, over
    the control channel) → escrow `{key, seqFloor}` → make-persistent
    → detach (proxy keeps mosh-server, "kept (persistent)") → bogus
    session-id and garbage assertion both refused → fresh client
    process: assertion verified, escrow returned verbatim, attach at
    floor+10 000 → **pre-detach screen resyncs, echo works, sequence
    resumed above the floor** → second persistent detach → SIGTERM
    reaps. What it took (mosh 1.4.0 sources, fork patch 3 in
    `.deps/mosh-go/DEPS.md`): a fresh client's instructions were
    dropped by the server's dedup (its retained client-state window
    is {0..N}; mosh-go never advances throwaway), and the server's
    diffs anchor at a state K the fresh client doesn't have — with
    acks for culled states *ignored*, both directions deadlock
    silently (the observed empty screen). Escrowing state floors is
    unsafe: UserStream diffs are positional, so a stale sender floor
    corrupts (server `fatal_assert`) or drops keystrokes. Instead the
    transport **adopts** from the server's first instruction (its
    `ack_num` = our sender floor, frozen during detach; its `old_num`
    = the receiver anchor) — heartbeats arrive every 3 s, so adoption
    is prompt, and the escrow stays `{key, seqFloor}`. Screen content
    at the adopted anchor is unknowable, so the engine forces a full
    repaint with a **resize dance** (attach one row off, snap to true
    size on the first content diff): a size change is the only
    client-reachable full-repaint trigger in the protocol
    (`terminaldisplay.cc` emits clear + full redraw when a diff
    crosses a size boundary). Two latent mosh-go bugs surfaced and
    fixed along the way (ledgered as fork patch 4): an ack could
    clear a never-sent pending diff, and the acked-action bookkeeping
    keyed by predicted state numbers breaks when numbering moves.

21. **Browser PRF leg (web-tests phase 3): Chromium 151's CDP virtual
    authenticator supports `hasPrf`, real prototype-call ceremonies
    pass headless, and the PRF→HKDF→AES-GCM escrow wrap survives a
    fresh assertion** (`prf.enabled` true at create; 32-byte eval at
    get; unwrap under a *second* assertion's PRF output returns the
    sealed `{key, seqFloor}` — the deterministic-KEK property the
    reattach flow relies on). Tamper (ct bit-flip) and
    wrong-credential unwraps throw; the blob shape is byte-identical
    across `web/storage.mjs`, `web/prf-wrap.mjs`, and `proto::Escrow`
    (parity-tested both sides). Security note now recorded with D4:
    in a proxy-returned escrow only the sealed payload is trusted —
    the outer `seqFloor` is client-local bookkeeping, and attach uses
    the inner value plus a per-reattach `FLOOR_JUMP` (2^32) so a
    client that dies without a detach-time write still cannot reuse a
    nonce. The full browser↔proxy ceremony E2E remains A3-blocked
    (lann/jco#51 fires at instantiation, before the scheduler).

22. **The ssh engine can be pure sync sans-I/O: parked goroutines
    survive across sync export calls, and Go-native timers work in
    the sync world (M7 spike; finding 3a was async-world-specific).**
    The M0 sync spike grew two probes, green under jco/node and
    jco/Chromium: (a) a goroutine parked on an unbuffered channel
    inside one sync export call resumes correctly during a *later*
    export call once fed and pumped (`runtime.Gosched` rounds); (b) a
    goroutine blocked in stock-Go `time.Sleep` fires once wall time
    has passed and the scheduler is pumped — no trap, because the
    sync world runs stock Go (the finding-3a timer trap is a
    patched-Go/async-world artifact). Caveat: the spike's wasmtime
    leg is WAVE single-invoke and cannot exercise cross-call
    parking — the M7 gate itself is the wasmtime-side proof. Belt and
    suspenders, audited anyway: x/crypto/ssh v0.49.0 contains ZERO
    `time.After/Sleep/NewTimer/NewTicker/AfterFunc/Tick` in non-test
    files (deadline use only in `tcpip.go`, port forwarding, unused);
    the client path (NewClientConn/mux/session/exec) is timer-free.
    Consequence: `wit/mosh.wit` grew a second engine interface `ssh`
    (same component, same sans-I/O discipline as `engine`):
    `connect(user, password)` never fails synchronously,
    `feed`/`drain` shuttle the forwarded stream's bytes, `pump` runs
    scheduler rounds on the tick cadence, and `status` surfaces
    `connecting | host-key-check | ready | failed`. Inside,
    x/crypto/ssh runs unmodified on goroutines over a `shuttleConn`
    (an in-memory `net.Conn`: Read parks on a 1-buffered wake
    channel — check-then-park is race-free under cooperative wasm
    scheduling; Write appends to an outbox). The **host-key gate**
    exploits x/crypto/ssh's guarantee that authentication runs
    strictly after the HostKeyCallback: the callback goroutine parks
    on a decision channel, status shows `host-key-check` with the
    fingerprint readable, and the password is only ever sent after an
    explicit `host-key-decision(true)`. x/crypto/ssh v0.49.0 rides
    unpatched (nothing vendored); engine grows +3 MB to 8.06 MB.
    The shape is browser-viable by construction (sync exports, stock
    Go); the browser leg still waits on A3 — but via the endpoint's
    jco scheduler blockage like everything else, no longer via the
    finding-4 async-lower gap.

23. **M7 gate PASSED (`just m7`): inner ssh end-to-end — the client
    boots its own mosh-server through a forwarded ssh stream, the
    proxy runs deprivileged and never sees the mosh key (the D2 end
    state).** The gate runs the proxy WITHOUT `--personal` against a
    russh-based sshd stand-in on loopback (`host-test/ssh-e2e`;
    password auth, exec via `sh -c` with a UTF-8 locale, exit-status
    forwarding, and a password-attempt counter). Flow: `connect-ssh`
    dials the proxy, hellos, opens a bi stream whose first byte is
    `stream_tag::SSH_FORWARD` (the control stream needs no tag: it is
    the first one), and the proxy-core stream daemon forwards it to
    `--ssh-target` over `wasi:sockets@0.3` TCP (p3 stream-shaped:
    `send(stream<u8>)` and `receive()` are each called once; teardown
    rides the FIN cascade, no import cancellation). x/crypto/ssh in
    the engine handshakes through the tunnel (~2.8 KB → / ~3.4 KB ←
    including exec), the client execs `mosh-server new -i 127.0.0.1
    -c 256 …`, parses `MOSH CONNECT` from complete lines only, sends
    `ForwardDatagrams{port}` — the host assigns a session id and
    records the port (`register-forward`), the datagram pumps run
    unchanged, and the M1 trio passes through the full path.
    Negatives, in order: `connect-proxy` (NewSession) is refused in
    deprivileged mode with a legible error; a wrong
    `expected-host-key` fails BEFORE authentication with the stand-in
    observing **zero** password attempts (the finding-22 host-key
    gate, verified externally); a wrong password fails legibly (one
    attempt observed). Fingerprint format pinned end-to-end: base64
    (standard, padded) of SHA-256 over the host key's SSH wire blob.
    Lessons: (a) sending a terminal control `Error` and then closing
    the connection is a race — QUIC close discards in-flight stream
    data, and the client sees "stream closed" instead of the reason;
    the proxy now sends the refusal and waits for the *peer* to close
    (`Control::fail`) before teardown. (b) The stream-accept daemon
    must be listening while the proxy still waits for the
    session-establishing control message (the ssh leg precedes
    `ForwardDatagrams` by construction); completion follows the
    no-cancel discipline — the session phase decides, `conn.close`
    resolves the daemon's parked `accept-bi`, and the daemon drains
    to its natural end. (c) Reattach to a forwarded session needs no
    second ssh leg: the client-owned mosh-server is the user's own
    process and survives detach; the host's session entry (id ↔
    port, no pid, no key) makes passkey binding port-agnostic —
    `make-persistent`/`reattach` work unchanged. ssh v0 gaps,
    deliberate: password auth only, one exec per session, no
    interactive stdin surface; host-key pinning is embedder-side
    (`expected-host-key`/`ssh-host-key`). The browser ssh leg stays
    A3-blocked with the rest of the composed client (finding 18);
    `just m5-jco-probe` remains the unblock detector. Sizes:
    proxy-core 496 KB, composed proxy 2.5 MB, composed client
    10.5 MB.

24. **deltic cutover (2026-08-10): jco is fully replaced; every gate
    that existed is green on the new host, and the finding-4/A3 defect
    family is gone.** deltic is a runtime linker (wasmtime-frontend
    translation in-process, CM 0.3 task model native to the JS event
    loop): no transpile step, no generated trees, no `--map` flags, no
    fork pin, no `--experimental-wasm-jspi` (the callback ABI needs no
    JSPI; the stackful forms light up via JSPI where the engine has
    it). The node harness lanes moved to stock Deno (`deno.json` at
    the root is the one import map; polymorph deltic host modules come
    from the pinned `.deps/polymorph-iroh` nested checkouts; the
    browser gets one bundled ESM via `just web-bundle`, Deno-only
    WebRTC backends marked external). Cutover evidence: M1
    conformance (both legs), M2 browser smoke incl. prediction, all
    three spikes — and the async spike's `[async-lower]` import shape,
    broken under every jco pin we ever tested (finding 4), completes
    in ~10 ms under deltic. Composed sync AND async cross-component
    shapes work; lann/jco#51's TDZ class cannot exist (nothing is
    emitted). Two wosh-side accommodations: every export call is
    Promise-shaped on JS hosts (drivers became single-writer async
    pump loops — two concurrent `drain-output`s could interleave
    screen bytes), and trailing `option<T>` params need an explicit
    `undefined` (exact arity). Embedder path policy rides guest env,
    not WIT: `WOSH_UDP=off` skips the endpoint's UDP bind where
    `wasi:sockets` is stubbed (browser profile) — a socket-create
    failure would otherwise fail the whole dial (the endpoint treats
    a provided-but-unbindable addr as an error, correctly).

25. **The browser leg is LIVE (`just m5`), and it found a real deltic
    scheduler-periphery defect on the way — fixed upstream the same
    day (lann/deltic#70).** The defect: a FACT cross-component call
    promising-wrapped only the callee's *initial* entry; the
    callback-loop *re-entries* went in unwrapped, so a composed
    callback-ABI callee that parks (WAIT) and later blocks
    synchronously mid-activation — wit-bindgen's `block_on` shape,
    here the fused endpoint signing its TLS CertificateVerify via
    `block_on(webcrypto sign)` inside packet processing — died with
    `SuspendError: trying to suspend without WebAssembly.promising`.
    Invisible to the official CM suite (its callees only block via
    WAIT codes, which unwind the frame first); found by this repo's
    composed client within an hour of it first running under deltic,
    exactly the consumer-workload class deltic's docs predicted.
    Upstream fix mirrors the lift path (`enterWasm` on the callback,
    per-callee `canBlock`), with a hand-written composed-wat
    regression fixture; deltic gates green (conformance 1254/0).
    With the fix: `just m5-client-deno` (Deno lane, ~230 ms
    connect-proxy) and `just m5-browser-e2e` (headless Chromium
    drives the real page: QR-shaped `/#connstring` navigation, panel
    connect, prompt/echo/resize through xterm.js, stats, clean
    detach; wrong pairing token refused with a legible notice
    first). Both connect on attempt 1 — the endpoint's RefCell
    borrow hazard (documented upstream, host-deltic README) never
    fired here, but the browser gate keeps a bounded retry budget
    (8) against it. Paths are relay-only for now: the glue never
    sets `endpoint-options.webrtc`, so the WebRTC upgrade is an
    unexercised follow-up (enable both sides + assert
    `connection.path` moves, per the upstream exam). Remaining
    browser follow-ups: M6 ceremony E2E and M7 inner-ssh in-page
    (both now purely wosh-side work). Sizes: page bundle 527 KB,
    translator shim 3.8 MB, composed client 10.5 MB (unchanged).

26. **Pin bump (2026-08-10 late): deltic @ a18be734 + polymorph-iroh @
    d8fdd039 — three defects surfaced, all fixed, all upstream-first.**
    The polymorph-iroh bump brings their #40 (jco host retired — deltic
    is their JS leg too), #43 (parking-kernel adoption), and #44
    (event-driven endpoint wakeups replace the jco-era bounded-polling
    pump); no WIT changes, endpoint surface stable. What the bump
    shook loose: (a) deltic's always-on parking kernel marks
    `wasi:io` block/poll as suspension-capable, which auto-detects our
    plain sync ENGINE into jspi mode — its exports now settle a
    microtask after the guest turn (the "entry hop") — and deltic
    released the instance's reentrance bracket during that hop, so a
    concurrent host call's guest turn could reuse the still-unlifted
    return area: `tick`'s `list<list<u8>>` lift read reallocated
    memory (`Trap: list too long`), poisoning the instance. Fixed
    upstream (lann/deltic#82): host calls gate on hop quiescence —
    the reference's core+lift atomicity restored — with a
    deterministic tick/clobber wat fixture; found by `just m2` within
    minutes of the bump. (b) The poisoned instance's parked segments
    then died on an enterability assert, burying the real trap under
    an assert cascade — same PR retires poisoned late-settles quietly.
    (c) A latent WOSH race in `drive_ssh` (M7): exit-status can beat
    the final stdout through the engine's goroutine buffers when one
    network flight carries data + exit together (the new upstream
    arrival coalescing does exactly that) — `MOSH CONNECT` sat
    undrained while the glue concluded "exited without MOSH CONNECT".
    The glue now drains to quiescence on exit before concluding
    (strictly convergent: no further input exists after exit). Also
    upstream this session: deltic#78 (timer pollable re-arm + chunking
    below the setTimeout ceiling — review finding on their #71) and
    deltic#79 (smoke-c0 follows our rename, legs 1/3 revived).
    Sweep at the final pins: proto, m1×2, spikes×6, m2, m3, m4,
    m5×3, m6, m7 — all green.
    Post-sweep addendum, same bump: the deno.lock grew FOUR pinned
    raw-URL deltic trees — each polymorph sibling package carries its
    own deno.json (for standalone use) whose import map pins @deltic/*
    to its own prerelease URL, and Deno applies a package's own config
    to that package's files. The graph (and the browser bundle: esbuild
    `WitError2` renames) carried MULTIPLE deltic runtimes — a latent
    module-identity break (`instanceof WitError` fails across the
    webcrypto/websocket module boundary, so their first real error
    would have become a spurious "unbranded throw" trap; never fired
    only because the happy paths never threw). Fixed with URL-prefix
    import-map keys collapsing every sibling-pinned deltic tree onto
    .deps/deltic (bundle 563 → 490 KB, zero remote content, zero
    collision renames); the deno.json header documents the
    add-a-prefix-per-pin-bump rule. Upstream convergence note filed in
    TASK.md — the consumers doc should bless this pattern or the
    sibling modules should drop standalone pins.

27. **WebRTC upgrade leg LIVE (the M5 carried item): browser sessions
    leave the relay.** One dial site serves every lane, so the enable
    is a line per side: the glue's `dial_connection` sets
    `endpoint-options.webrtc` and offers a `webrtc(relay-url)` addr
    entry (an upgrade hint, not a dial target — the handshake runs on
    the relay and the packets move to the data channel once it opens,
    per the endpoint WIT), and proxy-core sets `webrtc` at bind to
    answer signaling. Upgrade attempts run only on relay-dialed
    connections, so the native ip-dialed gates never attempt one
    (m3/m4/m6/m7 swept green). Observation surface:
    `client-session.path` (additive WIT: "relay" | "ip" | "webrtc";
    not latched — upgrade and fallback both move it), shown live in
    the page status line and as the `__mosh.path()` hook.
    m5-browser-e2e now hard-asserts the upgrade (30 s bound; in
    practice already upgraded by the time the M1-trio phases finish)
    and echoes again post-migration — Chromium's RTCPeerConnection
    interops with the proxy's webrtc-rs shim on loopback; the Deno
    lane polls bounded and logs where the wire ended up (observed
    upgraded in ~0.8 s; node-datachannel ↔ webrtc-rs). The per-path
    datagram-ceiling question stays the recorded upstream courtesy
    (TASK.md); the tunnel's sub-framing already tolerates a
    post-upgrade ceiling shrink. Sweep: m2, m3, m4, m5×3, m6, m7
    green (m1/spikes untouched — engine unchanged).

28. **M6 browser ceremony leg LIVE (`just m6-browser`): the passkey
    lifecycle end-to-end from the real page.** The RP's webauthn-rs
    JSON is the standard WebAuthn wire format, so the page marshals
    with `PublicKeyCredential.parse*FromJSON`/`toJSON` — and
    webauthn-rs-proto's `alias = "clientExtensionResults"` accepts
    `toJSON()` output verbatim. The PRF extension never crosses the
    wire: ceremony options gain it client-side, and responses are
    stripped of `clientExtensionResults` before the RP sees them (the
    PRF output seeds the escrow KEK; handing it to the proxy would
    defeat the D4 PRF arm). Reattach is ONE `get()`: the same
    assertion satisfies the RP and evaluates the PRF that unwraps the
    returned escrow; attach at sealed-floor+SEQ_MARGIN, then the
    prf-wrap floor-jump policy executes for real — re-seal at
    floor+2^32 under the same PRF output (credId taken from the
    assertion's own rawId, never from the returned blob's outer
    fields — finding 21) and re-escrow over the live control channel
    (repeated make-persistent replaces; the proxy logs the second
    escrow write). Gate topology: CDP virtual authenticator
    (ctap2.1 + prf, resident, UV), page at http://localhost:3354
    (`--rp-id localhost --rp-origin` = the page origin; Chromium
    resolver-maps localhost→127.0.0.1), relay :3353. A reload is the
    fresh-client-process boundary; localStorage and the resident
    credential survive it; the pre-detach screen resyncs without
    input, the engine resumes above the floor, and a second detach is
    still kept. Storage: session records now carry the proxy session
    id; the panel offers "persist session" on a live session and
    "reattach #N" on saved proxies holding a prf-arm record.
    Ceremony negatives stay native-gate territory (passkey-e2e).
    Swept: m5-web, m5-browser-e2e, m2, m6-browser.

29. **M7 browser leg LIVE (`just m7-browser`) — the last finding-24
    follow-up is closed.** The page grows the inner-ssh UX: an ssh
    cluster (user, password, optional command) on the pending and
    saved proxy rows drives connect-ssh through the DEPRIVILEGED
    proxy; the ssh-e2e russh stand-in is factored behind a lib and a
    `sshd-standin` bin the node harness spawns. Host-key policy is
    storage policy: `proxies[].sshHostKey`, pinned TOFU-style from
    `ssh-host-key` on first success, passed as `expected-host-key`
    afterwards. The gate proves the pin does its job from the page: a
    TAMPERED pin fails "host key mismatch" BEFORE the password leaves
    the browser (the stand-in's password-attempts counter is asserted
    unchanged across the refusal), and restoring the pin reconnects
    (fresh session, second exec'd mosh-server). Auth and posture
    negatives (wrong password, NewSession-without---personal) stay in
    the native gate. Relay :3355. Swept: m5-web, m5-browser-e2e,
    m6-browser, m7 native, m2 (one m2 flake under parallel browser
    load — the prediction-latency budget is timing-sensitive — green
    on rerun).

30. **First contact now confirms the fingerprint BEFORE the password
    moves (issue #7): a two-phase `ssh-flow` closes the sharpest ssh
    v0 gap.** The steady state was already gate-proven (a pinned
    mismatch fails pre-auth), but TRUE first contact auto-accepted:
    the glue observed the key, sent the password, and the embedder
    pinned afterwards — one free password capture per new client for
    a malicious proxy operator, exactly the party inner ssh evicts
    from the auth TCB (D2). `ssh-flow` mirrors `reattach-flow`:
    `begin` dials, hellos, opens the ssh-forward stream, runs kex,
    and PARKS at the finding-22 host-key gate; `host-key` reports the
    fingerprint; `authenticate(password, mosh-command, cols, rows)`
    resumes into the mosh bootstrap; `decline` rejects the parked key
    and closes with detach's wait-closed discipline (zero auth
    attempts). The engine's credentials went DEFERRED to make the
    guarantee hold in memory, not just on the wire: `ssh.connect
    (user)` starts a password-less handshake and `authenticate
    (password)` feeds a `PasswordCallback` closure, so the engine
    never even HOLDS a password while an unapproved key is on the
    table (accepting without credentials fails legibly). The user
    name must ride `begin` — x/crypto snapshots its ClientConfig by
    value at NewClientConn, before kex — but it is only ever SENT in
    auth requests, strictly after the gate resolves, so nothing
    secret moves early (this is why the issue's sketched
    `authenticate(user, password, …)` was not implementable without
    forking x/crypto). `connect-ssh` keeps its shape on the same
    two-phase driver (pin present ⇒ no prompt; `expected-host-key:
    none` stays the harness TOFU path); the panel routes no-pin first
    contact through the flow — fingerprint row with connect/cancel,
    pin lands only on confirmed success, and the password waits in
    page memory (not in the engine) while parked. This park → verdict
    → resume plumbing is the shape keyboard-interactive (#9) rides.
    Gates: native m7 phases 5–6 (decline with the stand-in's counter
    still zero after the fingerprint was in hand; confirm → auth →
    live session), m7-browser first-contact legs (fingerprint
    DISPLAYED with zero attempts while parked; decline → zero
    attempts, nothing pinned; confirm → session + pin; the
    tampered/restored legs additionally assert pinned paths never
    prompt). Two engine bugs surfaced on the way: (a) the exec-output
    `bytes.Buffer` was shared by x/crypto's stdout+stderr copier
    goroutines and the `read-output` export with no lock — Go on wasm
    yields mid-method at allocation/GC safepoints, and the buffer
    tore (Len() observed NEGATIVE; `MOSH CONNECT` truncated out of
    the output while exit-status was visible — a pre-existing race my
    restructure merely re-timed; now a mutex-guarded `lockedBuf`);
    (b) componentize-go export args are zero-copy views over
    transferred cabi memory — anything RETAINED past the export call
    (the deferred user/password) must be `strings.Clone`d, or later
    export calls recycle the backing buffer (observed as auth
    failures with the correct password). Swept: full suite — m1,
    m3, m4, m5×3, m6, m6-browser, m7 (×5 runs), m7-browser.

31. **Async-world goroutine liveness between export calls: SOLVED by
    keep-alive helpers + deltic's settlement pump (`just
    spike-keepalive-deltic`, wosh#25).** The bridge
    (`go.bytecodealliance.org/pkg` wit/async) maps scheduler-idle to
    EXIT when the task has no pending CM waitables — goroutines
    blocked on Go-native primitives are invisible, hence the
    finding-3a trap (unresolved task) and silent stranding of
    background goroutines (resolved task). Two wait-for-based helpers
    (`spikes/componentize-go/async/keepalive`, the PLAN risk-3
    contingency) fix both: a per-task **Guard** (pending
    `wasi:clocks@0.3 wait-for` loop, armed at export entry, released
    on return) converts EXIT to WAIT — `sleep-guarded(30)` returns
    36ms where bare `sleep-echo(10)` still traps (the canary, both
    lanes; deltic wording: `task finished all threads without
    resolving`) — and an eternal instance **Ticker** gives stranded
    goroutines a periodic slice. Between-calls progress additionally
    needs the HOST to deliver timer completions while no call is in
    flight: deltic does since its settlement pump (deltic#121,
    embedder-api amendment A11, pinned as `.deps/deltic-next` @
    a2f84a5) — the ambient probe's background goroutine (spawned by
    `spawn-bg`, task long returned) fired **50ms after spawn, on
    schedule, during a 300ms no-calls idle window** (driver-gated
    behaviour would read ~300ms; guest-side timestamps
    discriminate). wasmtime lane covers the guarded probes under
    `--invoke` (36ms, same numbers); ambient-under-wasmtime needs a
    dwelling `run_concurrent` host (wosh#25 follow-up). The main
    deltic pin CANNOT yet advance past a2f84a5: deltic A10 renamed
    `WitError`→`ComponentException` and payload `{tag,val}`→
    `{kind,value}`, which the pinned polymorph host modules construct
    AND read — convergence tracked in TASK.md; the spike rides a
    second checkout (`scripts/setup.sh` deltic-next stanza,
    `deno-next.json` self-contained import map — do not import
    `deltic-host.ts` there). Helpers retire when upstream Go
    integrates timers with the CM event loop (golang/go#76775
    successor work); the canaries flip loudly when that lands.
