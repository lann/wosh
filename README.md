# experiment-mosh

A mosh-compatible client and proxy tunneled over iroh: a browser client
(xterm.js, JSPI, wasm components) speaking real mosh SSP end-to-end to a
stock `mosh-server`, through a native proxy that embeds the
[polymorph-iroh](https://github.com/polymorph-components/polymorph-iroh)
endpoint component.

**Status: M1 complete (wire-compat gate passed).** Local-only
experiment: no CI, no stability, delete-at-will. If it earns a public
repository it gets a new name. The full plan lives in
[`PLAN.md`](PLAN.md); resumable session state in [`TASK.md`](TASK.md).

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
  composition. Sync-only engine exports keep every pre-M5 milestone
  independent of the jco async-scheduler defect (polymorph-iroh#10),
  and JS-orchestrating the components separately remains a cheap
  fallback (the engine surface is the same either way).
- Control channel: one bi stream, ALPN `experiment-mosh/ctl/0`,
  versioned CBOR. Pairing token in the QR/connection string; unknown
  peers without a valid token are silently rejected; with one, both
  sides display both endpoint pubkeys and the proxy operator accepts
  manually (TOFU).
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
  authentication TCB and runs unprivileged.
- **D3** Upstream-first: the two polymorph-iroh gaps (QUIC datagram WIT
  surface, stable/injectable endpoint identity) are issues+PRs against
  polymorph-iroh, per its conventions (both fall under its issue #3).
- **D4** *(resolved 2026-08-07, finding 6)* Mosh key at rest: the M0
  PRF probe **passed** on Firefox mobile Nightly ⇒ PRF-wrapped key,
  ciphertext escrowed on the proxy; the proxy never sees the plaintext
  key. Storage schema stays a tagged variant (`plain` arm kept for
  emergencies); `mosh-server` binds loopback regardless. Open
  sub-policy for M6: runtime authenticator without `prf` ⇒ refuse
  persistence (lean) vs plaintext-with-warning.
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
  (finding 11); composed *async* under jco rides A3 exactly like the
  endpoint's browser leg (no new blocker). Recorded fallback if
  composed-async stalls: JS orchestrates engine and endpoint
  separately — kept permanently cheap because the engine surface is
  identical in both shapes. WebAuthn, UI, storage, bootstrap, and (for
  now) the control channel stay in JS; moving the control channel into
  the glue is an open sub-question for M5.

## Layout

- `.deps/mosh-go/` — vendored mosh-go fork at the pinned rev, with the
  wasm build-tag and fragment-size patches (`DEPS.md` there is the
  patch ledger).
- `spikes/componentize-go/` — M0 feasibility spikes (sync exports;
  async/goroutine abstraction probes).
- `spikes/compose/` — D7 composition spike: sync Rust adapter
  wac-plugged with the engine; wasmtime/node/browser legs
  (`just spike-compose-wasmtime spike-compose-jco
  spike-compose-browser`).
- `web/prf-probe/` — M0 WebAuthn PRF capability probe page (deploy to
  the target gh-pages origin; run on Firefox mobile Nightly).
- `wit/` — the `experiment:mosh` engine world.
- `engine-go/` — the mosh engine component (generated bindings
  committed; regenerate with `just engine-bindings` after WIT changes).
- `host-test/` — M1 conformance harness: jco-transpiled engine driven
  from node over loopback UDP against stock C `mosh-server` (gate) and
  mosh-go's server (`moshgo-server/`).
- `proxy/` — the native proxy (from M4).
- `web/` — the static client site. M2 shape: `index.html` + `app.mjs`
  (xterm.js front end, engine pump) served by the bridge; grows into
  the real client (bootstrap, storage, composed core) from M5.

## Milestones

| # | Deliverable | Gate |
|---|---|---|
| M0 | scaffold; componentize-go spikes; PRF probe; upstream issues filed | componentize-go fails ⇒ stop and discuss; PRF result selects D4 arm |
| M1 | engine WIT + Go impl; native harness vs C mosh-server over UDP | **DONE** — wire compat (findings 7–10); `just m1` |
| M2 | browser mosh: xterm.js + engine + throwaway ws-datagram bridge | **DONE** — findings 12–13; `just m2` / `just web-serve` |
| M3 | polymorph-iroh datagram PR (native legs) | upstream conformance |
| M4 | proxy (QR, TOFU, interim sessions, forwarding) + native E2E over iroh | |
| M5 | identity PR + browser client (bootstrap flows, storage, WebRTC-direct E2E) | blocked on polymorph-iroh#10 for the browser endpoint leg |
| M6 | passkeys (ceremonies over control channel, gated reattach) | |
| M7 | inner ssh (stream forward to sshd; ssh in engine; deprivileged proxy) | |

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
1.247.0, node 24.18.0, jco = lann/jco fork @ 30186b2 (via
polymorph-iroh/.deps), headless Chromium 151. M1 adds: stock
`mosh-server` 1.4.0 (Debian), mosh-go @ 8dca5c67ec8e (vendored fork,
see `.deps/mosh-go/DEPS.md`), vt-go v0.1.0. The D7 compose spike adds:
wac 0.10.1, Rust 1.96.0 with the `wasm32-wasip2` target, wit-bindgen
0.59.

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
