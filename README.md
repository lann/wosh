# experiment-mosh

A mosh-compatible client and proxy tunneled over iroh: a browser client
(xterm.js, JSPI, wasm components) speaking real mosh SSP end-to-end to a
stock `mosh-server`, through a native proxy that embeds the
[polymorph-iroh](https://github.com/polymorph-components/polymorph-iroh)
endpoint component.

**Status: M0 (feasibility spikes).** Local-only experiment: no CI, no
stability, delete-at-will. If it earns a public repository it gets a new
name.

## Architecture

```
BROWSER (JSPI)                                   PROXY HOST (native Rust)
┌──────────────────────────────┐                 ┌────────────────────────────────┐
│ JS: xterm.js, QR scan,       │   iroh QUIC     │ terminal UI: QR + connstring,  │
│ WebAuthn, storage, glue      │  (RPK TLS,      │ TOFU prompts                   │
│ ┌──────────────────────────┐ │   both peers    │ webauthn RP · session registry │
│ │ mosh engine (Go, sync    │ │   pinned)       │ ┌────────────────────────────┐ │
│ │ sans-I/O exports)        │ │ ──────────────► │ │ wasmtime + polymorph-iroh  │ │
│ ├──────────────────────────┤ │  relay / webrtc │ │ endpoint component         │ │
│ │ polymorph-iroh endpoint  │ │  / udp          │ └────────────────────────────┘ │
│ │ (jco, JSPI, async)       │ │                 │ forwarders:                    │
│ └──────────────────────────┘ │                 │  QUIC dgram ↔ UDP 127.0.0.1    │
└──────────────────────────────┘                 │  QUIC stream ↔ TCP :22 (ssh)   │
                                                 │ spawns: mosh-server -i 127.0.0.1│
                                                 └────────────────────────────────┘
```

Layering: mosh SSP (AES-OCB, end-to-end browser↔mosh-server) over QUIC
datagrams on the iroh connection; ssh (end-to-end browser↔sshd) joins in
workstream F. The iroh layer is network access control; the inner
ssh/mosh layer is the strong security boundary.

- The mosh engine wraps [mosh-go](https://github.com/unixshells/mosh-go)
  `DialConnRaw` (no goroutines, no timers) behind fully synchronous WIT
  exports; JS drives an ~8 ms tick. Sync exports keep the engine
  independent of the jco async-scheduler defect
  (polymorph-iroh#10).
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
- **D4** Mosh key at rest is gated on the M0 PRF probe (Firefox mobile
  Nightly, Play Services authenticator path). Pass ⇒ PRF-wrapped key,
  ciphertext escrowed on the proxy. Fail ⇒ plaintext localStorage.
  Storage schema uses a tagged variant either way; `mosh-server` binds
  loopback either way.
- **D5** Engine is big-Go (mosh-go) via componentize-go, sync sans-I/O
  exports. If the componentize-go spike fails the gate: stop and
  discuss — no automatic TinyGo fallback.
- **D6** Firefox mobile Nightly with the JSPI opt-in flag is an
  accepted target configuration.

## Layout

- `spikes/componentize-go/` — M0 feasibility spikes (sync exports;
  async/goroutine abstraction probes).
- `web/prf-probe/` — M0 WebAuthn PRF capability probe page (deploy to
  the target gh-pages origin; run on Firefox mobile Nightly).
- `wit/` — the `experiment:mosh` engine world (from M1).
- `engine-go/` — the mosh engine component (from M1).
- `host-test/` — native conformance harness: engine under wasmtime
  against stock C `mosh-server` over real UDP (from M1).
- `proxy/` — the native proxy (from M4).
- `web/` — the static client site (from M2).

## Milestones

| # | Deliverable | Gate |
|---|---|---|
| M0 | scaffold; componentize-go spikes; PRF probe; upstream issues filed | componentize-go fails ⇒ stop and discuss; PRF result selects D4 arm |
| M1 | engine WIT + Go impl; native harness vs C mosh-server over UDP | wire compat |
| M2 | browser mosh: xterm.js + engine + throwaway ws-datagram bridge | engine runs under jco in-browser |
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
polymorph-iroh/.deps), headless Chromium 151.

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
