# Plan: experiment-mosh

The full working plan as settled by design discussion (2026-08-07).
Durable companions: `README.md` (architecture summary, decision log,
findings — the experiment record) and `TASK.md` (resumable session
state). This file is the complete plan; update it when a decision or
milestone changes shape, not for routine progress.

## Goal

A mosh-compatible client and proxy that tunnel over iroh:

- Client runs in JSPI-enabled browsers, xterm.js front end, wasm
  components for the protocol engines.
- Proxy is a native binary on (or near) the target host; displays a QR
  code + connection string in the terminal for bootstrap.
- Steady state is real mosh SSP — wire-compatible with stock
  `mosh-server` — over unreliable iroh QUIC datagrams, end-to-end
  encrypted (AES-OCB) between browser and mosh-server.
- The outer iroh layer is *secondary network access control*; the inner
  ssh/mosh layer is the strong security boundary (end state).

## Bootstrap and session UX (requirements, refined)

- QR encodes `https://<site>/#<connstring>`; the same string works via
  in-browser QR scan (nimiq/qr-scanner: BarcodeDetector fast path,
  camera fallback) or manual entry. Fragment keeps the string out of
  HTTP logs.
- Connection string: version ‖ proxy endpoint-id (32B Ed25519) ‖ relay
  ref (well-known-relay index or explicit URL) ‖ short-lived pairing
  token, base64url. Exact format designed in M5.
- TOFU: unknown client peers presenting a valid pairing token trigger a
  manual accept prompt on the proxy terminal; both sides display both
  endpoint pubkeys for cross-check. Unknown peers without a token are
  silently rejected (prompt-fatigue defense). Known peers connect
  without ceremony.
- localStorage saves proxy peer details (and the client identity
  reference) after an explicit "save" offer; saved proxies get
  single-tap reconnect.
- Passkey (proxy = WebAuthn RP server; RP ID = the static site's
  registrable domain, e.g. `lann.github.io` — valid per PSL; bare
  `github.io` is not): on new session, offer to make it persistent via
  new or existing passkey. Reattach to a live session requires a
  user-presence (UV preferred) assertion. Detach without a passkey
  binding kills the session; with one, the session persists (idle
  timeout configurable).
- v0 session model: one attached session per iroh connection;
  multi-session later (mosh-go's latch extensions are prior art, our
  control channel is the natural home).

## Architecture

```
BROWSER (JSPI)                                   PROXY HOST (native Rust)
┌──────────────────────────────┐                 ┌────────────────────────────────┐
│ JS: xterm.js, QR scan,       │   iroh QUIC     │ terminal UI: QR + connstring,  │
│ WebAuthn, storage, ctl chan  │  (RPK TLS,      │ TOFU prompts                   │
│ ┌──────────────────────────┐ │   both peers    │ webauthn RP · session registry │
│ │ client core (wac-composed│ │   pinned)       │ ┌────────────────────────────┐ │
│ │  mosh engine (Go, sync)  │ │ ──────────────► │ │ wasmtime + polymorph-iroh  │ │
│ │  ⇄ glue (Rust: dgram     │ │  relay / webrtc │ │ endpoint component         │ │
│ │  pump + tick, async)     │ │  / udp          │ └────────────────────────────┘ │
│ │  ⇄ polymorph-iroh        │ │                 │ forwarders:                    │
│ │  endpoint (JSPI, async)  │ │                 │  QUIC dgram ↔ UDP 127.0.0.1    │
│ └──────────────────────────┘ │                 │  QUIC stream ↔ TCP :22 (ssh)   │
└──────────────────────────────┘                 │ spawns: mosh-server -i 127.0.0.1│
                                                 └────────────────────────────────┘
```

Layering, steady state:

    mosh SSP (AES-128-OCB, e2e browser↔mosh-server)
      over QUIC datagrams                    ssh (e2e browser↔sshd) [M7]
        over the iroh QUIC connection (RPK TLS, both peers pinned)
          over relay websocket / WebRTC data channel / UDP

Composition ruling (D7, revised 2026-08-07): the client's wasm pieces
are **wac-composed into one client-core component** rather than
JS-orchestrated — advancing the component-model way of doing things is
a standing secondary goal of the polymorph project, and the composed
core buys a real capability: the *whole client core* runs headless
under wasmtime for native conformance (M4). The decomposition keeps
M0/M1's risk isolation intact:

- **engine** (componentize-go, unchanged from M1): pure sync sans-I/O
  `session` resource, zero non-wasi imports. Every existing harness
  and the M2 browser smoke keep driving it directly.
- **client-core glue** (Rust, small): imports the engine's session
  surface and the #28 datagram surface; owns the only async parts —
  the recv-datagram loop and a `wasi:clocks` `wait-for` tick; exports
  a compact driver interface (attach connection + key/size, feed-keys,
  drain-output, stats). WebAuthn, UI, storage, bootstrap, and (at
  least initially) the CBOR control channel stay in JS.
- send needs no async anywhere: #28's `send-datagram` is sync by
  design, and sync-import-from-sync-export is legal.

Composition mechanics are proven (finding 11): a sync Rust adapter
wac-plugged with the engine passes cross-component statics, resource
construct/method/drop, results, and nested-list transfer under
wasmtime, jco/node, and jco/browser on the pinned fork. What remains
unproven is composed *async* under jco — the glue's recv/tick imports
ride exactly the A3 scheduler hardening that already gates the
endpoint's browser leg (no new blocker, more surface on the same one).
Fallback if composed-async-under-jco stalls beyond A3: JS orchestrates
the two components separately — the engine surface is unchanged, so
the fallback stays permanently cheap.

Control channel: one bi stream per connection, ALPN
`experiment-mosh/ctl/0`, versioned CBOR (ciborium / cbor-x). Messages:
hello (pairing token), TOFU state, session new/list/attach/detach,
interim key delivery (M4, removed/demoted in M7), WebAuthn ceremonies
(M6), ssh/datagram forward setup (M7/M3).

## Security model

- **Outer (iroh)**: mutual Ed25519 authentication (key = address; RPK
  TLS), device binding via TOFU + manual accept, pairing token against
  connect-spam. Browser identity key is non-extractable WebCrypto
  (survives XSS as *use-only*, never exfiltratable).
- **Inner (ssh + mosh, M7 end state)**: session creation gated by OS
  credentials against sshd through a forwarded stream; the proxy drops
  out of the authentication TCB, runs unprivileged, and never sees
  mosh keys. Defense-in-depth against the young outer stack
  (noq-proto/polymorph-tls/relay/webcrypto bridges) and against our own
  control-plane bugs (cross-session datagram misrouting fails closed on
  OCB keys).
- **Interim mode (M4, kept long-term as "personal mode")**: proxy runs
  as the target user, spawns `mosh-server -i 127.0.0.1` (loopback bind
  mandatory — a leaked mosh key must not be usable off-host), hands the
  key over the TOFU-gated control channel. Explicitly outer-layer-only
  security; acceptable for single-user personal hosts, not the default
  posture once M7 lands.
- **Mosh key at rest (D4, resolved — PRF arm)**: the key is wrapped
  with a key derived from the WebAuthn `prf` extension output
  (fixed-salt eval on the session's passkey) and the **ciphertext is
  escrowed on the proxy**. Properties: key at rest is useless without a
  user-presence ceremony; synced passkeys give multi-device reattach;
  the proxy never sees plaintext. Storage schema keeps a tagged variant
  (`{prf: {credId, salt, iv, ct}} | {plain: …}`) so policy changes
  never force migrations. Open sub-policy (decide in M6): runtime
  authenticator without `prf` ⇒ refuse persistence (lean) vs
  plaintext-with-warning.
- **Trusted computing base, honestly**: the static-site origin serves
  the client code — its compromise owns new sessions regardless of
  layering (SRI/self-host hardening is future work). Passkey RP ID is
  that origin, so WebAuthn results and credentials are origin-scoped.
  Field reality: password managers wrap `navigator.credentials` and
  can break ceremonies (M0 finding 6) — the client must call prototype
  methods and surface interference legibly.

## Workstreams

**A — upstream polymorph-iroh** (issue-first per its AGENTS.md; branches
in the sibling checkout; conformance is the gate):

- A1 [#28](https://github.com/polymorph-components/polymorph-iroh/issues/28)
  QUIC datagram surface: `max-datagram-size` / `send-datagram` (sync,
  drop-on-full) / `recv-datagram` (async) on `connection`; pump plumbing
  for `DatagramReceived`/`DatagramsUnblocked` in both endpoint impls.
  noq-proto already ships RFC 9221 and endpoints already advertise it.
  ~1162 B application ceiling under the fixed 1200 B MTU profile (mosh
  fragments at ~500 B — fits). Native legs first; jco leg rides #10.
- A2 [#29](https://github.com/polymorph-components/polymorph-iroh/issues/29)
  injectable/persistable identity: optional identity reference in
  `endpoint-options`; private key stays behind the webcrypto boundary
  (crypto-split invariant). Browser persistence (IndexedDB CryptoKey,
  load-or-generate-by-name) likely lands as a polymorph-webcrypto
  surface PR that this consumes.
- A3 (external, watch/assist): jco scheduler hardening —
  polymorph-iroh#10, lann/jco#11, PR #27. Gates M5 browser E2E and M7
  browser ssh. Everything before M5 is sequenced to not depend on it.

**B — engine**: `experiment:mosh` WIT world (sync `session` resource:
`feed-keys`, `resize`, `handle-datagram`, `tick -> list<datagram>`,
`drain-output`, `stats`); Go implementation wrapping mosh-go
`DialConnRaw` + an in-memory `Conn` (Write→outbox drained by tick,
Read→inbox pop or immediate timeout); prediction/output handling
cribbed from mosh-go `cmd/mosh-wasm/state.go`. mosh-go is a vendored
fork at the pinned rev (`.deps/mosh-go`, MIT): wasm build-tag +
fragment-size patches applied, ledger in its `DEPS.md`. *(Built — M1.)*

**B2 — client-core glue (Rust)**: the composition seam of D7. Imports
the engine's `session` interface and the #28 datagram surface; owns
the recv-datagram loop and the `wait-for` tick; exports the client
driver interface JS talks to (attach connection+key+size, feed-keys,
resize, drain-output or output notification, stats, detach).
wac-composes with the engine (mechanics proven, finding 11; sync
adapter spike in `spikes/compose/`). Native-first: composed core under
wasmtime is M4's E2E vehicle; the browser composed leg rides A3 (M5).
Open sub-question (decide by M5): move the CBOR control channel from
JS into the glue — Rust shares ciborium shapes with the proxy — with
WebAuthn ceremonies surfaced as driver-level events.

**C — proxy**: Rust binary embedding wasmtime + the endpoint component
(reuse polymorph-iroh host-wasmtime patterns; relay + UDP +
WebRTC-direct all work natively). Terminal QR (unicode half-blocks) +
connstring; TOFU store (`known_clients`) + accept prompts; session
registry; per-session loopback UDP socket, QUIC-datagram↔UDP pump;
detach semantics (kill vs persist per passkey binding). Forwarder must
handle stock mosh-server datagrams up to ~1252 B (> the ~1162 B iroh
ceiling, finding 9): tunnel-layer sub-framing of oversized datagrams,
or a larger negotiated datagram size on non-UDP paths (#28 design
input) — decide in M3/M4.

**D — browser client**: static site, minimal tooling, committed jco
output; bootstrap flows (fragment, qr-scanner, manual entry);
localStorage schema `{v, proxies[], identityRef, sessions[{proxyId,
key: {prf…}|{plain…}, …}]}` with explicit save offers and single-tap
reconnect; consumes the composed client core (B2) — engine⇄endpoint
plumbing lives inside the composition; JS keeps the tick-driving out
only if the composed tick proves unreliable under JSPI. rAF-coalesced
xterm writes; measurements under netem (loss/latency vs prediction
feel) — the thesis findings.

**E — passkeys**: webauthn-rs RP server in the proxy; ceremonies over
the control channel; register on "make persistent" (attestation none,
credential store keyed to the proxy owner); reattach = UV/UP assertion
verifying origin + rpIdHash + challenge, then authorize forwarding and
release the escrowed ciphertext; client evals `prf` in the same get()
and unwraps locally. New-device flow works via synced passkeys
(PRF secret syncs; escrow provides the blob).

**F — inner ssh**: proxy stream-forward pinned to `127.0.0.1:22`;
engine grows an ssh mode (x/crypto/ssh over an imported stream;
password auth v0; hostkey TOFU in client storage; parse `MOSH CONNECT`
in-component and start SSP internally). Proxy deprivileges in this
mode; interim key-delivery becomes a flagged personal mode. M0 findings
constrain the shape: on wasmtime, goroutine concurrency over async
imports is confirmed, but Go-*native* timers inside async exports trap
(patched-Go limitation) — x/crypto/ssh's internal `time.After` use
needs auditing/shimming; on jco, `[async-lower]` imports are broken
until the fork hardens (travels with A3). Directional last step:
unextractable WebCrypto ssh key via a WIT-imported signer (needs an
async export, per finding 3b).

## Milestones

| # | Deliverable | Gate / status |
|---|---|---|
| M0 | scaffold; componentize-go spikes; PRF probe; upstream issues | **DONE** — D5 PASSED (findings 1–5); D4 → PRF arm (finding 6); #28/#29 filed |
| M1 | engine WIT + Go impl; native harness vs stock C mosh-server over UDP | **DONE** — wire compat incl. multi-fragment paste (findings 7–10); our datagrams ≤ 1138 B; stock server emits up to 1252 B (> ceiling, → M4 forwarder design) |
| M2 | browser mosh: xterm.js + engine + throwaway ws-datagram bridge (no iroh) | engine under jco in a real browser; composition not required for this gate |
| M3 | A1 datagram PR upstream, native legs green; client-core glue starts against it | upstream conformance |
| M4 | proxy (QR, TOFU, interim sessions, forwarding) + native E2E over iroh, driving the **wac-composed client core** (engine+glue+endpoint) under wasmtime | composed core passes the M1 conformance suite over iroh |
| M5 | A2 identity PR + browser client proper; composed core in-browser; relay then WebRTC-direct E2E; netem measurements | **blocked on A3** for the browser endpoint leg (composed or not); two-component JS orchestration is the recorded fallback |
| M6 | passkeys: ceremonies, PRF wrap + escrow, gated reattach; decide no-prf sub-policy | |
| M7 | inner ssh; proxy deprivileged; interim demoted to personal mode | ssh-in-component shape per findings 2–4 |

Every milestone appends findings to README.md (findings-first culture);
gates that stop the plan stop it into discussion, not silent fallback
(D5 rule).

## Risks

1. **A3 stalls** (external jco hardening) → M5/M7 browser legs slip;
   native path and M0–M4 unaffected by construction; assist upstream.
2. **mosh-go fidelity edge cases** → M1 conformance harness against the
   C implementation is the gate; MIT license permits vendored fixes
   (exercised: `.deps/mosh-go` fork carries the wasm build-tag and
   fragment-size patches; client-must-resize-first fixed engine-side;
   two open observations in finding 10 — leg-b scroll artifact, RTO
   clamp 10 s vs C mosh's 1 s).
3. **ssh-in-component** → Go-native-timer trap and jco async-lower gap
   (findings 3–4); contingencies: shim timers via explicit
   `wait-for`-based helpers, russh sidecar component, or defer browser
   ssh behind A3 while wasmtime-side lands.
4. **Moving targets**: Firefox Nightly flag, patched Go (upstreaming as
   golang/go#76775), jco fork — pin what's tested, record versions in
   findings (done for M0).
5. **Extension interference with WebAuthn** in the field (finding 6) —
   client UX must detect and explain, as the probe now does.
6. **Composed-async under jco is unproven** (D7): composition
   mechanics are green sync-only (finding 11), but the glue's async
   recv/tick imports inside a wac composition may surface jco defects
   beyond the known A3 set once exercised (M5). Goal-aligned response:
   minimal repro + upstream issue, as with #10/#11. Fallback stays
   cheap by construction: the engine's sync surface is unchanged, so
   JS two-component orchestration remains a drop-in.

## References

- mosh-go: https://github.com/unixshells/mosh-go (`Conn`, `DialConnRaw`,
  `ServeRW`, latch extensions)
- componentize-go: https://github.com/bytecodealliance/componentize-go
  (v0.4.1; async worlds auto-install patched Go)
- polymorph-iroh: issues #3 (surface design), #10 (jco scheduler),
  #28 (datagrams), #29 (identity); AGENTS.md conventions;
  lann/wasm-component-starter OUTLINE.md (CM/WASI knowledge base)
- Deployed probe: https://lann.github.io/prf-probe/
