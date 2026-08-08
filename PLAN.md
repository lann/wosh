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
  drain-output, stats). WebAuthn, UI, storage, and bootstrap stay in
  JS; the CBOR control channel moved into the glue (D8, M4).
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

Control channel (D8, resolved 2026-08-08): the first client-opened bi
stream per connection (one ALPN for the whole connection,
`experiment-mosh/0` — a separate `ctl` ALPN was a conflation),
length-prefixed versioned CBOR, implemented in the client-core glue
and proxy-core against the shared `proto/` crate (ciborium both
sides). Messages: hello (pairing token), TOFU state, session
new/list/attach/detach, interim key delivery (M4, removed/demoted in
M7), WebAuthn ceremonies (M6, surfaced as driver-level exports),
ssh/datagram forward setup (M7/M3).

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
  never force migrations. Sub-policy (resolved M6): runtime
  authenticator without `prf` ⇒ **refuse persistence** (the lean arm);
  the `plain` schema arm stays for tests/emergencies. The *sealed*
  seq-floor is the authoritative one at attach — outer fields of a
  proxy-returned escrow are attacker-controlled, and a rolled-back
  floor means OCB nonce reuse (finding 21).
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
  QUIC datagram surface: **DONE upstream** (PR #30, 2026-08-08) —
  `max-datagram-size` (option, capability probe) / `send-datagram`
  (sync, drop-oldest-on-full) / `recv-datagram` (async, accept-family
  concurrency); conformance relay/UDP/WebRTC + RFC 9221 interop vs
  upstream iroh both directions. Ceiling ≈ 1156–1176 B under the
  1200 B profile — engine's ≤ 1138 B fits (finding 14). Finding 9
  (stock server 1252 B) was not addressed: sub-frame in the M4
  forwarder; file a fresh per-path-ceiling issue when concrete.
- A2 [#29](https://github.com/polymorph-components/polymorph-iroh/issues/29)
  injectable/persistable identity: **DONE upstream** (PR #31) —
  identity resource, `identity-generate` / `identity-from-keys`
  (webcrypto handles; crypto-split intact), borrowed into an
  `endpoint-options` resource. Browser persistence stays
  embedder-side (IndexedDB CryptoKey), polymorph-webcrypto#97 additive
  later.
- A3 (external, watch/assist): jco scheduler hardening —
  polymorph-iroh#10, lann/jco#11 (both still open 2026-08-08), plus
  **lann/jco#51** (filed with M5, finding 18): composed-resource TDZ
  at instantiation — fires *before* the scheduler machinery on our
  composed client; minimal repro in `spikes/compose-async-tdz/`. The
  dbad4d7d "all-fixes" pin adds CM-async machinery + composed
  guest-to-guest tests, but componentize-go async-lower is still
  broken under it (finding 14: hang, previously throw) and #51
  reproduces there too. Gates M5 browser E2E, M7 browser ssh, and
  composed-async. Everything before M5 is sequenced to not depend on
  it; `just m5-jco-probe` is the standing unblock detector.

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
driver interface (`client` with `dial` for self-contained use;
`embed.attach` for embedder-owned connections — split so native hosts
can bindgen `client` without resolving fused-away endpoint types).
wac-composes with the engine and endpoint. *(Built — M3, finding 15;
native gate `just m3`.)* The M3-era sub-question is resolved: the
CBOR control channel lives in the glue (D8, M4) — Rust shares
ciborium shapes with proxy-core via `proto/` — with WebAuthn
ceremonies to be surfaced as driver-level events (M6).

**C — proxy**: a thin native Rust shell around the composed
`proxy-core` component (D9) — proxy-core (wasm) owns the accept loop,
control channel, TOFU flow, framed datagram pumps, and the
mosh-server UDP leg over `wasi:sockets`, wac-fused with the endpoint
component; the shell provides `authorize` (TOFU policy + prompt +
`known_clients` persistence), `new-session` (spawn `mosh-server -i
127.0.0.1`), `end-session`, `log`, plus terminal QR (unicode
half-blocks) + connstring `1.<endpoint-id-hex>.<token>.<relay-url>`.
Oversized stock-server datagrams (up to ~1252 B vs the 1162 B iroh
ceiling, finding 9) are sub-framed at the tunnel layer (proto: 1-byte
header, 2-fragment split) — measured live in the M4 gate (finding
16). Detach semantics v0: connection close kills the session;
passkey-gated persistence arrives in M6. *(Built — M4, finding 16;
native gate `just m4`.)*

**D — browser client**: static site, minimal tooling, committed jco
output; bootstrap flows (fragment, qr-scanner, manual entry);
localStorage schema `{v, proxies[], identityRef, sessions[{proxyId,
key: {prf…}|{plain…}, …}]}` with explicit save offers and single-tap
reconnect; consumes the composed client core (B2) — engine⇄endpoint
plumbing lives inside the composition; JS keeps the tick-driving out
only if the composed tick proves unreliable under JSPI. rAF-coalesced
xterm writes; measurements under netem (loss/latency vs prediction
feel) — the thesis findings. *(M5 landed the A3-independent parts:
connstring/storage/idb-keys modules + boot panel, gated by `just m5`
(finding 17); Ed25519 identity persists non-extractable through
IndexedDB; netem matrix ran natively over the M3 gate instead
(finding 19); the composed-core-in-browser leg is blocked on
A3 + lann/jco#51 with `just m5-jco-probe` as the detector (finding
18). Remaining when unblocked: qr-scanner wiring, composed-core page
pump, WebRTC-direct E2E, in-browser prediction-feel measurements.)*

**E — passkeys**: webauthn-rs RP server in the proxy; ceremonies over
the control channel; register on "make persistent" (attestation none,
credential store keyed to the proxy owner); reattach = UV/UP assertion
verifying origin + rpIdHash + challenge, then authorize forwarding and
release the escrowed ciphertext; client evals `prf` in the same get()
and unwraps locally. New-device flow works via synced passkeys
(PRF secret syncs; escrow provides the blob). The escrowed blob is
`{key, seq-floor}`, not the key alone: SSP replay protection plus OCB
nonce-reuse safety require every reattach to resume with a strictly
larger datagram sequence (finding 13) — the engine grows an
initial-sequence connect option and a current-sequence stat with this
milestone; the floor gets a large forward margin on each attach.
*(Built — M6, findings 20–21; native gate `just m6`, browser crypto +
ceremonies in web-tests phase 3. SSP state numbers turned out to be a
second counter that must survive reattach and must be adopted live
from the server rather than escrowed — fork patches 3–4; the engine
forces the post-adopt repaint with a resize dance. D4 sub-policy
resolved: no `prf` ⇒ refuse persistence. Browser↔proxy ceremony E2E
A3-blocked.)*

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
| M2 | browser mosh: xterm.js + engine + throwaway ws-datagram bridge (no iroh) | **DONE** — engine under jco in Chromium; prediction paints locally under latency (findings 12–13) |
| M3 | B2 client-core glue against the merged upstream surface (A1/A2 landed upstream, finding 14); engine+glue+endpoint composed, native wasmtime leg green | **DONE** — finding 15; live datagram ceiling 1162 B; composed-async proven on wasmtime |
| M4 | proxy (QR, TOFU, interim sessions, forwarding incl. 1252 B sub-framing) + native E2E over iroh, driving the **wac-composed client core** under wasmtime | **DONE** — finding 16; wrong-token negative path; sub-framing measured live (6–7 oversized datagrams per bulk run) |
| M5 | browser client proper (identity persistence, bootstrap flows); composed core in-browser; relay then WebRTC-direct E2E; netem measurements | **unblocked parts DONE** (findings 17–19) — modules+panel gated, native netem matrix green to 10% loss; **composed-core-in-browser blocked on A3 + lann/jco#51**; two-component JS orchestration is the recorded fallback |
| M6 | passkeys: ceremonies, PRF wrap + escrow, gated reattach; decide no-prf sub-policy | **DONE** — findings 20–21; `just m6`; state-number adoption + resize dance (fork patches 3–4); no-prf ⇒ refuse persistence; browser ceremony E2E A3-blocked |
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
6. **Composed-async under jco is unproven** (D7): proven on the
   wasmtime path (finding 15 — spawn_local pumps, wait-for tick, async
   cross-component calls all live in the composed core); under jco it
   is now *exercised* and fails **earlier** than the A3 scheduler —
   instantiation-time TDZ on composed resource classes (finding 18,
   lann/jco#51, minimal repro `spikes/compose-async-tdz/`), with the
   scheduler defects (#10/#11) still queued behind it. Goal-aligned
   response happened: minimal repro + upstream issue. Fallback stays
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
