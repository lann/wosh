# wosh

A real SSH session in a browser tab, tunnelled over [iroh][], reaching a
machine with **no inbound port open** and no public address.

That is the point: the target sits behind NAT or a firewall, opens
nothing, and forwards nothing. It makes an outbound connection to a
relay and is reachable by its public key. Nothing is listening on the
internet to be scanned, brute-forced, or caught by the next
`sshd` CVE — and you get to it from a phone by scanning a QR code.

Three WebAssembly components:

- **the listener** (`listener-core`) — a `wasi:cli` component you run on
  the machine you want a shell on. It mints (and persists) an iroh
  identity, binds an endpoint on a relay, prints a connection string as
  a link *and* a terminal QR code, then accepts iroh connections and
  byte-proxies each one to a configured TCP endpoint (your `sshd`).
- **the client** (`wosh-client`, Rust) — runs in the browser under
  [deltic][], and owns everything long-lived: it parses the connection
  string, dials the listener over iroh, pumps bytes, relays signatures
  and prompt batches, and drives an [xterm.js][] UI through a custom
  WIT interface (`wosh:terminal`).
- **the SSH core** (`ssh-core`, Go) — `golang.org/x/crypto/ssh` as a
  sans-I/O byte-and-tick machine behind `wosh:ssh-core`: it performs no
  I/O, holds no keys, and every export is a plain synchronous function.
  The client feeds it wire bytes and answers its two park-and-poll
  surfaces (signature requests, prompt batches).

The listener never sees SSH plaintext: it is a dumb pipe once the
pairing token checks out. The SSH session is end-to-end between the
browser and `sshd`, so the tunnel is network reachability, not a trust
boundary you have to take on faith — the host key you confirm is the
real `sshd`'s, checked through the tunnel, not the listener's.

**Status: the whole chain works.** `just e2e` drives it into a real
OpenSSH `sshd`, authenticated by a non-extractable WebCrypto key;
the client is live at <https://lann.github.io/wosh/>. See "Where this
actually is" for what remains. Experiment-grade code.

## How it fits together

```
BROWSER (deltic)                          TARGET HOST
┌────────────────────────────┐            ┌──────────────────────────────┐
│ xterm.js                   │            │ wosh-listener (native shell) │
│   ↕ wosh:terminal (WIT)    │            │   wasmtime + polymorph hosts │
│ wosh-client (Rust: dial,   │  iroh QUIC │   ┌──────────────────────────┐│
│   pump, signature relay)   │ ─────────► │   │ listener-core (wasi:cli) ││
│   ↕ wosh:ssh-core (WIT)    │ relay /    │   │   + polymorph-iroh       ││
│ ssh-core (Go: sans-I/O     │ webrtc     │   └──────────┬───────────────┘│
│   x/crypto/ssh)            │            │              ▼ TCP            │
│   + polymorph-iroh endpoint│            │                               │
└────────────────────────────┘            │                               │
         └──────────── SSH, end to end ───────────► sshd (127.0.0.1:22)   │
                                          └──────────────────────────────┘
```

The connection string (base64url, carried in the URL fragment so it
stays out of HTTP logs) is a version byte followed by a
[postcard](https://postcard.jamesmunns.com/)-encoded payload: the
listener's 32-byte Ed25519 endpoint id, the relay (either a spelled-out
URL or a varint index into an **append-only table of the public iroh
relays** — indices are never reused, so old QR codes keep meaning the
same relay), and an optional 16-byte pairing token. `connstring/` owns
the format, and is its only decoder: the Rust client links the crate
directly (the previous Go client carried a hand-matched mirror decoder;
the split retired it).

Authentication is SSH's own. The browser mints an **Ed25519 key through
`polymorph:webcrypto` with `extractable: false`**, prints it as an
`authorized_keys` line, and signs with it during publickey auth — the
private half is a capability handle the component can use but never
read, so it survives XSS as use-only. The host key fingerprint is shown
for confirmation *before* any credential is sent; that ordering is
structural, because `x/crypto/ssh` runs authentication strictly after
its host-key callback returns.

A **passkey** can be that key instead. OpenSSH has accepted browser-made
WebAuthn assertions as publickey credentials since 8.4, under the
signature algorithm `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`. The
target needs an ordinary `authorized_keys` line
(`sk-ecdsa-sha2-nistp256@openssh.com …`, the same kind of line a
hardware token gets) and **nothing else installed** — no agent, no
helper. Nothing in the listener participates. What it buys over the
browser key: the private half lives in the platform authenticator
rather than in browser storage, and every signature costs a deliberate
human act — sshd enforces that, rejecting a signature whose
user-presence flag is clear, and `verify-required` in `authorized_keys`
can demand user verification too.

One server-side caveat, and it is a configuration line rather than a
capability: only **OpenSSH 10.3 and later** put that algorithm in the
default `PubkeyAcceptedAlgorithms` (upstream enabled it in February
2026). Every release from 8.4 on can *verify* these signatures, but
8.4 through 10.2 refuse the offer before looking at one — sshd logs
`signature algorithm ... not in PubkeyAcceptedAlgorithms` at
`LogLevel VERBOSE`. On those, add:

```
PubkeyAcceptedAlgorithms +webauthn-sk-ecdsa-sha2-nistp256@openssh.com
```

Without it the client reports *the server did not accept the offered key
(webauthn-sk-ecdsa-sha2-nistp256@openssh.com)*, and sshd at
`LogLevel VERBOSE` says `signature algorithm ... not in
PubkeyAcceptedAlgorithms`. Note that the client's message names the key
rather than whatever method the server steered to afterwards — on a
server that also offers passwords, the refusal arrives as a password
prompt this session cannot answer, and reporting *that* would point at
the wrong thing entirely.

Two consequences of how WebAuthn works, worth knowing. The key's
`application` field is the **site's domain**, not the customary `ssh:`,
because the authenticator signs over `sha256(rp-id)` and sshd rebuilds
that hash from the `application` in `authorized_keys` — so the identity
is stamped with the origin that minted it, and a clone of this page on
another domain cannot use the same line. And because a WebAuthn
assertion does not return the credential's public key (nor is there
anywhere in the credential to stash it: the user handle is fixed at
registration, before the key exists), the public half has to live in
this browser's storage — which a passkey outlives. It outlives being
carried to a second device, and it outlives eviction of the storage
itself, which is a real event and not a hypothetical one: browsers
reclaim IndexedDB from sites you have not visited lately.

The public half is not a secret, so both cures are mundane:

- **Adopt** — paste the same `authorized_keys` line into the other
  device. One touch, which confirms the claim by asserting once before
  storing it. Preferred when the line is to hand.
- **Recover** — work the public key back out of the credential itself.
  ECDSA verification reconstructs a point from a signature's `r`; run
  backwards, one signature narrows the key to a couple of candidates,
  and two assertions from the same passkey have exactly one in common.
  Two touches, and it needs **nothing external** — not the line, not
  the target, not another device — which is what makes it the answer
  when storage went away and the line is only readable from a host you
  can no longer log in to. It reconstructs the *same* key, so the line
  already installed on the target keeps working untouched; both gates
  assert that byte for byte.

Offering both is the default under server-steered `auto`: the passkey
is offered first, each key is offered *unsigned* before any is signed
for, so an sshd that will not take webauthn declines the passkey and
the browser key answers inside the same connection, with no ceremony
spent.

The confirmation can be **remembered, per listener, with an explicit
opt-in checkbox**: the page pins the approved fingerprint keyed by the
listener's endpoint id (the one identity iroh itself authenticates
during the dial), skips the prompt when the same listener presents the
same host key, and warns LOUDLY when it presents a different one. To
make those pins survive restarts, the listener persists its iroh
identity (default `${XDG_DATA_HOME:-~/.local/share}/wosh`, overridable
with `--identity-dir`, disabled with `--ephemeral-identity`); the key
pair rides `polymorph:webcrypto` handles end to end and is stored as
PKCS#8 + raw public key. First contact with an unknown fingerprint is
always confirmed interactively — the pin store can only ever suppress
the prompt for a fingerprint a human explicitly approved.

Pairing is TOFU in the other direction. The browser persists an iroh
**pairing identity** of its own (IndexedDB, via the host's
`pairing-store`), and a client that once presents a valid token is
**enrolled** by endpoint id (`wosh-data/paired`, next to the listener's
key). iroh authenticates that id on every dial, so an enrolled device
keeps reconnecting after the listener restarts and its token rotates —
a printed QR stays valid for the devices that already used it, and
token rotation gates **new** devices only. The stakes are deliberately
low on this outer layer: pairing gates the tunnel, and SSH — the
host-key gate, real authentication — remains the boundary that
matters.

Sessions **survive transport death**. The tunnel (`tunnel/`, protocol
v2) frames the byte streams with cumulative offsets and bounded replay
buffers, so a dropped connection — relay restart, network roam, laptop
sleep — parks the session on the listener (sshd leg held open, default
`--resume-grace 600`) while the client redials with backoff and both
sides retransmit exactly the bytes the other missed. The SSH stack
never notices: the sans-I/O core is simply not told the wire broke
unless the resume window (90s) is exhausted. Both endpoints also
REBIND themselves after a relay restart (an iroh endpoint shares fate
with its relay websocket; the persistent identities are what make the
rebind invisible), and v2 refusals travel as legible errors — a stale
token now says "bad pairing token" at the client instead of silently
dropping.

The page keeps a **connection history** (opt-out checkbox, on by
default; unchecking records nothing and forgets nothing): listener
endpoint id, relay, and user name — **never the pairing token**.
Tapping a recent connection rebuilds a *tokenless* connection string
and dials; it works because this device's pairing enrollment already
vouches for it, which is also what makes a copied history worthless
off-device. Combined with a pinned host key, a remembered connection
is scan-once-tap-forever: open the page, tap, shell — no QR, no
prompt. History rows show `user@endpoint…` and a `key pinned` badge;
the relay and full endpoint id live in the hover detail. Forgetting an
entry is a two-step (arm, confirm) affordance on the row itself, and
does not touch its host-key pin — losing interest in a host and
distrusting its key are different decisions.

## Running it

```sh
scripts/setup.sh          # pins + builds the external chain into .deps/
just web-deps             # xterm + the browser-gate driver (once)
just build                # both components + native hosts
just listener             # SSH to this box via the public iroh relay
just serve                # the site on :8080 (or `just site out/` to deploy)
```

`just listener` exposes 127.0.0.1:22 through n0's public relay; see
`--help` for `--relay`, `--target`, pairing-token and identity options.
It uses the machine's own identity (`~/.local/share/wosh`), and exactly
one listener may hold it — a second fails fast rather than fighting
over the relay registration. For hacking in a checkout, `just
dev-listener` is the same thing with a worktree-local identity, so
several can run at once.

The listener prints a QR code and a link. Open it, confirm the
fingerprint, paste the `authorized_keys` line it shows you, connect.
With the page already open, the connect panel's **scan QR** button
fills the connection string from the camera instead (the platform's
BarcodeDetector where there is one, jsQR everywhere else) — that needs
an https origin or localhost, like every camera on the web; on a plain
http LAN address the button says so. Served over https the site installs as a PWA; over plain http (local development)
the service worker deliberately never registers, so a stale cache
cannot confuse iteration or the browser gate.

## Findings

Measured, not assumed. Each one changed the design.

**1. WASI 0.3.1's async `run` is load-bearing, not a nicety.**
Binding an iroh endpoint suspends across real network I/O. Under the
0.2 `wasi:cli/command` world — whose `run` is synchronously lifted —
that traps outright:

```
wasm trap: cannot block a synchronous task before returning
```

So the listener targets the real **`wasi:cli@0.3.1`** world, whose `run`
is `async func`. `wasmtime-wasi` 47 ships no p3 `Command` helper, so
`listener-host` hand-rolls that bindgen. The guest imports
`wasi:sockets@0.3.1` while wasmtime implements `@0.3.0`; those share the
`@0.3` compatibility track, which is exactly what the linker's name
resolution bridges. Rust's `wasm32-wasip2` target auto-generates the
**0.2** world for a `fn main()`, which is why this only surfaces once
you stop using `main` and export `run` yourself.

**2. Go can call async WIT imports — but only from async-lifted
exports.** Go has no `async`/`await`; componentize-go maps async imports
onto goroutines plus the Component Model callback ABI, so
`monotonic-clock.wait-for` appears as an ordinary blocking Go call. What
matters is how the *export* is lifted:

| export lifting | calling an async import |
| --- | --- |
| sync (`func`) | **traps** (`SubtaskWait` → `unreachable`) |
| async (`async func`) | works |

Both were measured (`spikes/go-async`). The restriction is the ABI's —
a synchronously-lifted task may not block — not a Go limitation.

**3. A never-returning "keepalive" export makes background goroutines
work; without one, they silently lose their task.** This is the subtle
one, and it decides the whole architecture.

componentize-go's async runtime ends a task when the guest goes idle
with no Component-Model waitable outstanding:

```go
} else if len(state.pending) == 0 { return CALLBACK_CODE_EXIT }
```

"Idle with nothing pending" also describes *a goroutine blocked on a Go
channel waiting for a future export call* — so a background goroutine
doing long-lived network I/O has its host task exit out from under it.
Observed as `async-lifted export failed to produce a result` the moment
an SSH handshake parked waiting for credentials.

Compare Rust's wit-bindgen, which keeps the export's root future and
every `spawn_local`'d future in **one set**, and only exits when all of
them finish:

```rust
Poll::Ready(()) => { assert!(me.tasks.is_empty());
                     if me.remaining_work() { Wait } else { Exit } }
Poll::Pending  => { assert!(!me.tasks.is_empty()); ... Wait }
```

There is a sharper corollary, and it cost real debugging time: **an
async-lifted export must never block on an in-language primitive.** The
exit decision is per-task, so an export whose closure is parked on a Go
channel gets declared complete the instant nothing Component-Model
visible is pending *for that task* — never calling task-return, which
surfaces as the same `async-lifted export failed to produce a result`.
The keepalive keeps *background* goroutines running; it cannot rescue a
blocked export closure. Hence the `authenticate-*` calls latch a
credential and resolve at once, `answer-prompts` latches its answers the
same way, and the caller polls `status` — the sans-I/O discipline,
arrived at the hard way.

Findings 2 and 3 eventually reshaped the client outright. The first
working client was one Go component doing its own iroh I/O, living
inside these rules (async-lifted everything, a caller-supplied
keepalive, no export that blocks). The shipped design moves every
long-lived concern into Rust (`wosh-client`), where wit-bindgen's task
tracking makes them legal, and shrinks the Go side to a sans-I/O core
(`ssh-core`) whose exports are all synchronous and whose imports are
none — a component the findings simply cannot reach: no keepalive, no
task-exit races, nothing async to trap. The latch-then-poll contract
survives at the `wosh:terminal` surface because it is a good contract,
not because Go still requires it.

**This is a library-design difference, not a Component Model limit.** A
Rust future is a value the binding owns and can enumerate; a goroutine
is opaque — once you `go f()`, the runtime owns it, and there is no
portable way to distinguish "finished" from "blocked until someone calls
in again". Any language with runtime-managed, opaque concurrency would
hit this; any language where background work is a first-class object the
binding holds (Rust futures, JS promises) would not.

The workaround, measured in `spikes/go-async`: an async export that
never returns, sleeping on an async import in a loop. Its task always
has a pending subtask, so its callback returns `WAIT`, the host keeps
resuming it, and every resume runs *all* runnable goroutines — whose
imports attach to that task.

```
after 600ms with ZERO export calls: bg-count = 20
```

Twenty of twenty background iterations completed with no export call
driving them. **Sharp edge:** this is user-space emulation of a missing
library feature. If that export is ever awaited to completion or
dropped, background I/O stops silently. The clean fix is upstream — a
`witAsync.Spawn` that tracks live background goroutines and returns
`WAIT` while any remain would give Go parity with Rust.

## Layout

- `connstring/` — the pairing format (shared by both ends), with tests.
- `tunnel/` — the tunnel framing (protocol v2): resumable sessions as
  frames + cumulative offsets + bounded replay buffers, one codec
  linked by both Rust ends, with golden-byte tests.
- `webauthn-ssh/` — the WebAuthn-to-SSH wire mapping: a passkey's
  `authorized_keys` line, a browser assertion turned into an OpenSSH
  `webauthn-sk-ecdsa` signature, and the public-key recovery that gets
  an identity back from nothing but two signatures. A crate of its own
  because every rule it enforces is one sshd enforces silently, several
  round trips away, so they are cheaper as unit tests than as failed
  logins.
- `listener-core/` — the `wasi:cli@0.3.1` listener component.
- `listener-host/` — its native shell: wasmtime + the polymorph
  webcrypto/websocket/webrtc host crates + hand-rolled 0.3.1 bindgen.
- `wosh-client/` — the browser SSH client's Rust half, and the
  `wosh:terminal` exporter: connection-string parsing (links
  `connstring/` directly), the iroh dial and pairing frame, the
  never-cancelled reader and single-writer byte pump, and the
  signature relay to the host's `identity-store` and `passkey-store`.
- `ssh-core/` — the Go half: `x/crypto/ssh` as a sans-I/O component
  behind `wosh:ssh-core`. No I/O, no keys, no non-WASI imports; every
  export is a plain synchronous function, and every state change
  happens inside one (feed bytes, tick, answer a parked signature or
  prompt batch). Its engine internals are plain Go with host-runnable
  tests (`ssh-core/core/`) against an in-process x/crypto server.
- `scripts/gate-proc.sh` — the gates' process ownership: background
  processes started under a name and stopped by pid, never by pattern,
  with logs and pidfiles under `.deps/run/` (per worktree). Its own
  self-test is `just test-gate-proc`; `just gates-down` stops whatever
  this worktree left running.
- `smoke-test/` — the end-to-end gate: the composed client under
  wasmtime, over real iroh, through the listener, into a real OpenSSH
  `sshd`.
- `site/` — the static site: xterm.js in front of the client component,
  runtime-linked in-page by deltic. Installable as a PWA: the service
  worker precaches the tree version-keyed, which matters because the
  tree carries ~12 MB of wasm (the component plus deltic's translator)
  and because deltic runtime-links the component against the page
  bundle, so a cache mixing two deploys would be incoherent.
- `host-test/` — browser gates driven by playwright-core against the
  real assembled site.
- `spikes/go-async/` — the three measurements above, as runnable code.
- `wit/` — vendored upstream WIT (polymorph-iroh, polymorph-webcrypto,
  WASI 0.3.1), plus this project's own interfaces.
- `.deps/` — pinned external checkouts and their build outputs, fetched
  by `scripts/setup.sh`. Deliberately inside the repo: `iroh_endpoint.wasm`
  is required to compose either component, so it must not live in a
  scratch directory that can be reclaimed.

## Where this actually is

Verified working:

- The listener, end to end: identity minted through webcrypto, endpoint
  bound on a live relay, connstring + QR + link printed, pairing token
  enforced, and a peer's bytes proxied to a TCP service and back.
- **The whole thing, end to end** (`just e2e`): the browser client
  component under wasmtime obtains its identity's public half from the
  host's `identity-store`, emits an `authorized_keys` line, dials the
  listener over real iroh, verifies the host key fingerprint against
  the real sshd's, authenticates by **publickey with a signature the
  store produces** (no private-key handle exists anywhere in the
  component graph; the sshd's own verification is what judges the
  signature), gets an
  interactive pty, round-trips a command through the tunnel, resizes,
  and detaches cleanly. A second leg does the same via
  `authenticate-auto`: the server steers method selection, and against
  this publickey-only sshd that must resolve to the same silent
  signature flow -- the leg fails if any prompt surfaces.
- **Keyboard-interactive auth** (`just e2e-kbdint`): the same composed
  client answers two server-driven prompt batches (echoed and masked
  prompts, RFC 4256) over the same iroh path and reaches a shell; a
  wrong answer is refused legibly; and an `authenticate-auto` leg
  proves the server steers auto to keyboard-interactive when that is
  all it offers. Runs against a scripted `x/crypto/ssh` stand-in
  server (`kbdint-sshd/`), because a user-mode OpenSSH sshd has no
  keyboard-interactive backend without PAM. This is what PAM OTP/2FA
  setups need; the prompts render in the page with masking honored.
- **Pairing across token rotation** (`just e2e-pairing`): a client that
  once presented a valid token is enrolled by its persistent iroh id;
  after a listener restart rotates the token, the SAME device connects
  with the stale connstring (a printed QR keeps working) while a NEW
  device with that connstring is refused, legibly.
- **Session resume** (`just browser-resume`): a live browser session
  rides out a **relay restart** — the client detects the transport
  death, rebinds its endpoint, redials with backoff and resumes; the
  listener rebinds its accept loop, re-registers under the same
  identity, and replays from the parked session. The page never
  changes state; a post-restart keystroke round-trips. (The listener's
  accept loop previously went permanently deaf on the first relay
  hiccup — found by this gate's drill.)
- All three spike measurements above.
- The site in real headless Chromium (`just browser`): the page loads,
  xterm mounts, deltic instantiates the composed component and runs
  guest code in-page, **the browser's SSH identity survives a page
  reload** (the non-extractable CryptoKey pair persists in IndexedDB,
  so an installed `authorized_keys` line keeps working across visits),
  and the PWA shell is coherent (manifest parsed, icons resolve,
  service worker version-keyed with the component in its precache).
- **The page, live, end to end** (`just browser-e2e`): headless
  Chromium drives the real UI -- form, **interactive host-key
  confirmation** (the prompt must appear and the session parks on it:
  TOFU is asserted, not assumed), the default **auto** method steering
  to publickey with the browser-minted key (silently: no prompt may
  surface), keystrokes round-tripping through xterm to the sshd and
  back, and a rejected fingerprint ending the attempt with nothing
  sent. Plus the whole pinning ladder: approval alone persists nothing
  (opt-in is asserted), approval with "remember" checked skips the
  prompt on the next connect, and a pinned listener presenting a
  DIFFERENT host key gets the loud changed-key warning showing both
  fingerprints.
- **The mobile layer** (`just browser-mobile`): synthesized touch in
  headless Chromium drives the key strip against the page's
  real stylesheet -- a tap types (without taking focus off the
  terminal, which would drop the soft keyboard), a finger that drags
  off a key types nothing, and a sideways flick scrolls the strip
  instead of emitting the key it started on. The bar sits under the
  thumb and its strip scrolls, so press-vs-drag is a live conflict.
  Plus the rule that keeps the keyboard reachable: on a touch device a
  freshly opened page leaves nothing focused, because a focus the page
  took for itself cannot summon a keyboard -- it can only make the
  taps that would look like no-ops. And scrolling, against a real
  xterm: a finger drags the scrollback (or the scrollbar's thumb)
  instead of panning the page, without the drag also landing as a tap
  that summons the keyboard. No other gate can see any of this; the
  e2e legs type through xterm, and none of them synthesize a finger
  that moves.
- Listener identity persistence: the endpoint id (and so the browser's
  pins) survives listener restarts; `--ephemeral-identity` restores the
  old per-run behavior.
- **Gate isolation** (`just test-gate-proc`): stopping one gate's
  process kills that process and nothing else. The gates used to open
  by pkill-ing every `wosh-listener` on the machine — other worktrees'
  gates and the operator's own dev listener included — which is also
  how strays accumulated in the first place (nothing stopped what it
  started). Now each is named, pid-tracked and stopped from a trap,
  test listeners are `--ephemeral-identity` (nothing on disk to share),
  and the logs gates read connstrings from live under `.deps/run/`
  rather than fixed `/tmp` paths two worktrees would clobber. One
  pattern-kill survives on purpose: `browser-resume` restarts the
  RELAY, which is shared machine-wide, so that gate still reaches
  further than its own worktree.

Not finished:

- CI.

## Deploying

`.github/workflows/pages.yml` publishes `site/` to GitHub Pages on every
push to `main`. What ships is the *same* component the gates run --
deltic is a runtime linker, so there is no transpiled variant that could
drift from what was tested.

The listener's `--qr-base` defaults to that deployed client, because the
QR code is the entire bootstrap and it has to point at something a phone
can open. Pass `--qr-base` to aim at your own copy:
`scripts/site-deploy-tree.sh <dir>` produces a tree any static host can
serve, and the whole thing is relative-path clean.

The origin serving the client is part of the trusted computing base, as
it is for any web application: whoever controls it controls the code
that runs. Trust has to start somewhere — with a web client it is the
origin, with a native client it is your package manager and whoever
signed the binary. Neither is free.

What is worth knowing is where that trust *does not* have to extend.
The listener is not trusted: SSH runs end-to-end, so it carries
ciphertext and the host key you confirm is the target `sshd`'s. The
relay is not trusted: it sees QUIC packets between two keys it cannot
read. And the target exposes nothing to the internet at all, which is
the substantive difference from port-forwarding `sshd` and hoping.

If you would rather not depend on this origin,
`scripts/site-deploy-tree.sh <dir>` produces a tree any static host can
serve; the whole thing is relative-path clean and needs no build at the
far end. Note the service worker does not help here — it caches a
version-keyed tree for offline start-up, but it will happily install the
next deploy, so it is a startup and coherency mechanism, not a pin.

## Licence and provenance

Experiment-grade; no stability promised. Built against
[polymorph-iroh][] (the iroh endpoint as a component), [deltic][] (the
JS component host), and `golang.org/x/crypto/ssh`.

[iroh]: https://iroh.computer
[deltic]: https://github.com/lann/deltic
[polymorph-iroh]: https://github.com/polymorph-components/polymorph-iroh
[xterm.js]: https://xtermjs.org
