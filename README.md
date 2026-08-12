# wosh

A real SSH session in a browser tab, tunnelled over [iroh][], reaching a
machine with **no inbound port open** and no public address.

That is the point: the target sits behind NAT or a firewall, opens
nothing, and forwards nothing. It makes an outbound connection to a
relay and is reachable by its public key. Nothing is listening on the
internet to be scanned, brute-forced, or caught by the next
`sshd` CVE — and you get to it from a phone by scanning a QR code.

Two WebAssembly components:

- **the listener** (`listener-core`) — a `wasi:cli` component you run on
  the machine you want a shell on. It mints an iroh identity, binds an
  endpoint on a relay, prints a connection string as a link *and* a
  terminal QR code, then accepts iroh connections and byte-proxies each
  one to a configured TCP endpoint (your `sshd`).
- **the client** (`client-go`) — runs in the browser under [deltic][],
  takes a connection string, dials the listener over iroh, and speaks
  SSH end-to-end to the target's `sshd` over the proxied stream. It
  drives an [xterm.js][] UI through a custom WIT interface
  (`wosh:terminal`).

The listener never sees SSH plaintext: it is a dumb pipe once the
pairing token checks out. The SSH session is end-to-end between the
browser and `sshd`, so the tunnel is network reachability, not a trust
boundary you have to take on faith — the host key you confirm is the
real `sshd`'s, checked through the tunnel, not the listener's.

**Status: both components work.** `just e2e` drives the whole chain into
a real OpenSSH `sshd`, authenticated by a non-extractable WebCrypto key;
the client is live at <https://lann.github.io/wosh/>. See "Where this
actually is" for what remains. Experiment-grade code.

## How it fits together

```
BROWSER (deltic)                          TARGET HOST
┌────────────────────────────┐            ┌──────────────────────────────┐
│ xterm.js                   │            │ wosh-listener (native shell) │
│   ↕ wosh:terminal (WIT)    │            │   wasmtime + polymorph hosts │
│ client-go (x/crypto/ssh    │  iroh QUIC │   ┌──────────────────────────┐│
│   over an iroh net.Conn)   │ ─────────► │   │ listener-core (wasi:cli) ││
│   + polymorph-iroh endpoint│ relay /    │   │   + polymorph-iroh       ││
│   + polymorph-iroh endpoint│ webrtc     │   └──────────┬───────────────┘│
└────────────────────────────┘            │              ▼ TCP            │
         └──────────── SSH, end to end ───────────► sshd (127.0.0.1:22)   │
                                          └──────────────────────────────┘
```

The connection string (base64url, carried in the URL fragment so it
stays out of HTTP logs) is: version, the listener's 32-byte Ed25519
endpoint id, a flag byte, an optional 16-byte pairing token, then the
relay URL. `connstring/` owns the format and round-trip-tests it.

Authentication is SSH's own. The browser mints an **Ed25519 key through
`polymorph:webcrypto` with `extractable: false`**, prints it as an
`authorized_keys` line, and signs with it during publickey auth — the
private half is a capability handle the component can use but never
read, so it survives XSS as use-only. The host key fingerprint is shown
for confirmation *before* any credential is sent; that ordering is
structural, because `x/crypto/ssh` runs authentication strictly after
its host-key callback returns.

## Running it

```sh
scripts/setup.sh          # pins + builds the external chain into .deps/
just web-deps             # xterm + the browser-gate driver (once)
just build                # both components + native hosts
just listener             # SSH to this box via the public iroh relay
just serve                # the site on :8080 (or `just site out/` to deploy)
```

`just listener` exposes 127.0.0.1:22 through n0's public relay; see
`--help` for `--relay`, `--target`, and pairing-token options.

The listener prints a QR code and a link. Open it, confirm the
fingerprint, paste the `authorized_keys` line it shows you, connect.
Served over https the site installs as a PWA; over plain http (local
development) the service worker deliberately never registers, so a
stale cache cannot confuse iteration or the browser gate.

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
blocked export closure. Hence `authenticate-password` and
`authenticate-publickey` latch a credential and resolve at once, and the
caller polls `status` — the sans-I/O discipline, arrived at the hard
way.

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
- `listener-core/` — the `wasi:cli@0.3.1` listener component.
- `listener-host/` — its native shell: wasmtime + the polymorph
  webcrypto/websocket/webrtc host crates + hand-rolled 0.3.1 bindgen.
- `client-go/` — the browser SSH client, one Go component:
  `x/crypto/ssh` over a real `net.Conn` wrapping an iroh bi stream,
  exporting `wosh:terminal`. No glue component and no sans-I/O
  shuttling — componentize-go surfaces the endpoint's async WIT methods
  as ordinary blocking Go calls, so it reads like a normal networked Go
  program.
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
  component under wasmtime mints its non-extractable WebCrypto key,
  emits an `authorized_keys` line, dials the listener over real iroh,
  verifies the host key fingerprint against the real sshd's,
  authenticates by **publickey with a signature produced by that
  WebCrypto key**, gets an interactive pty, round-trips a command
  through the tunnel, resizes, and detaches cleanly.
- All three spike measurements above.
- The site in real headless Chromium (`just browser`): the page loads,
  xterm mounts, deltic instantiates the composed component and runs
  guest code in-page, and the PWA shell is coherent (manifest parsed,
  icons resolve, service worker version-keyed with the component in its
  precache).

Not finished:

- The page has not yet been driven through a full live session in a
  browser: `just browser` proves the component loads and runs guest
  code in-page, and `just e2e` proves the same component completes a
  real SSH session, but nothing yet asserts the two together.
- Host-key pinning across visits (the fingerprint is confirmed every
  time), and any persistence of the browser's identity — it is minted
  fresh per instance today.
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
