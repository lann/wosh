# Task state

Point-in-time working state for resuming this effort. The full plan is
`PLAN.md`; the design record and findings live in `README.md`; this
file says where work stopped and what comes next. Update it at the end
of each session.

## Status: DELTIC CUTOVER COMPLETE — browser leg live (2026-08-10)

2026-08-11, end of session — DIRECTION SHIFT (owner conversation) +
a spike in flight; read this first when resuming:

1. **Owner verdict: mosh UX is not good enough — local echo
   specifically ("just doesn't work well").** Direction under
   consideration: replace mosh with plain-SSH-carried sessions. The
   recommended phasing (discussed, owner did not object): (a) an
   interactive ssh mode ALONGSIDE mosh — the "interactive-shell
   fallback" that TASK previously parked "awaiting a concrete need"
   now has its need; reuses the M7 forwarded-stream plumbing +
   finding-30 flow; gives scrollback and full xterm.js fidelity
   (mosh's server-side emulator is the ceiling: no scrollback, eats
   OSC 52/images); (b) persistence via `tmux new -A` at first; if
   that offends, a small resume daemon (pty + ring buffer +
   seq-resume) spoken INSIDE an ssh exec channel — D2 preserved by
   ssh crypto, no new cryptography; (c) keep mosh as the bad-network
   mode until `m5-netem` grows an ssh-mode column and MEASURES the
   stream HOL-blocking cost vs SSP under the same delay/loss cells.
   None of this is started.

2. **webauthn-ssh publickey auth is the owner's killer feature**
   (happy path; password/other methods stay supported). This
   upgrades issue #8 from WebCrypto-key to passkey. SPIKE AUTHORIZED
   AND IN FLIGHT — facts pinned so far (env + upstream source), no
   spike code written yet:
   - Local sshd is OpenSSH 10.0p2; `ssh -Q sig` lists
     `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`.
   - x/crypto v0.49.0: `KeyAlgoSKECDSA256` is in the supported
     pubkey-auth algos, and client_auth marshals the
     `Signature{Format,Blob,Rest}` a custom Signer returns — so
     pkalg `sk-ecdsa-…` with sig format `webauthn-sk-…` should pass
     through unpatched (if a strict Format check bites anywhere,
     it's a ~3-line vendored shim).
   - PROTOCOL.u2f: authorized_keys holds a plain sk-ecdsa pubkey
     blob whose `application` is the web RP ID (browser credentials
     can't mint `ssh:`); webauthn sig wire = format string,
     ecdsa_signature (mpint r, mpint s), flags u8, counter u32,
     origin string, clientData string, extensions string.
   - ssh-ecdsa-sk.c verify semantics (the details that make or
     break the client): clientData is checked by PREFIX match
     against `{"type":"webauthn.get","challenge":"<b64url>",
     "origin":"<origin>"` — the challenge is the UNPADDED base64url
     of the RAW ssh signed blob (session id + userauth request),
     NOT a hash of it ⇒ the WebAuthn get() challenge must be the
     raw blob bytes (the browser base64urls it); crossOrigin and
     trailing clientData fields are ignored; origin must contain no
     `"`; flags: AD (0x40) must be clear, ED (0x80) set iff the
     extensions field is non-empty; signed payload reconstructed as
     SHA256(application) || flags || counter || extensions ||
     SHA256(clientData), ECDSA/SHA-256; the webauthn key impl is
     sigonly=1 over KEY_ECDSA_SK (confirms the pkalg/sig pairing).
   - NEXT (the actual spike, ~a day): `spikes/webauthn-sshd/` — Go
     client with a soft-WebAuthn P-256 signer (hand-built
     clientDataJSON; no authenticator hardware), custom ssh.Signer
     (PublicKey().Type() = sk-ecdsa-…; Sign returns Format
     webauthn-sk-…, Blob = ecdsa sig, Rest = flags || counter ||
     origin || clientData || extensions), authorized_keys line
     generation, unprivileged sshd on a loopback high port
     (current-user login, publickey-only), assert handshake + exec.
     Probe whether stock `PubkeyAcceptedAlgorithms` accepts it
     unconfigured; pin the sshd version floor (8.3-era claim).
   - AFTER the spike: reshape #8 around it — engine sign gate via
     the finding-30 park/resume pattern (status `sign-request` +
     provide-signature, exactly like the host-key gate), ceremony
     from the page (M6 machinery + CDP virtual authenticator for
     the gate), and the m7 gate grows a REAL-sshd leg (the russh
     stand-in almost certainly cannot verify webauthn sigs —
     verify). Payoff worth restating: assertion binds to the ssh
     session id (channel binding — unphishable, unlike the
     password), the proxy exits the RP business, one
     authorized_keys line works on every host. TCB note: passkey
     sync provider becomes an authorized-key holder; device-bound
     attestation at registration is the opt-out.

3. **Local-echo complaint is UNDIAGNOSED — open question: our bug
   or mosh's design?** Known so far (findings 12/19 + m2 numbers):
   mosh-go's predictor engages on ANY printable keystroke with no
   RTT-adaptive gating and resets on control chars (C mosh gates
   display on SRTT/glitch triggers and confirms epochs before
   un-tentative display — the port may lack the adaptive/confirm
   machinery wholesale); the 10 s RTO clamp (finding 10b/19) is a
   separate stall. m2 measures ~130-140 ms to paint a 9-char burst
   (~40-50 ms/char through feedKeys → pump → rAF) — the in-page
   pipeline deserves profiling too. NEXT: diff
   `.deps/mosh-go/predict.go` against C mosh `terminaloverlay.cc`
   (display gating, epochs, confirmation, cursor predictions), and
   instrument per-keystroke paint latency on the real page. If the
   verdict is "port gaps", it feeds the fork-patch list (DEPS.md);
   if "inherent", it strengthens the plain-ssh pivot.

PR state at hand-off: #20 (finding 30) and #22 (m1 flake fix)
MERGED; **#23 (CI tiering + unit-test extraction) OPEN and green —
this TASK update rides it.** After #23 merges, the first main push
seeds the per-shard caches; PRs restore warm from then on.

2026-08-11 addendum: the client now deploys to GitHub Pages on every
main merge (since gated on the CI gates; `.github/workflows/ci.yml`;
repo went public), `just
proxy-personal` runs the proxy against n0's public relays with QR/RP
defaults pointing at the Pages client, and every finding-24 browser
follow-up landed: the **WebRTC upgrade leg** (finding 27,
m5-browser-e2e hard-asserts the relay→webrtc move), the **M6 browser
ceremony leg** (finding 28, `just m6-browser`: persist/reattach from
the real page against the real RP, PRF wrap/unwrap in-page,
floor-jump re-escrow per reattach), and the **M7 in-page ssh leg**
(finding 29, `just m7-browser`: ssh UX in the panel, TOFU host-key
pin, tampered pin refused before the password leaves the page).

Post-cutover pin bump (same day, finding 26): deltic @ a18be734
(includes the hop-atomicity fix lann/deltic#82 our M2 gate found, the
timer re-arm #78, smoke-c0 path fix #79), polymorph-iroh @ d8fdd039
(their jco host retired #40, parking kernel adopted #43, event-driven
endpoint wakeups #44 — the jco-era polling latency workaround is
gone). One wosh-side fix rode along: drive_ssh drains to quiescence
on exit-status (exit can beat the final stdout through the engine's
buffers under the new arrival coalescing).

2026-08-11, latest: CI tiered (the serial 44-minute gates job is
gone). Measured on that job: gate RUNTIME was ~2 min; ~36 min was
four cold cargo builds of the wasmtime-embedding harnesses. New
layout (`.github/workflows/ci.yml` + the wosh-setup composite
action): `unit` (proto cargo tests + web-tests — now including a
first-contact-ssh panel phase 4 with fake handlers, and
parse-mosh-connect moved to proto with unit tests), three native
gate shards split by cargo-build cluster (engine=spikes+m1+m3,
proxy=m4, sessions=m6+m7) with PER-SHARD rust caches and
cache-on-failure (a gate flake no longer throws the build away —
the old cache never landed on main because of exactly that), and
the browser legs on main pushes + nightly cron + the
`browser-gates` PR label. Deploy gated on all tiers. The e2e gates
remain the source of truth (finding 30 alone: three bugs only they
could catch); the tiers changed their cost, not their authority.

2026-08-11, later: issue #7 landed (finding 30) — TRUE first-contact
ssh now parks at the host-key gate and the page confirms the
fingerprint BEFORE the password moves (two-phase `ssh-flow`; engine
password deferred; `just m7` grew flow decline/confirm phases,
`just m7-browser` grew the prompt/decline/confirm legs). Full gate
suite swept green. Also fixed en route: a pre-existing torn-buffer
race on the ssh exec output (engine `lockedBuf`).

This session (owner instruction: "rebuild, replacing jco with
lann/deltic; update all polymorph dependencies") replaced the JS host
wholesale and shipped the previously A3-blocked browser leg:

- **jco is gone.** deltic (runtime linker, Deno + browsers) hosts
  every JS-side component: M1 conformance (Deno lane), M2 browser
  smoke, all three spikes (single deltic leg each; the jco node +
  browser legs retired — the real M2/M5 gates cover browsers with the
  actual workload). No transpile step, no generated trees, no JSPI
  flag. Root `deno.json` = the one import map; `deno.lock` + npm deps
  via `deno install --allow-scripts=npm:node-datachannel` (setup.sh).
- **Pins.** `.deps/polymorph-iroh` → f46a80df (deltic-leg merge; its
  nested webcrypto/websocket/webrtc pins carry the deltic host
  modules). NEW `.deps/deltic` clone; translator shim built there by
  setup.sh (`just _translator` prints the path; recipes export
  DELTIC_TRANSLATOR). One mechanical native rename rode the bump:
  `WasiWebrtc*` → `Webrtc*` in the wasmtime-impl types (5 files).
- **Browser leg (finding 25):** `just m5` = m5-web + m5-client-deno
  (composed client on the Deno lane vs real proxy) + m5-browser-e2e
  (headless Chromium drives the real page: `/#connstring` → panel
  connect → prompt/echo/resize/stats/detach; wrong-token negative
  first). `web/deltic-entry.ts` → `just web-bundle` →
  `web/dist/deltic.js`; app.mjs has two modes (bridge M2 / iroh M5,
  `connectIroh`); boot.mjs connects for real (pending row has the
  token; saved proxies prompt — tokens deliberately not persisted).
- **Upstream deltic defect found + fixed (finding 25):** FACT callee
  callback re-entries weren't promising-wrapped → `SuspendError` when
  the composed endpoint's `block_on(webcrypto sign)` hit
  `waitable-set.wait` mid-activation. Fixed in lann/deltic#70
  (merged) with a composed-wat regression fixture; wosh pins a rev
  including it.
- **Embedder path policy:** `WOSH_UDP=off` (guest env, no WIT change)
  makes the glue skip the endpoint's UDP bind — required in browsers
  where `wasi:sockets` is the fail-on-call stub profile. Native
  harnesses unchanged (default on).

## Pending / open (carried)

- **RefCell borrow hazard** (endpoint guest, upstream-documented):
  never fired in our gates (connects at attempt 1), but
  browser-e2e.mjs keeps an 8-attempt budget. If it starts firing,
  that's upstream polymorph-iroh work (their issue tracker).
- Finding 10 follow-ups: leg-b scroll artifact; predictor not
  RTT-adaptive; RTO clamp 10 s measured live (finding 19) — fork
  patch to C mosh's [50 ms, 1 s] if long sessions stall on idle
  recovery. NOW ELEVATED: the local-echo experience is the owner's
  top complaint — see the status addendum item 3 for the diagnosis
  plan (predict.go vs terminaloverlay.cc diff + in-page paint
  profiling) before any protocol decision.
- **mosh replacement direction (owner, this session)**: interactive
  plain-ssh mode alongside mosh, tmux-then-maybe-resume-daemon for
  persistence, netem ssh-mode column to price stream HOL vs SSP —
  status addendum item 1 has the full phasing. Nothing started.
- mosh-go throwaway limitation (DEPS.md): C server retains all client
  states, quenches past 1024 — long sessions degrade; candidate patch
  sketched there. Now tracked upstream: unixshells/mosh-go#3.
- Escrow refresh: per-reattach floor-jump re-escrow LANDED (finding
  28). Residual: re-escrow *within* a session epoch (immortal
  sessions crossing 2^32 datagrams) needs a retained PRF output or a
  fresh assertion gesture — policy question, not plumbing.
- ssh v0 gaps (deliberate): password auth only; one exec per session;
  no interactive shell/stdin surface. Triaged into issues: #7 DONE
  (finding 30 — first-contact fingerprint confirm BEFORE the password
  moves: two-phase ssh-flow begin/host-key/authenticate/decline, the
  engine's password deferred behind the host-key gate, panel prompt
  UX, native + browser gate legs; the user name rides begin because
  x/crypto snapshots its config pre-handshake — sent only post-gate),
  #8 UPGRADED to passkey/webauthn publickey auth against stock sshd
  (`webauthn-sk-ecdsa-sha2-nistp256@openssh.com` — owner's killer
  feature; spike in flight, status addendum item 2 has the pinned
  wire/verify facts and next steps; the engine plumbing is the
  finding-30 park/resume pattern, NOT an async import), #9
  (keyboard-interactive, riding #7's now-landed park→verdict→resume
  prompt plumbing). Interactive-shell fallback: NO LONGER unfiled-
  by-default — it is phase (a) of the mosh-replacement direction
  (status addendum item 1). Multi-exec stays unfiled.
- Upstream courtesies: ALL FILED 2026-08-11 — deltic module-identity
  convergence (lann/deltic#108); mosh-go wasip build tags
  (unixshells/mosh-go#1), pending-diff races + resume-adoption notes
  (#2), throwaway_num quench (#3); polymorph-iroh per-path datagram
  ceiling (polymorph-iroh#47) and peer close-info accessor for the
  Error-then-close race (polymorph-iroh#48).
- `just m5-netem` rerun 2026-08-11: all five cells green (RTO adapts
  250→684 ms under 100 ms delay; dial survives 10% loss). Needs
  passwordless sudo for tc; measurement matrix, not a regression
  gate.

## Environment

- Tools: componentize-go 0.4.1, host Go 1.26.5 at `~/.local/go/bin`
  (PATH-prefixed by recipes), wasmtime 47.0.1 CLI / crate 47.0.3,
  wasm-tools 1.247.0, wac 0.10.1, node 24.18.0 (harness scripts:
  playwright/ws only), **deno 2.9.5** (component hosting), just
  1.54.0, Rust 1.96 + wasm32-wasip2 + wasm32-unknown-unknown (deltic
  translator shim). M6: webauthn-rs 0.5 (proxy),
  webauthn-authenticator-rs 0.5.5 + webauthn-rs-proto 0.5 (harness).
  M7: golang.org/x/crypto v0.49.0 (engine go.mod, unpatched); russh
  0.62.5 (ssh-e2e stand-in). webauthn-sshd spike: local OpenSSH is
  10.0p2 (`/usr/sbin/sshd`; `ssh -Q sig` lists the webauthn-sk
  algo) — the spike runs it unprivileged on a loopback high port.
- `.deps/mosh-go` — committed vendored fork (4 patches, DEPS.md).
  `.deps/polymorph-iroh`, `.deps/deltic` — setup.sh clones at the
  pins in scripts/setup.sh (deltic consumed as a git reference; its
  translator shim built locally, stamp files `.wosh-built-at`).
- The old `../polymorph-iroh` sibling checkout is GONE (the jco
  `file:` dep with it); nothing references it anymore.
- Browser legs: playwright-core + chrome.mjs (Chromium 151).
- mosh-server 1.4.0 at `/usr/bin/mosh-server`.
- Harness ports: :3345 m3, :3347 m4, :3348 m5-client-deno, :3349 m6,
  :3350 m7, :3352 m5-browser-e2e, :3353/:3354 m6-browser
  (relay/page), :3355 m7-browser. The user's own `mosh-server -p 0`
  is NOT ours; never kill it.
- This repo: private remote `lann/wosh`. GitHub auth: `gh` as `lann`.

## Entry points

- `just m5` — web modules + Deno-lane client E2E + the browser E2E
  (the deltic showcase); `just m5-browser-e2e` alone for the page
  gate. `just m6-browser m7-browser` — the in-page ceremony and
  inner-ssh legs. `just m7 m6 m4 m3` — native gates; `just m2` /
  `just web-serve` — dev bridge; `just m1` — conformance; `just
  spikes` — wasmtime + deltic spike legs.
- `just web-bundle` — rebuild `web/dist/deltic.js` after touching
  `web/deltic-entry.ts` or bumping deltic.
- `just engine-bindings` — regen after `wit/mosh.wit` changes
  (rewrites go.mod deliberately; commit). NOTE:
  `client-core/wit/deps/mosh/mosh.wit` is a HARD LINK to
  `wit/mosh.wit` (same inode) — don't break it.
- `scripts/setup.sh` — toolchain + .deps pins (idempotent; owns the
  polymorph-iroh AND deltic pins + translator build).
- `scripts/web-deploy-tree.sh <dest>` — static deploy tree (now
  includes dist/: bundle + composed client + translator; a static
  host serves a working client).
- `proto/` — control/framing/escrow shapes (`cargo test --lib`).
