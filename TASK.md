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

## Status: PLAN COMPLETE — M7 DONE (committed as this file's commit)

Commit history: M0 `4003320`..`59d9b8f`; M1 `fe86742`; D7 `1929ae2`;
M2 `601f799`; upstream eval `fda916b`; M3 `a20c531`; M4 `308e304`;
M5 `74e59cb`; M6 `b6391df`; M7 = the commit carrying this file
version. The standing instruction (M4 → M7 autonomously) is
fulfilled; the design-decision summary was delivered in the
2026-08-08 session log. What remains is only the carried/pending
list below (A3-blocked browser legs documented, not waited on).

### M7 recap (findings 22–23 are the full record)

- **Engine (`wit/mosh.wit` interface `ssh`,
  `engine-go/export_experiment_mosh_ssh/ssh.go`):** pure sync
  sans-I/O ssh client — x/crypto/ssh v0.49.0 unpatched on goroutines
  over a `shuttleConn`; parked goroutines survive across sync export
  calls and stock-Go timers work in the sync world (finding 22; the
  M0 timer trap was async-world-only). Host-key gate parks the
  handshake pre-auth (`host-key-check` → `host-key-decision`);
  fingerprint = padded base64 of SHA-256 over the wire blob. NOTE:
  `client-core/wit/deps/mosh/mosh.wit` is a HARD LINK to
  `wit/mosh.wit` (same inode) — don't break it.
- **client-core `connect-ssh`:** dial → hello → `open_bi()` +
  `SSH_FORWARD` tag → `drive_ssh` (drain→write before read-await;
  status gate BEFORE read-await — the host-key park has nothing in
  flight) → expected-fp check fails BEFORE auth / TOFU-records
  otherwise → exec mosh-server → parse `MOSH CONNECT` from complete
  lines → `ForwardDatagrams`/`ForwardOk` → engine start with
  `framed=true` + session id + host fp accessor.
- **proxy-core:** `start(relay, ssh-target, personal)`;
  serve_connection = hello, then TWO concurrent phases — stream
  daemon (accept_bi → tag byte → `tcp::forward` to ssh-target over
  `wasi:sockets@0.3` TCP, p3 stream-shaped, FIN-cascade teardown)
  and session phase (`run_session`: NewSession gated on `personal`,
  Reattach, ForwardDatagrams → `host::register-forward`). No-cancel
  completion: session phase decides, `conn.close` resolves the
  parked accept-bi, daemon drains. `Control::fail` sends terminal
  `Error` and waits for the PEER to close (close races in-flight
  stream data — the phase-1 gate failure).
- **proxy shell:** `--personal` (default OFF = deprivileged),
  `--ssh-target` (default `127.0.0.1:22`, loopback enforced);
  `register_forward` host fn (session entry with `pid: None`, empty
  key; port-collision refused); `new_session` refuses without
  `--personal` (defense in depth).
- **Gate `host-test/ssh-e2e` (`just m7`):** russh 0.62.5 sshd
  stand-in (in-process; password counter; exec via `sh -c` with
  UTF-8 locale; daemon-pid parsing for teardown reaping). Phases:
  NewSession refused deprivileged; wrong expected-host-key fails
  with ZERO password attempts observed; wrong password legible;
  positive M1 trio + fp equality + detach. Relay port :3350.
- **Regressions all green post-M7:** m1 (C+go), m2, m3, m4, m5-web
  (incl. prf phase 3), m6, proto tests. m4/m6 harnesses now pass
  `--personal`.

## Pending / open (carried)

- Finding 10 follow-ups: leg-b scroll artifact; predictor not
  RTT-adaptive; RTO clamp 10 s measured live (finding 19) — fork
  patch to C mosh's [50 ms, 1 s] if long sessions stall on idle
  recovery (M7 gate itself ran at RTO 250 ms).
- mosh-go throwaway limitation (DEPS.md): C server retains all client
  states, quenches past 1024 — long sessions degrade; candidate patch
  sketched there.
- Real-client escrow-refresh policy: `FLOOR_JUMP` per reattach in
  prf-wrap; immortal sessions want periodic re-escrow — wire when the
  browser ceremony leg unblocks.
- ssh v0 gaps (deliberate): password auth only; one exec per
  session; no interactive shell/stdin surface; hostkey pinning is
  embedder-side (connect-ssh's expected-host-key) — the directional
  last step (unextractable WebCrypto ssh key via a WIT-imported
  signer) needs an async export, still A3-adjacent.
- A3 upstream: polymorph-iroh#10 / lann/jco#11 open, plus lann/jco#51
  (composed-resource TDZ, minimal repro in spikes/compose-async-tdz/).
  Gates M5 browser E2E, M6 ceremony E2E, M7 browser ssh.
  `just m5-jco-probe` = unblock detector.
- Upstream courtesies: mosh-go wasip build-tag patch; per-path
  datagram-ceiling issue on polymorph-iroh; mosh-go fork patch 4 +
  resume-adoption learning worth an upstream note. New candidate: a
  connection close-reason accessor on the endpoint WIT (the
  Error-then-close race would vanish with readable CONNECTION_CLOSE
  reasons; `Control::fail` is the guest-side workaround).
- setup.sh gap: `npm install` in
  `.deps/polymorph-iroh/.deps/webrtc/jco-impl` needed for
  `just m5-jco-probe`; done manually in a previous session.
- Sibling `../polymorph-iroh` on `port-noq` (old jco pin) — our jco
  transpiles ride it; don't touch.
- Stray processes: an old iroh-relay `--dev` on :3340/:9090 (not
  ours; leave). Harness ports: :3345 m3, :3347 m4, :3348 jco-probe,
  :3349 m6, :3350 m7. The user's own `mosh-server -p 0` is NOT ours;
  never kill it.

## Environment

- Tools: componentize-go 0.4.1, host Go 1.26.5 at `~/.local/go/bin`
  (PATH-prefixed by recipes), wasmtime 47.0.1 CLI / crate 47.0.3,
  wasm-tools 1.247.0, wac 0.10.1, node 24.18.0, just 1.54.0, Rust
  1.96 + wasm32-wasip2. M6: webauthn-rs 0.5 (proxy),
  webauthn-authenticator-rs 0.5.5 + webauthn-rs-proto 0.5 (harness).
  M7: golang.org/x/crypto v0.49.0 (engine-go go.mod, unpatched);
  russh 0.62.5 + sha2 + base64 (ssh-e2e stand-in).
- `.deps/mosh-go` — committed vendored fork (4 patches, DEPS.md).
  `.deps/polymorph-iroh` — setup.sh clone at pin `bcaed0f2`.
- jco: lann/jco fork @ 30186b2 via `../polymorph-iroh/.deps/jco`.
- Browser legs: playwright-core + chrome.mjs (Chromium 151).
- mosh-server 1.4.0 at `/usr/bin/mosh-server`; mosh C sources for
  protocol reference at `/tmp/opencode/mosh-src/mosh-1.4.0`.
- This repo: local-only by decision (D-repo); rename before
  publishing. GitHub auth: `gh` as `lann`.

## Entry points

- `just m7` — M7 native gate (deprivileged proxy + inner ssh);
  `just m6`; `just m5` (web incl. prf phase 3); `just m5-jco-probe`;
  `just m5-netem`; `just m4`; `just m3`; `just m2` /
  `just web-serve`; `just m1`; `just spikes` (sync spike carries the
  M7 parked-goroutine/timer probes — jco/node + browser legs assert
  them).
- `just engine-bindings` — regen after `wit/mosh.wit` changes
  (rewrites go.mod deliberately; commit).
- `scripts/setup.sh` — toolchain + .deps (idempotent).
- `proto/` — control/framing/escrow shapes (`cargo test --lib`).
- `client-core/` — glue (connect-ssh included); `proxy-core/` —
  proxy brain (stream daemon + tcp.rs forwarder); `proxy/` — native
  shell (`--personal`, `--ssh-target`).
- `host-test/ssh-e2e/` — M7; `host-test/passkey-e2e/` — M6;
  `host-test/web-tests.mjs` — M5+M6 web; `host-test/jco-probe.mjs`
  — A3 detector.
