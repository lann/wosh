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

## Status: M6 DONE (about to commit) — next M7

Commit history: M0 `4003320`..`59d9b8f`; M1 `fe86742`; D7 `1929ae2`;
M2 `601f799`; upstream eval `fda916b`; M3 `a20c531`; M4 checkpoints
`4ededc6`..`0cc01a4`, M4 `308e304`; M5 `74e59cb`; M6 pending commit.

### M6 outcome (findings 20–21; `just m6` green; m1–m5 re-run green)

- The reattach-resync bug that stopped the previous session is
  diagnosed and fixed. Root cause (confirmed in mosh 1.4.0 sources,
  fetched to /tmp/opencode/mosh-src): SSP state numbers are a second
  counter (finding 13 covered only the crypto seq) — the server
  dedups client states ≤ its high-water N, anchors its own diffs at a
  state K the fresh client lacks, and *ignores acks for culled
  states*, so both directions deadlock silently (the empty screen).
- Fix shape — **live adoption, not escrowed floors** (escrowed state
  floors are provably unsafe: UserStream diffs are positional; a
  stale sender floor crashes the C server via
  `get_remote_diff`'s `fatal_assert` or drops keystrokes):
  `Transport.EnableResumeAdopt()` (fork patch 3) adopts sender floor
  (= server `ack_num`, frozen during detach) and receiver anchor
  (= server `old_num`) from the first server instruction; server
  heartbeats every 3 s, so adoption is prompt. Escrow schema stays
  `{key, seqFloor}` — zero WIT/proto changes for the fix.
- Screen resync: engine-side **resize dance** — resume connects one
  row off, snaps to true size on the first content diff; a size
  change is the only client-reachable full-repaint trigger
  (terminaldisplay.cc). Embedder resize supersedes a pending dance.
- Fork patch 4 (correctness, upstream-worthy): an ack no longer
  clears a never-sent pending diff (was a keystroke-loss race,
  systematic under adoption); acked-action bookkeeping is now the
  number-agnostic pending-diff lifecycle (`HasPending`) instead of a
  map keyed by predicted state numbers.
- Proxy shell handles SIGINT/SIGTERM: reaps sessions (incl.
  persistent) before exit; previous behavior orphaned mosh-servers on
  every teardown path (destructors don't run on signals). The
  passkey-e2e harness now SIGTERMs (TERM-first Drop too) and asserts
  the reap; no more orphan-watch after failed runs (a SIGKILLed proxy
  still orphans — check `pgrep -a mosh-server` after hard kills;
  the user's own `-p 0` server is not ours).
- Browser PRF leg (finding 21): `web/prf-wrap.mjs`
  (PRF→HKDF(SHA-256)→AES-GCM-256 wrap/unwrap of `{key, seqFloor}`,
  base64url fields, prototype-call ceremony helpers, D4 policy
  guard); web-tests phase 3 drives real create/get ceremonies against
  the CDP virtual authenticator (`hasPrf: true`, Chromium 151 —
  supported) and proves the deterministic-KEK reattach property.
  Escrow JSON parity across storage.mjs / prf-wrap.mjs /
  proto::Escrow is tested on both sides.
- D4 sub-policy DECIDED: no `prf` ⇒ refuse persistence (README D4;
  `assertPersistencePermitted` in code). Trust boundary recorded: in
  a proxy-returned escrow only the sealed payload is trusted; attach
  uses the inner floor + `FLOOR_JUMP` (2^32) per reattach.
- M6 surface recap (all committed with this milestone): mosh-go fork
  patches 3–4 (`transport.go`, `client.go`, DEPS.md); engine
  `connect(key, cols, rows, initial-seq: option<u64>)` + `current-seq`
  stat + resume dance (engine.go); proto ceremony/reattach messages +
  `Escrow` variant; proxy-core post-hello routing (NewSession |
  Reattach), ceremony loop, `webauthn-step`/`make-persistent`/
  `reattach` host imports; proxy shell webauthn-rs RP + passkey/escrow
  persistence + signal handling; client-core `register-start/finish`,
  `make-persistent`, `session-key`, `reattach-flow`; passkey-e2e
  harness; web/prf-wrap.mjs + web-tests phase 3; `just m6`.

## Next: M7 — inner ssh (native leg; browser leg A3-blocked)

Workstream F (PLAN). Shape:

- Proxy: stream-forward pinned to `127.0.0.1:22`; proxy-core gains a
  stream-forward path (client opens a second bi stream; first-byte
  tag or a control message announcing it — decide there);
  `--personal` flag keeps interim key-delivery mode; without it the
  proxy never spawns mosh-server or sees keys (deprivileged posture,
  D2 end state).
- Engine: ssh mode — x/crypto/ssh over an imported stream; findings
  2–4 constrain (goroutines-over-CM-async OK on wasmtime; Go-native
  timers TRAP in async exports — audit/shim x/crypto/ssh timer use;
  jco async-lower broken ⇒ browser ssh waits on A3). Engine world
  grows an async variant; `MOSH CONNECT` parsed in-component.
- Native gate: composed client → proxy → sshd stand-in. sshd needs
  root/config; use a russh-based test server (password auth) as the
  stand-in — the gate is ssh-in-component correctness.

## Pending / open (carried)

- Finding 10 follow-ups: leg-b scroll artifact; predictor not
  RTT-adaptive; **RTO clamp 10 s measured live** (finding 19) — fork
  patch to C mosh's [50 ms, 1 s] justified if M6/M7 sessions stall on
  idle recovery.
- mosh-go throwaway limitation (noted in DEPS.md with patch 4): the
  client never advances `throwaway_num`, so a C server retains all
  client states and quenches past 1024 — long interactive sessions
  would degrade; candidate fork patch sketched in DEPS.md.
- Real-client escrow-refresh policy: prf-wrap documents
  `FLOOR_JUMP`-per-reattach; immortal sessions (> 2^32 datagrams)
  additionally want periodic re-escrow — wire when the browser
  ceremony leg unblocks.
- A3 upstream: polymorph-iroh#10 / lann/jco#11 open, plus
  **lann/jco#51** (composed-resource TDZ, ours, minimal repro in
  spikes/compose-async-tdz/) — #51 fires before the scheduler defects
  on the composed client. Gates M5 browser E2E, M6 ceremony E2E, M7
  browser ssh. `just m5-jco-probe` = unblock detector.
- Upstream courtesies: mosh-go wasip build-tag patch; per-path
  datagram-ceiling issue on polymorph-iroh (M4 fragmented data
  exists); mosh-go fork patch 4 (ack/bookkeeping correctness) and the
  resume-adoption learning are worth an upstream note.
- setup.sh gap: `npm install` in
  `.deps/polymorph-iroh/.deps/webrtc/jco-impl` (node-datachannel)
  needed for `just m5-jco-probe`; done manually previous session.
- Sibling `../polymorph-iroh` on `port-noq` (old jco pin) — our jco
  transpiles ride it; don't touch.
- Stray processes on this machine: an iroh-relay `--dev` from an
  older session listens on :3340/:9090 (cwd
  /tmp/opencode/polymorph-iroh — not this repo's). Harness ports:
  :3345 (m3), :3347 (m4), :3348 (jco-probe), :3349 (passkey-e2e); no
  conflicts.

## Environment

- Tools: componentize-go 0.4.1, host Go 1.26.5 at `~/.local/go/bin`
  (PATH-prefixed by recipes), wasmtime 47.0.1 CLI / wasmtime crate
  47.0.3, wasm-tools 1.247.0, wac 0.10.1, node 24.18.0, just 1.54.0,
  Rust 1.96 + wasm32-wasip2 (1.97 auto via polymorph-iroh
  rust-toolchain.toml). M6: webauthn-rs 0.5 (+ uuid v4+v5) in the
  proxy; webauthn-authenticator-rs 0.5.5 (softpasskey) +
  webauthn-rs-proto 0.5 in the harness.
- `.deps/mosh-go` — committed vendored fork (ledger in DEPS.md, now
  4 patches). `.deps/polymorph-iroh` — cloned+built by setup.sh at
  pin `bcaed0f2` (endpoint component, shim crates, iroh-relay;
  `enable_metrics = false` required).
- jco: lann/jco fork @ 30186b2 via `../polymorph-iroh/.deps/jco`.
- Browser legs: playwright-core + chrome.mjs (Chromium 151).
- mosh-server 1.4.0 at `/usr/bin/mosh-server`; C sources for protocol
  reference unpacked at /tmp/opencode/mosh-src/mosh-1.4.0 (fetched
  from the GitHub release tarball).
- This repo: local-only by decision (D-repo); rename before
  publishing. GitHub auth: `gh` as `lann` (used for lann/jco#51).

## Entry points

- `just m6` — M6 native gate (passkey-e2e); `just m5` (web gates,
  incl. prf phase 3) / `just m5-jco-probe` (A3 detector) /
  `just m5-netem` (loopback matrix; passwordless sudo);
  `just m4`; `just m3`; `just m2` / `just web-serve`; `just m1`;
  `just spikes`.
- `just engine-bindings` — regenerate engine bindings after
  `wit/mosh.wit` changes (rewrites go.mod deliberately; commit).
- `scripts/setup.sh` — toolchain + .deps (idempotent).
- `proto/` — shared control/framing/escrow (`cargo test --lib`).
- `client-core/` — the glue; `proxy-core/` — the proxy brain;
  `proxy/` — the native shell.
- `host-test/composed-e2e/` — M3; `host-test/proxy-e2e/` — M4;
  `host-test/passkey-e2e/` — M6; `host-test/web-tests.mjs` — M5+M6
  web; `host-test/jco-probe.mjs` — A3 detector.
