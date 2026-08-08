# .deps/mosh-go

Vendored copy of https://github.com/unixshells/mosh-go (MIT) at rev
`8dca5c67ec8e` (module pseudo-version
`v0.5.3-0.20260405220648-8dca5c67ec8e`), consumed via a `replace`
directive from `engine-go/` and `host-test/moshgo-server/`. `cmd/`,
`remote-test/`, and `demo.png` are dropped; everything else is intact.

Local patches (keep this list current):

1. `server.go`: build tag `!js` → `!js && !wasip1 && !wasip2`. The
   server half imports creack/pty, which does not compile for wasm
   targets (upstream already tags it off for GOOS=js; wasip1/wasip2
   need the same treatment). The engine only uses the client half.
2. `fragment.go`: `maxFragmentPayload` 1300 → 1100. Worst-case wire
   datagram is payload + 38 B (8 nonce + 4 timestamps + 10 fragment
   header + 16 OCB tag): 1338 B upstream, over the ~1162 B iroh
   application ceiling (QUIC datagrams, 1200 B MTU profile); 1138 B
   patched. Fragment sizing is sender-local in SSP — verified
   wire-compatible against stock C mosh-server 1.4.0 by the M1 bulk
   paste test (multi-fragment client diffs reassemble fine).
3. `transport.go` + `client.go`: fresh-process reattach support (M6,
   findings 13 and 20). Two independent counters must survive a
   detach/reattach across client processes:
   - Crypto sequence (persisted): `Transport.SeqOut()`/`SetSeqOut()`
     expose the outgoing sequence, and `DialConnRawSeq(conn, ocb,
     initialSeq)` applies a persisted floor before the association
     datagram (lower is dropped as replay by the server, equal reuse
     is OCB nonce reuse). `DialConnRaw` delegates with 0 — wire
     behavior unchanged for fresh sessions.
   - SSP state numbers (learned, NOT persisted): a non-zero
     `initialSeq` enables `Transport.EnableResumeAdopt()` — the first
     complete instruction from the server teaches the client its
     retained-state window (`AckNum` = high-water for client states,
     frozen during detach; `OldNum` = the server's current diff
     anchor), and the transport adopts both: jumps `sentNum`, rebases
     any pending diff, and seeds `receivedNums`/`ackNum` with the
     anchor. A persisted snapshot would go stale (the anchor moves
     with every ack) and staleness is corrupting, not just lossy:
     UserStream diffs are positional, and the C server's
     `get_remote_diff` `fatal_assert`s on a shrinking action count.
     Screen contents of the adopted anchor are unknowable — the
     engine forces a full repaint via a resize dance (size change is
     the only client-reachable full-repaint trigger, mosh 1.4.0
     `terminaldisplay.cc`).
4. Correctness fixes surfaced by 3 (upstream-worthy independent of
   reattach):
   - `transport.go` `Recv`: an ack must not clear a pending diff that
     was never sent (`diffSent` guard) — previously a race between
     `SetPending` and the next `Tick` could drop keystrokes; under
     resume adoption it fired systematically.
   - `client.go`: the acked-action bookkeeping keyed a map by
     predicted state number (`sentNum+1` at `SetPending` time), which
     breaks whenever numbering moves between build and send (resume
     adoption does exactly that). Replaced with the number-agnostic
     pending-diff lifecycle: `inFlight`/`inFlightCovers` +
     `Transport.HasPending()`.

Known limitation (pre-existing, noted while reading mosh 1.4.0
sources): the client always sends `throwaway_num = 0`, so a C server
retains every client state; past 1024 states the server's receiver
quench drops new client states to ~1 per 15 s. Long interactive
sessions would degrade. Candidate patch: emit `throwaway_num =
diffOldNum` (the locked diff base) when a diff is pending, else
`ackedByRemote`. Not applied — gate-scale sessions never approach the
limit, and reattach adoption depends on the current retain-everything
behavior only for the degenerate no-prior-state case (adoption itself
anchors at the server's live window either way).
