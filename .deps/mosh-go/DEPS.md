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
