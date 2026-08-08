#!/usr/bin/env bash
# Composition spike, wasmtime leg: drives the wac-composed component
# (Rust adapter + componentize-go engine) through WAVE --invoke and
# checks the answers. All values deterministic (no time dependence in
# the probed path).
set -euo pipefail
cd "$(dirname "$0")"

check() {
  local expr="$1" want="$2" got
  got=$(wasmtime run --invoke "$expr" composed.wasm)
  if [ "$got" != "$want" ]; then
    echo "FAIL: $expr -> $got (want $want)"
    exit 1
  fi
  echo "ok: $expr -> $got"
}

check 'version-via-engine()' '"experiment-mosh engine (mosh-go v0.5.3-0.20260405220648-8dca5c67ec8e)"'
check 'session-round-trip("AAAAAAAAAAAAAAAAAAAAAA", 80, 24)' \
  'ok({datagrams: 2, first-datagram-len: 60, sent-num: 1, output-len: 0})'
check 'session-round-trip("notakey!", 80, 24)' \
  'err("bad key: illegal base64 data at input byte 7")'
echo "compose spike wasmtime leg: OK"
