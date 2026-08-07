#!/usr/bin/env bash
# Sync spike, wasmtime leg: drives every export through WAVE --invoke and
# checks the answers.
set -euo pipefail
cd "$(dirname "$0")/sync"

check() {
  local expr="$1" want="$2" got
  got=$(wasmtime run --invoke "$expr" main.wasm)
  if [ "$got" != "$want" ]; then
    echo "FAIL: $expr -> $got (want $want)"
    exit 1
  fi
  echo "ok: $expr -> $got"
}

check 'add(2, 3)' '5'
check 'echo-bytes([1, 2, 250])' '[1, 2, 250]'
check 'hash-hex([])' '"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"'
check 'tick-batch(3)' '[[0, 0, 171, 205], [1, 0, 171, 205], [2, 0, 171, 205]]'
echo "sync spike wasmtime leg: OK"
