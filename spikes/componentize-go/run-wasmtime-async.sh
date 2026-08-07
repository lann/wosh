#!/usr/bin/env bash
# Async spike, wasmtime leg. Asserts the working set and that the two
# known-broken shapes still trap (flip to hard failures if they start
# passing, and update README findings).
set -euo pipefail
cd "$(dirname "$0")/async"

W='component-model-async=y'

invoke() { wasmtime run -W "$W" --invoke "$1" main.wasm 2>&1 | tail -1; }

got=$(invoke 'chan-pipeline(4, 100)')
[ "$got" = 5350 ] || { echo "FAIL chan-pipeline: $got"; exit 1; }
echo "ok: chan-pipeline (goroutines+channels in sync export)"

got=$(invoke 'spin-pipeline(4, 100)')
[ "$got" = 5350 ] || { echo "FAIL spin-pipeline: $got"; exit 1; }
echo "ok: spin-pipeline (async lift)"

got=$(invoke 'wait-for-echo(50)')
[ "$got" -ge 50 ] && [ "$got" -lt 200 ] || { echo "FAIL wait-for-echo: $got"; exit 1; }
echo "ok: wait-for-echo (blocking-style async import) -> ${got}ms"

got=$(invoke 'concurrent-wait-fors(4, 50)')
[ "$got" -ge 50 ] && [ "$got" -lt 150 ] || { echo "FAIL concurrent-wait-fors: $got (serialized?)"; exit 1; }
echo "ok: concurrent-wait-fors (4 goroutines parked concurrently) -> ${got}ms"

got=$(invoke 'sleep-in-sync(30)')
[ "$got" -ge 30 ] || { echo "FAIL sleep-in-sync: $got"; exit 1; }
echo "ok: sleep-in-sync (Go timer in sync export) -> ${got}ms"

if out=$(wasmtime run -W "$W" --invoke 'sleep-echo(10)' main.wasm 2>&1); then
  echo "sleep-echo (Go timer in async export) WORKS NOW: $out — update README findings"
else
  echo "ok(known): sleep-echo still traps (Go-native timers in async exports)"
fi

if out=$(wasmtime run -W "$W" --invoke 'wait-for-in-sync(10)' main.wasm 2>&1); then
  echo "wait-for-in-sync (async import from sync export) WORKS NOW: $out — update README findings"
else
  echo "ok(known): wait-for-in-sync still traps (ABI rule)"
fi

echo "async spike wasmtime leg: OK"
