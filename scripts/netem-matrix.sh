#!/usr/bin/env bash
# M5 netem matrix: the composed client over real iroh (the M3 gate)
# under loopback delay/loss — the native substitute for the A3-blocked
# in-browser measurements. Each cell re-runs the whole gate; the
# per-phase timings printed by composed-e2e are the measurement.
#
# Requires passwordless sudo for tc. netem attaches to lo's root qdisc:
# every loopback EGRESS traverses it once, so the client↔peer direct
# UDP path costs ~1× the delay each way, relayed traffic ~2× per way
# (two lo hops), and the peer↔mosh-server UDP hop adds 1× more. Loss
# applies to all loopback traffic including the relay websocket.
#
# The qdisc is removed on exit (including ^C); a failed cell records
# the failure and the matrix continues.
set -uo pipefail
cd "$(dirname "$0")/.."

cleanup() { sudo -n tc qdisc del dev lo root 2>/dev/null || true; }
trap cleanup EXIT

sudo -n true 2>/dev/null || { echo "needs passwordless sudo for tc"; exit 1; }

just compose-client >/dev/null

cells=(
  "baseline:"
  "delay40:delay 40ms"
  "delay100:delay 100ms"
  "delay40-loss3:delay 40ms loss 3%"
  "delay40-loss10:delay 40ms loss 10%"
)

for cell in "${cells[@]}"; do
  label="${cell%%:*}"
  spec="${cell#*:}"
  if [ -z "$spec" ]; then
    cleanup
  else
    sudo -n tc qdisc replace dev lo root netem $spec
  fi
  echo "=== netem ${label}${spec:+ (${spec})} ==="
  if ! (cd host-test/composed-e2e \
        && cargo run --release --quiet -- ../../client-core/composed-client.wasm) \
       2>&1 | grep -E "composed-e2e|OK|Error|error"; then
    echo "=== netem ${label}: RUN FAILED ==="
  fi
done
