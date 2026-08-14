#!/usr/bin/env bash
# Background processes a gate OWNS: started by name, stopped by pid.
#
# The gates used to open with `pkill -f 'wosh-listene[r]'`, which kills
# every listener on the machine -- other worktrees' gates and the
# operator's own dev listener included. That was compensation, not
# policy: nothing stopped what it started, so strays accumulated (three
# forgotten listeners on one identity dir is what the identity flock was
# eventually added to catch), and each run cleared the field by killing
# everything that looked familiar.
#
# Here a gate names what it starts, gets a pidfile, and stops exactly
# that pid -- verified against the recorded command line, so a pid that
# has been recycled by something else is left alone. Nothing is ever
# matched by pattern, so no run can reach another run's processes.
#
# State lives under .deps/run/, which is per worktree by construction:
# the logs the gates grep their connstrings out of used to be fixed
# /tmp paths, i.e. two worktrees running the same gate would clobber
# each other's log -- and read each other's connstring, silently
# dialing the wrong listener.
#
#   scripts/gate-proc.sh start <name> <cmd> [args...]   # background it
#   scripts/gate-proc.sh field <name> <prefix>          # "<prefix>: X" -> X
#   scripts/gate-proc.sh log   <name>                   # the log's path
#   scripts/gate-proc.sh stop  <name> [name...]         # ours, by pid
#   scripts/gate-proc.sh stop-all
set -euo pipefail
cd "$(dirname "$0")/.."
# Per worktree by default; overridable so the self-test gets a sandbox
# of its own rather than reaching into a live worktree's run state.
RUN="${WOSH_RUN_DIR:-$(pwd)/.deps/run}"

# How long `field` waits for a line the process has not printed yet.
# Generous: it only elapses when something is actually wrong, and the
# report then carries the log.
FIELD_TIMEOUT_S="${WOSH_FIELD_TIMEOUT_S:-30}"

pidfile() { echo "$RUN/$1.pid"; }
logfile() { echo "$RUN/$1.log"; }

# Kill one named process, if it is still the one we started. The
# recorded command must still appear in the live process's argv:
# without that check a stale pidfile whose pid has been recycled turns
# `stop` into exactly the blind kill this script exists to avoid.
stop_one() {
  local name="$1" pf pid cmd
  pf="$(pidfile "$name")"
  [ -f "$pf" ] || return 0
  read -r pid cmd < "$pf" || true
  rm -f "$pf"
  [ -n "${pid:-}" ] || return 0
  if [ -z "${cmd:-}" ]; then
    # A truncated pidfile names no command, so the check below would
    # have nothing to check: `grep -F ""` matches every argv there is.
    # Refuse rather than fall back to killing a bare number.
    echo "gate-proc: $name's pidfile names no command; leaving pid $pid alone" >&2
    return 0
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    return 0 # already gone: the normal case after a clean run
  fi
  if ! ps -p "$pid" -o args= 2>/dev/null | grep -qF -- "$cmd"; then
    echo "gate-proc: pid $pid is no longer '$cmd' (recycled); leaving it alone" >&2
    return 0
  fi
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 40); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.1
  done
  kill -9 "$pid" 2>/dev/null || true
}

case "${1:-}" in
  start)
    name="${2:?usage: gate-proc.sh start <name> <cmd> [args...]}"
    cmd="${3:?usage: gate-proc.sh start <name> <cmd> [args...]}"
    shift 3
    # A previous run of THIS gate in THIS worktree that died before its
    # trap ran. Ours to clean up, and only ours.
    stop_one "$name"
    mkdir -p "$RUN"
    log="$(logfile "$name")"
    : > "$log"
    "$cmd" "$@" > "$log" 2>&1 &
    printf '%s %s\n' "$!" "$cmd" > "$(pidfile "$name")"
    ;;

  field)
    name="${2:?usage: gate-proc.sh field <name> <prefix>}"
    prefix="${3:?usage: gate-proc.sh field <name> <prefix>}"
    log="$(logfile "$name")"
    deadline=$(( $(date +%s) + FIELD_TIMEOUT_S ))
    while :; do
      value="$(grep -m1 "^$prefix: " "$log" 2>/dev/null | cut -d' ' -f2 || true)"
      if [ -n "$value" ]; then
        echo "$value"
        exit 0
      fi
      if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "gate-proc: no '$prefix:' line from '$name' after ${FIELD_TIMEOUT_S}s; $log ends:" >&2
        tail -20 "$log" >&2 || true
        exit 1
      fi
      sleep 0.2
    done
    ;;

  log)
    logfile "${2:?usage: gate-proc.sh log <name>}"
    ;;

  stop)
    shift
    [ "$#" -gt 0 ] || { echo "usage: gate-proc.sh stop <name> [name...]" >&2; exit 2; }
    for name in "$@"; do stop_one "$name"; done
    ;;

  stop-all)
    for pf in "$RUN"/*.pid; do
      [ -e "$pf" ] || continue
      name="$(basename "$pf" .pid)"
      stop_one "$name"
    done
    ;;

  *)
    echo "usage: gate-proc.sh start|field|log|stop|stop-all ..." >&2
    exit 2
    ;;
esac
