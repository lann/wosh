#!/usr/bin/env bash
# Self-test for scripts/gate-proc.sh -- the process ownership the gates
# depend on. Needs nothing built: it drives a stand-in process, so it
# runs in seconds and in any checkout.
#
# The property under test is the one whose absence made gates stomp on
# each other: stopping a gate's process must kill THAT process and
# nothing else. A pattern-kill passes every other check here and fails
# leg 3.
set -euo pipefail
cd "$(dirname "$0")/.."

GATE="scripts/gate-proc.sh"
SANDBOX="$(mktemp -d)"
export WOSH_RUN_DIR="$SANDBOX/run"
FAKE="$SANDBOX/fake-listener"
# Cleanup is by parent pid, not by pattern: everything below is a child
# of this shell, and matching on names is the habit under test.
trap '"$GATE" stop-all 2>/dev/null || true; pkill -P $$ 2>/dev/null || true; rm -rf "$SANDBOX"' EXIT
trap 'exit 130' INT TERM

# Stands in for a listener: announces itself on a delay (so `field` has
# to wait, as it does against the real thing) and then stays up.
cat > "$FAKE" <<'EOF'
#!/usr/bin/env bash
sleep 0.6
echo "connstring: fake-$1"
echo "direct-addr: 127.0.0.1:1"
sleep 300
EOF
chmod +x "$FAKE"

fails=0
check() { # check <condition-description> <actual> <expected>
  if [ "$2" = "$3" ]; then return 0; fi
  echo "FAIL: $1: expected '$3', got '$2'" >&2
  fails=$((fails + 1))
}
alive() { kill -0 "$1" 2>/dev/null && echo yes || echo no; }
pid_of() { read -r p _ < "$WOSH_RUN_DIR/$1.pid"; echo "$p"; }

# 1. Two named processes coexist -- gates in flight at the same time
#    are the situation the whole exercise is about.
"$GATE" start selftest-alpha "$FAKE" alpha
"$GATE" start selftest-beta "$FAKE" beta
alpha="$(pid_of selftest-alpha)"
beta="$(pid_of selftest-beta)"
check "alpha is running" "$(alive "$alpha")" yes
check "beta is running" "$(alive "$beta")" yes
check "they are different processes" "$([ "$alpha" != "$beta" ] && echo ok)" ok
echo "[1] two named processes run side by side (pids $alpha, $beta)"

# 2. `field` waits for a line that has not been printed yet.
check "alpha's connstring" "$("$GATE" field selftest-alpha connstring)" fake-alpha
check "beta's connstring" "$("$GATE" field selftest-beta connstring)" fake-beta
echo "[2] field waits for the announcement and reads it back"

# 3. THE PROPERTY: stopping one leaves the other alone.
"$GATE" stop selftest-alpha
sleep 0.2
check "alpha stopped" "$(alive "$alpha")" no
check "beta survived alpha's stop" "$(alive "$beta")" yes
echo "[3] stop kills its own process and not the other gate's"

# 4. Stopping something already stopped is quiet and successful --
#    recipes stop from an EXIT trap that also runs on the happy path.
"$GATE" stop selftest-alpha
echo "[4] stopping an already-stopped name is a no-op"

# 5. A recycled pid is NOT killed. Simulated the only way that can be
#    done deterministically: a pidfile naming a live process that was
#    never ours. Both shapes: a wrong command, and a truncated pidfile
#    that names no command at all (where a substring check has nothing
#    to check and must refuse rather than kill a bare number).
innocent_cmd="sleep"
sleep 300 &
innocent=$!
printf '%s %s\n' "$innocent" "definitely-not-$innocent_cmd" > "$WOSH_RUN_DIR/selftest-ghost.pid"
"$GATE" stop selftest-ghost 2>/dev/null
sleep 0.2
check "a recycled pid is left alone" "$(alive "$innocent")" yes
printf '%s\n' "$innocent" > "$WOSH_RUN_DIR/selftest-truncated.pid"
"$GATE" stop selftest-truncated 2>/dev/null
sleep 0.2
check "a pidfile with no command kills nothing" "$(alive "$innocent")" yes
kill "$innocent" 2>/dev/null || true
echo "[5] a pid that no longer runs what we started is left alone"

# 6. Restarting a name replaces it rather than leaking it.
old_beta="$beta"
"$GATE" start selftest-beta "$FAKE" beta2
sleep 0.2
new_beta="$(pid_of selftest-beta)"
check "the old beta is gone" "$(alive "$old_beta")" no
check "a new beta is running" "$(alive "$new_beta")" yes
echo "[6] restarting a name stops the previous one first"

# 7. stop-all clears what this worktree started.
"$GATE" stop-all
sleep 0.2
check "beta stopped by stop-all" "$(alive "$new_beta")" no
check "no pidfiles left" "$(ls "$WOSH_RUN_DIR"/*.pid 2>/dev/null | wc -l)" 0
echo "[7] stop-all clears this worktree's processes"

# 8. A process that never announces fails loudly, with its log.
"$GATE" start selftest-silent sleep 30
if WOSH_FIELD_TIMEOUT_S=1 "$GATE" field selftest-silent connstring >/dev/null 2>&1; then
  echo "FAIL: field invented a connstring for a silent process" >&2
  fails=$((fails + 1))
fi
"$GATE" stop selftest-silent
echo "[8] field fails loudly when the line never comes"

if [ "$fails" -ne 0 ]; then
  echo "GATE-PROC SELFTEST FAIL: $fails check(s)" >&2
  exit 1
fi
echo
echo "GATE-PROC SELFTEST PASS: gates own their processes and nothing else"
