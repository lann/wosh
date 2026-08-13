#!/usr/bin/env bash
# Stand up a throwaway OpenSSH sshd for the end-to-end gate.
#
# Runs as the invoking user on a high port with its own host key and
# authorized_keys, so it needs no root and touches nothing system-wide.
# Publickey auth only: the gate authenticates with the WebCrypto key
# the client component mints for itself, which is the whole point.
#
#   scripts/test-sshd.sh start|stop|fingerprint|authorized-keys
set -euo pipefail
cd "$(dirname "$0")/.."
DIR="$(pwd)/.deps/test-sshd"
PORT="${WOSH_SSHD_PORT:-2222}"

ensure() {
  mkdir -p "$DIR"
  [ -f "$DIR/host_ed25519" ] || ssh-keygen -t ed25519 -f "$DIR/host_ed25519" -N '' -q
  touch "$DIR/authorized_keys"
  chmod 600 "$DIR/authorized_keys"
  cat > "$DIR/sshd_config" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $DIR/host_ed25519
AuthorizedKeysFile $DIR/authorized_keys
PidFile $DIR/sshd.pid
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
StrictModes no
# The gates deliberately hammer this sshd with rejected host keys
# (connections that never attempt auth) and failed publickey probes;
# OpenSSH 9.8+ per-source penalties would start refusing 127.0.0.1
# outright after a few of those, which surfaces as flaky "tunnel died
# before the host-key gate" hangs in whichever gate runs next.
PerSourcePenalties no
PrintMotd no
X11Forwarding no
LogLevel VERBOSE
EOF
}

case "${1:-start}" in
  start)
    ensure
    /usr/sbin/sshd -t -f "$DIR/sshd_config"
    if [ -f "$DIR/sshd.pid" ] && kill -0 "$(cat "$DIR/sshd.pid")" 2>/dev/null; then
      echo "test sshd already running on 127.0.0.1:$PORT (pid $(cat "$DIR/sshd.pid"))"
    else
      /usr/sbin/sshd -f "$DIR/sshd_config" -E "$DIR/sshd.log"
      sleep 1
      echo "test sshd on 127.0.0.1:$PORT (log: $DIR/sshd.log)"
    fi
    ;;
  stop)
    [ -f "$DIR/sshd.pid" ] && kill "$(cat "$DIR/sshd.pid")" 2>/dev/null || true
    echo "stopped"
    ;;
  fingerprint) ensure; ssh-keygen -lf "$DIR/host_ed25519.pub" | awk '{print $2}' ;;
  authorized-keys) ensure; echo "$DIR/authorized_keys" ;;
  port) echo "$PORT" ;;
  *) echo "usage: $0 start|stop|fingerprint|authorized-keys|port" >&2; exit 2 ;;
esac
