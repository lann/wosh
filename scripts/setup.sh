#!/usr/bin/env bash
# Idempotent toolchain setup for wosh. Re-run freely; each step
# checks before acting. Mirrors the polymorph family's setup.sh shape but
# stays experiment-grade (unpinned latest for spike-only tools, pins
# recorded in README findings once a version is known-good).
set -euo pipefail

say() { printf '\033[1m== %s\033[0m\n' "$*"; }

# --- Go (>=1.25.5; componentize-go requirement) -------------------------
GO_MIN=1.25.5
find_go() {
  for g in "$HOME/.local/go/bin/go" "$(command -v go 2>/dev/null || true)"; do
    [ -n "$g" ] && [ -x "$g" ] && { echo "$g"; return; }
  done
}
GO_BIN="$(find_go || true)"
if [ -z "${GO_BIN:-}" ]; then
  say "installing Go to ~/.local/go"
  VER=$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1)
  ARCH=$(uname -m); case "$ARCH" in aarch64) GOARCH=arm64;; x86_64) GOARCH=amd64;; *) echo "unsupported arch $ARCH"; exit 1;; esac
  curl -fsSL "https://go.dev/dl/${VER}.linux-${GOARCH}.tar.gz" -o /tmp/go.tgz
  rm -rf "$HOME/.local/go" && mkdir -p "$HOME/.local" && tar -C "$HOME/.local" -xzf /tmp/go.tgz
  GO_BIN="$HOME/.local/go/bin/go"
fi
say "go: $($GO_BIN version)"
export PATH="$(dirname "$GO_BIN"):$HOME/go/bin:$PATH"

# --- componentize-go -----------------------------------------------------
if ! command -v componentize-go >/dev/null 2>&1; then
  say "installing componentize-go (go install @latest)"
  "$GO_BIN" install github.com/bytecodealliance/componentize-go@latest
fi
say "componentize-go: $(componentize-go --version 2>/dev/null || echo present)"

# --- required, expected preinstalled -------------------------------------
for t in wasmtime wasm-tools wac node just cargo; do
  command -v "$t" >/dev/null 2>&1 || { echo "missing: $t (install per polymorph family setup)"; exit 1; }
done
say "wasmtime: $(wasmtime --version)"
say "node: $(node --version) (harness scripts: playwright/ws)"

# --- rust wasm target (composition spike, client-core glue) ---------------
if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -q wasm32-wasip2; then
  say "rustup target add wasm32-wasip2"
  rustup target add wasm32-wasip2
fi

# --- deno (deltic host lane) ----------------------------------------------
# deltic (the JS component host that replaced jco) runs on Deno; the repo
# itself is pinned below and consumed as source through the root
# deno.json import map.
command -v deno >/dev/null 2>&1 || { echo "missing: deno (>=2.9; https://deno.com)"; exit 1; }
say "deno: $(deno --version | head -1)"

# --- deltic (pinned): the JS component host + its translator shim -----------
# Consumed as a git reference per deltic docs/consumers.md: the root
# deno.json maps @deltic/* into this checkout, and the translator shim
# (the wasm build of its wasmtime-frontend translator) is built here.
DELTIC_REPO=https://github.com/lann/deltic
DELTIC_PIN=a18be734a55667c8a5d371649fd125629e665a0f
DELTIC_DIR="$(cd "$(dirname "$0")/.." && pwd)/.deps/deltic"
if [ ! -d "$DELTIC_DIR/.git" ]; then
  say "cloning deltic @ ${DELTIC_PIN:0:12}"
  git clone "$DELTIC_REPO" "$DELTIC_DIR"
fi
if [ "$(git -C "$DELTIC_DIR" rev-parse HEAD)" != "$DELTIC_PIN" ]; then
  git -C "$DELTIC_DIR" fetch --quiet origin
  git -C "$DELTIC_DIR" checkout --quiet "$DELTIC_PIN"
fi
say "deltic: $(git -C "$DELTIC_DIR" log --oneline -1)"
if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -q wasm32-unknown-unknown; then
  say "rustup target add wasm32-unknown-unknown (deltic translator shim)"
  rustup target add wasm32-unknown-unknown
fi
TRANSLATOR="$DELTIC_DIR/target/wasm32-unknown-unknown/release/translator_shim.wasm"
DELTIC_STAMP="$DELTIC_DIR/.wosh-built-at"
if [ -f "$TRANSLATOR" ] && [ -f "$DELTIC_STAMP" ] && [ "$(cat "$DELTIC_STAMP")" = "$DELTIC_PIN" ]; then
  say "deltic translator shim already built"
else
  say "building the deltic translator shim"
  (cd "$DELTIC_DIR" && cargo build -p translator-shim --target wasm32-unknown-unknown --release)
  echo "$DELTIC_PIN" > "$DELTIC_STAMP"
fi

# --- deltic-next (pinned): settlement-pump evaluation lane ------------------
# A SECOND deltic checkout, ahead of the main pin, used ONLY by the
# componentize-go keep-alive spike (finding 31 / wosh#25): deltic PR #121
# ("settlement pump", embedder-api amendment A11) gives guests between-calls
# liveness, which is what makes the goroutine keep-alive ticker self-driving.
# The main pin cannot advance past deltic A10 (WitError -> ComponentException,
# payload {tag,val} -> {kind,value}) until the pinned polymorph modules
# migrate — see TASK.md "deltic A10/A11 convergence". When the main pin
# advances past a2f84a5, delete this stanza and fold the spike back onto
# DELTIC_DIR.
DELTIC_NEXT_PIN=a2f84a5e9a4ef44aaa64a8141bdea8e1103047d3
DELTIC_NEXT_DIR="$(cd "$(dirname "$0")/.." && pwd)/.deps/deltic-next"
if [ ! -d "$DELTIC_NEXT_DIR/.git" ]; then
  say "cloning deltic-next @ ${DELTIC_NEXT_PIN:0:12}"
  git clone "$DELTIC_REPO" "$DELTIC_NEXT_DIR"
fi
if [ "$(git -C "$DELTIC_NEXT_DIR" rev-parse HEAD)" != "$DELTIC_NEXT_PIN" ]; then
  git -C "$DELTIC_NEXT_DIR" fetch --quiet origin
  git -C "$DELTIC_NEXT_DIR" checkout --quiet "$DELTIC_NEXT_PIN"
fi
say "deltic-next: $(git -C "$DELTIC_NEXT_DIR" log --oneline -1)"
TRANSLATOR_NEXT="$DELTIC_NEXT_DIR/target/wasm32-unknown-unknown/release/translator_shim.wasm"
DELTIC_NEXT_STAMP="$DELTIC_NEXT_DIR/.wosh-built-at"
if [ -f "$TRANSLATOR_NEXT" ] && [ -f "$DELTIC_NEXT_STAMP" ] && [ "$(cat "$DELTIC_NEXT_STAMP")" = "$DELTIC_NEXT_PIN" ]; then
  say "deltic-next translator shim already built"
else
  say "building the deltic-next translator shim"
  (cd "$DELTIC_NEXT_DIR" && cargo build -p translator-shim --target wasm32-unknown-unknown --release)
  echo "$DELTIC_NEXT_PIN" > "$DELTIC_NEXT_STAMP"
fi

# --- M1 conformance harness -----------------------------------------------
command -v mosh-server >/dev/null 2>&1 || { echo "missing: mosh-server (apt install mosh) — M1 conformance gate needs it"; exit 1; }
say "mosh-server: $(mosh-server --version 2>&1 | head -1)"
HOST_TEST="$(cd "$(dirname "$0")/.." && pwd)/host-test"
if [ -f "$HOST_TEST/package.json" ] && [ ! -d "$HOST_TEST/node_modules" ]; then
  say "npm install (host-test)"
  (cd "$HOST_TEST" && npm install --no-fund --no-audit)
fi

# --- web client deps --------------------------------------------------------
WEB="$(cd "$(dirname "$0")/.." && pwd)/web"
if [ -f "$WEB/package.json" ] && [ ! -d "$WEB/node_modules" ]; then
  say "npm install (web)"
  (cd "$WEB" && npm install --no-fund --no-audit)
fi

# --- polymorph-iroh (pinned): endpoint component, host shims, relay --------
# Post-#44: event-driven endpoint wakeups (the jco-era polling pump is
# gone); #40 retired their jco host, #43 adopted deltic's parking kernel.
PIROH_REPO=https://github.com/polymorph-components/polymorph-iroh
PIROH_PIN=d8fdd039f5f78daef519985d484f546845555b7a
PIROH_DIR="$(cd "$(dirname "$0")/.." && pwd)/.deps/polymorph-iroh"
if [ ! -d "$PIROH_DIR/.git" ]; then
  say "cloning polymorph-iroh @ ${PIROH_PIN:0:12}"
  git clone "$PIROH_REPO" "$PIROH_DIR"
fi
if [ "$(git -C "$PIROH_DIR" rev-parse HEAD)" != "$PIROH_PIN" ]; then
  git -C "$PIROH_DIR" fetch --quiet origin
  git -C "$PIROH_DIR" checkout --quiet "$PIROH_PIN"
fi
say "polymorph-iroh: $(git -C "$PIROH_DIR" log --oneline -1)"
# Its own pinned deps (webcrypto/websocket/webrtc shims, upstream iroh, tls).
(cd "$PIROH_DIR" && scripts/setup.sh >/dev/null)
PIROH_STAMP="$PIROH_DIR/.wosh-built-at"
if [ -f "$PIROH_STAMP" ] && [ "$(cat "$PIROH_STAMP")" = "$PIROH_PIN" ]; then
  say "polymorph-iroh artifacts already built"
else
  say "building iroh-endpoint component + iroh-relay (takes a few minutes cold)"
  (cd "$PIROH_DIR" && cargo build -p iroh-endpoint --target wasm32-wasip2 --release)
  (cd "$PIROH_DIR/.deps/iroh" && cargo build --release -p iroh-relay --features server --bin iroh-relay)
  echo "$PIROH_PIN" > "$PIROH_STAMP"
fi

# --- deno module graph + npm deps (root deno.json/deno.lock) ---------------
# Last: the import map's local paths point into the .deps checkouts above.
WOSH_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ ! -d "$WOSH_ROOT/node_modules" ]; then
  say "deno install (import map + npm deps)"
  (cd "$WOSH_ROOT" && deno install --frozen --allow-scripts=npm:node-datachannel)
fi

say "setup complete"
