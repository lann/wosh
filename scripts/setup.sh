#!/usr/bin/env bash
# Idempotent toolchain setup for experiment-mosh. Re-run freely; each step
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
say "node: $(node --version) (need >=24 for JSPI)"

# --- rust wasm target (composition spike, client-core glue) ---------------
if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -q wasm32-wasip2; then
  say "rustup target add wasm32-wasip2"
  rustup target add wasm32-wasip2
fi

# --- jco fork (transpiler) -----------------------------------------------
# The pinned lann/jco fork build is consumed from the polymorph-iroh
# sibling checkout; runner/package.json references it as a file: dep.
JCO_PKG="$(cd "$(dirname "$0")/.." && pwd)/../polymorph-iroh/.deps/jco/packages/jco-transpile"
if [ -d "$JCO_PKG/dist" ]; then
  say "jco-transpile: $JCO_PKG"
else
  echo "warning: built jco-transpile not found at $JCO_PKG (run polymorph-iroh/scripts/setup.sh)"
fi

# --- runner npm deps ------------------------------------------------------
RUNNER="$(cd "$(dirname "$0")/.." && pwd)/spikes/componentize-go/runner"
if [ -f "$RUNNER/package.json" ] && [ ! -d "$RUNNER/node_modules" ]; then
  say "npm install (spike runner)"
  (cd "$RUNNER" && npm install --no-fund --no-audit)
fi

# --- M1 conformance harness -----------------------------------------------
command -v mosh-server >/dev/null 2>&1 || { echo "missing: mosh-server (apt install mosh) — M1 conformance gate needs it"; exit 1; }
say "mosh-server: $(mosh-server --version 2>&1 | head -1)"
HOST_TEST="$(cd "$(dirname "$0")/.." && pwd)/host-test"
if [ -f "$HOST_TEST/package.json" ] && [ ! -d "$HOST_TEST/node_modules" ]; then
  say "npm install (host-test)"
  (cd "$HOST_TEST" && npm install --no-fund --no-audit)
fi

say "setup complete"
