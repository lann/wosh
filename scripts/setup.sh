#!/usr/bin/env bash
# Idempotent toolchain + dependency setup for wosh. Re-run freely.
#
# Everything external is pinned and built under .deps/ INSIDE the repo,
# deliberately: these builds are load-bearing (nothing composes without
# iroh_endpoint.wasm, nothing runs without a relay), so they must not
# live in a scratch directory that can be reclaimed.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
DEPS="$ROOT/.deps"
mkdir -p "$DEPS"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# --- pins -------------------------------------------------------------
# polymorph-iroh supplies the iroh endpoint component (the transport for
# both of our components). Its own scripts/setup.sh no longer checks out
# sibling repos: it installs its pinned toolchain and tools, including
# the prebuilt iroh-relay binary the gates run. The revs in
# listener-host/Cargo.toml and smoke-test/Cargo.toml must match the ones
# polymorph-iroh's own Cargo.toml pins, since the native hosts link
# those crates directly.
#
# Full SHAs: these are the revisions this project was developed and
# verified against.
PIROH_REPO=https://github.com/polymorph-components/polymorph-iroh
# Current main: the @polymorph/iroh 0.5.0 release commit (v0.5.0).
PIROH_PIN=55e1b368a8345ed29fbffa2ed27613e63345529f

# polyengine (the JS component host) arrives as published jsr releases:
# the root deno.json pins @polyengine/* and @polymorph/* there, and
# scripts/site-deploy-tree.sh fetches the matching digest-pinned
# translator wasm from the same @polyengine release.

# --- required tools ---------------------------------------------------
# componentize-go installs to GOBIN, and componentize-go itself needs a
# Go newer than most distributions ship (it builds the guest with its
# own patched toolchain for async worlds, but the driver needs >=1.25).
# Prefer a locally-installed Go over /usr/bin/go.
export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"

say "checking the toolchain"

# Required to BUILD the components and the site.
for t in cargo rustup go componentize-go wac; do
  command -v "$t" >/dev/null 2>&1 || {
    echo "missing: $t" >&2
    case "$t" in
      componentize-go) echo "  go install github.com/bytecodealliance/componentize-go@latest" >&2 ;;
      wac)             echo "  cargo binstall wac-cli" >&2 ;;
    esac
    exit 1
  }
done

# Needed only to RUN the gates or inspect artifacts, so a build-only
# environment (CI publishing the site) is not blocked on them.
for t in wasmtime wasm-tools; do
  command -v "$t" >/dev/null 2>&1 || \
    echo "note: $t not found -- fine for building, needed for 'just e2e'/'just spike-async'" >&2
done
for target in wasm32-wasip2 wasm32-unknown-unknown; do
  rustup target list --installed | grep -q "$target" || rustup target add "$target"
done
say "go: $(go version)"
say "wasmtime: $(wasmtime --version)"

# componentize-go downloads a patched Go toolchain on first async build
# (golang.org/x/crypto builds fine on it; see README "async lifting").

# --- polymorph-iroh: the endpoint component + a local relay -----------
if [ ! -d "$DEPS/polymorph-iroh/.git" ]; then
  say "cloning polymorph-iroh"
  git clone "$PIROH_REPO" "$DEPS/polymorph-iroh"
fi
if [ "$(git -C "$DEPS/polymorph-iroh" rev-parse HEAD)" != "$PIROH_PIN" ]; then
  git -C "$DEPS/polymorph-iroh" fetch --quiet origin || true
  git -C "$DEPS/polymorph-iroh" checkout --quiet "$PIROH_PIN" 2>/dev/null || {
    echo "note: pin $PIROH_PIN not found; staying on $(git -C "$DEPS/polymorph-iroh" rev-parse --short HEAD)" >&2
  }
fi
say "polymorph-iroh: $(git -C "$DEPS/polymorph-iroh" log --oneline -1)"

# Its pinned toolchain + tools, incl. the iroh-relay binary the gates run.
(cd "$DEPS/polymorph-iroh" && ./scripts/setup.sh)

say "building the iroh endpoint component (cold: several minutes)"
(cd "$DEPS/polymorph-iroh" && cargo build -p iroh-endpoint --target wasm32-wasip2 --release)


say "setup complete

  iroh endpoint : .deps/polymorph-iroh/target/wasm32-wasip2/release/iroh_endpoint.wasm
  iroh relay    : iroh-relay on PATH ($(iroh-relay --version 2>/dev/null || echo not found))

next: just build"
