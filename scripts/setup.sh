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
# the prebuilt iroh-relay binary the gates run. The sibling host-crate
# tags in listener-host/Cargo.toml and smoke-test/Cargo.toml must stay
# content-identical (Rust + WIT) to the revs polymorph-iroh's own
# Cargo.toml pins, since the native hosts link those crates directly
# against the endpoint guest built here -- re-verify when bumping.
PIROH_REPO=https://github.com/polymorph-components/polymorph-iroh
# The upstream release tag (the same line the Cargo.toml sibling pins
# and the deno.json @polymorph pins follow).
PIROH_PIN=v0.5.0

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
# The pin is a tag, so resolve it to a commit for the staleness check
# (and tolerate a checkout that predates the tag by fetching first).
piroh_want() {
  git -C "$DEPS/polymorph-iroh" rev-parse --verify --quiet "$PIROH_PIN^{commit}" 2>/dev/null || true
}
want="$(piroh_want)"
if [ -z "$want" ] || [ "$(git -C "$DEPS/polymorph-iroh" rev-parse HEAD)" != "$want" ]; then
  git -C "$DEPS/polymorph-iroh" fetch --quiet --tags origin || true
  want="$(piroh_want)"
  if [ -n "$want" ]; then
    git -C "$DEPS/polymorph-iroh" checkout --quiet "$want"
  else
    echo "note: pin $PIROH_PIN not found; staying on $(git -C "$DEPS/polymorph-iroh" rev-parse --short HEAD)" >&2
  fi
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
