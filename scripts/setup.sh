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
# both of our components). Its own scripts/setup.sh pins its siblings
# (webcrypto / websocket / webrtc-datachannels / tls) and upstream iroh;
# we call it rather than duplicating those pins here. The revs in
# listener-host/Cargo.toml and smoke-test/Cargo.toml must match the ones
# it checks out, since the native hosts link those crates directly.
#
# Full SHAs: these are the revisions this project was developed and
# verified against.
PIROH_REPO=https://github.com/polymorph-components/polymorph-iroh
PIROH_PIN=a9f422300a9be129cce21f591d74e848eae38926

# deltic is the JS component host that runs the browser client in-page.
# The pin matches what polymorph-iroh's deltic host modules are written
# against (their deno.jsons name jsr @deltic/*@0.1.0-pre.g<shorthash> of
# the same commit); our root deno.json maps @deltic/* to this checkout.
DELTIC_REPO=https://github.com/lann/deltic
DELTIC_PIN=a2f84a5e9a4ef44aaa64a8141bdea8e1103047d3

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

# Its own siblings (webcrypto/websocket/webrtc/tls) + upstream iroh.
(cd "$DEPS/polymorph-iroh" && ./scripts/setup.sh)

say "building the iroh endpoint component (cold: several minutes)"
(cd "$DEPS/polymorph-iroh" && cargo build -p iroh-endpoint --target wasm32-wasip2 --release)

# The relay is only needed to RUN the gates, never to build the
# components or the site -- and it is by far the most expensive thing
# here. CI that only publishes the site skips it.
if [ -n "${WOSH_SKIP_RELAY:-}" ]; then
  say "skipping the local iroh-relay build (WOSH_SKIP_RELAY set)"
else
  say "building a local iroh-relay (used by the gates)"
  (cd "$DEPS/polymorph-iroh/.deps/iroh" && cargo build --release -p iroh-relay --features server --bin iroh-relay)
fi

# --- deltic: the JS component host for the browser leg ----------------
if [ ! -d "$DEPS/deltic/.git" ]; then
  say "cloning deltic"
  git clone "$DELTIC_REPO" "$DEPS/deltic"
fi
git -C "$DEPS/deltic" rev-parse --verify --quiet "$DELTIC_PIN" >/dev/null 2>&1 \
  && git -C "$DEPS/deltic" checkout --quiet "$DELTIC_PIN"
say "deltic: $(git -C "$DEPS/deltic" log --oneline -1)"

say "building deltic's translator shim"
(cd "$DEPS/deltic" && cargo build -p translator-shim --target wasm32-unknown-unknown --release)

say "setup complete

  iroh endpoint : .deps/polymorph-iroh/target/wasm32-wasip2/release/iroh_endpoint.wasm
  iroh relay    : .deps/polymorph-iroh/.deps/iroh/target/release/iroh-relay${WOSH_SKIP_RELAY:+ (skipped)}
  deltic shim   : .deps/deltic/target/wasm32-unknown-unknown/release/translator_shim.wasm

next: just build"
