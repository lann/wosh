#!/usr/bin/env bash
# Idempotent toolchain + dependency setup for wosh. Re-run freely.
#
# Everything external is pinned and fetched (the iroh endpoint component)
# or installed (the relay) under/onto .deps/ and PATH INSIDE the repo,
# deliberately: these artifacts are load-bearing (nothing composes without
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
# both of our components), fetched as the digest-pinned artifact its
# GitHub release carries -- built there at the release tag, on the
# pinned toolchain, by its release-assets workflow. The sibling
# host-crate tags in listener-host/Cargo.toml and smoke-test/Cargo.toml
# must stay content-identical (Rust + WIT) to the revs polymorph-iroh's
# own Cargo.toml pins, since the native hosts link those crates directly
# against the endpoint guest fetched here -- re-verify when bumping.
PIROH_VERSION=v0.5.1
ENDPOINT_SHA256=b656296fafe63ac73c081ef32d0876cb4def3df4de6595f8462ad5bf781ab668
# The relay binary version pairs with the iroh line the endpoint is
# built against (polymorph-iroh pins the same 1.0.3).
IROH_RELAY_VERSION=1.0.3

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

# --- iroh endpoint component: digest-pinned release artifact ----------
say "fetching the iroh endpoint component"
endpoint_versioned="$DEPS/iroh_endpoint-$PIROH_VERSION.wasm"
if ! sha256sum -c --status <<<"$ENDPOINT_SHA256  $endpoint_versioned" 2>/dev/null; then
  curl -fsSL -o "$endpoint_versioned" \
    "https://github.com/polymorph-components/polymorph-iroh/releases/download/$PIROH_VERSION/iroh_endpoint.wasm"
  sha256sum -c --status <<<"$ENDPOINT_SHA256  $endpoint_versioned" || {
    echo "iroh_endpoint.wasm digest mismatch (expected $ENDPOINT_SHA256)" >&2
    exit 1
  }
fi
# Stable path the justfile composes against; unconditional so a version
# bump above takes effect even when the versioned file was already cached.
cp "$endpoint_versioned" "$DEPS/iroh_endpoint.wasm"

# --- iroh-relay: prebuilt, pinned binary -------------------------------
say "checking iroh-relay"
if iroh-relay --version 2>/dev/null | grep -qF "$IROH_RELAY_VERSION"; then
  say "iroh-relay $IROH_RELAY_VERSION already on PATH"
else
  if command -v cargo-binstall >/dev/null 2>&1; then
    cargo binstall --no-confirm --locked --force "iroh-relay@$IROH_RELAY_VERSION"
  else
    # No prebuilt path without binstall; the source build needs the
    # server feature to produce the binary at all.
    cargo install "iroh-relay@$IROH_RELAY_VERSION" --locked --features server
  fi
  hash -r
  iroh-relay --version 2>/dev/null | grep -qF "$IROH_RELAY_VERSION" || {
    echo "iroh-relay --version does not report $IROH_RELAY_VERSION after install" \
         "-- check for a shadowing binary earlier on PATH: $(command -v iroh-relay)" >&2
    exit 1
  }
fi

say "setup complete

  iroh endpoint : .deps/iroh_endpoint.wasm ($PIROH_VERSION)
  iroh relay    : $(command -v iroh-relay) ($(iroh-relay --version 2>/dev/null || echo not found))

next: just build"
