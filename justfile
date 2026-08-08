set shell := ["bash", "-cu"]

default:
    @just --list

# Idempotent toolchain setup (safe to re-run).
setup:
    scripts/setup.sh

# --- M0 spikes ---------------------------------------------------------

# Build the sync-export spike component with componentize-go.
spike-sync-build:
    cd spikes/componentize-go/sync && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" componentize-go bindings --format && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" go mod tidy && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" componentize-go build

# Run the sync spike's exports under wasmtime (WAVE --invoke).
spike-sync-wasmtime: spike-sync-build
    spikes/componentize-go/run-wasmtime-sync.sh

# Transpile the sync spike with the pinned jco fork and run under node.
spike-sync-jco: spike-sync-build
    cd spikes/componentize-go/runner && npm run transpile-sync && node run-sync-node.mjs

# Same transpiled module inside headless Chromium.
spike-sync-browser: spike-sync-build
    cd spikes/componentize-go/runner && npm run transpile-sync && node run-sync-browser.mjs

# Build the async/goroutine-abstraction spike component.
spike-async-build:
    cd spikes/componentize-go/async && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" componentize-go bindings --format && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" go mod tidy && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" componentize-go build

# Run the async spike under wasmtime (component-model async + p3).
spike-async-wasmtime: spike-async-build
    spikes/componentize-go/run-wasmtime-async.sh

# Transpile the async spike (JSPI) and run under node.
spike-async-jco: spike-async-build
    cd spikes/componentize-go/runner && npm run transpile-async && node --experimental-wasm-jspi run-async-node.mjs

# Same transpiled module inside headless Chromium (JSPI).
spike-async-browser: spike-async-build
    cd spikes/componentize-go/runner && npm run transpile-async && node run-async-browser.mjs

# All spike legs, in gate order.
spikes: spike-sync-wasmtime spike-sync-jco spike-sync-browser spike-async-wasmtime spike-async-jco spike-async-browser

# --- M1 engine + conformance -------------------------------------------

# Build the mosh engine component (bindings are committed; see below).
engine-build:
    cd engine-go && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" componentize-go build

# Regenerate bindings after a wit/mosh.wit change. componentize-go
# rewrites go.mod, so the .deps replace directive and pins are
# reapplied afterwards. Commit the result.
engine-bindings:
    cd engine-go && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" componentize-go bindings --format && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" go mod edit -replace github.com/unixshells/mosh-go=../.deps/mosh-go -require=github.com/unixshells/mosh-go@v0.5.3-0.20260405220648-8dca5c67ec8e -require=github.com/unixshells/vt-go@v0.1.0 && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" go mod tidy

# Engine instantiation smoke under wasmtime (version probe).
engine-wasmtime-smoke: engine-build
    wasmtime run --invoke 'version()' engine-go/main.wasm

# Transpile the engine for the node/browser hosts.
engine-transpile: engine-build
    cd host-test && npm run transpile

# Conformance gate: engine (jco/node, loopback UDP) vs stock C mosh-server.
conformance-c: engine-transpile
    cd host-test && npm run conformance-c

# Same driver vs mosh-go's native server.
conformance-go: engine-transpile
    cd host-test && PATH="$HOME/.local/go/bin:$PATH" npm run conformance-go

# All M1 legs, gate order.
m1: engine-wasmtime-smoke conformance-c conformance-go
