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
