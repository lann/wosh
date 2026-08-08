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
spikes: spike-sync-wasmtime spike-sync-jco spike-sync-browser spike-async-wasmtime spike-async-jco spike-async-browser spike-compose-wasmtime spike-compose-jco spike-compose-browser

# --- composition spike (D7) ----------------------------------------------

# Build the Rust adapter and wac-plug it with the engine component.
spike-compose-build: engine-build
    cd spikes/compose/adapter && cargo build --target wasm32-wasip2 --release
    wac plug spikes/compose/adapter/target/wasm32-wasip2/release/compose_spike_adapter.wasm --plug engine-go/main.wasm -o spikes/compose/composed.wasm

# Composed component under wasmtime (WAVE --invoke, exact answers).
spike-compose-wasmtime: spike-compose-build
    spikes/compose/run-wasmtime.sh

# Composed component transpiled by the pinned jco fork, node leg.
spike-compose-jco: spike-compose-build
    cd spikes/componentize-go/runner && npm run transpile-compose && node run-compose-node.mjs

# Same transpiled composition inside headless Chromium.
spike-compose-browser: spike-compose-build
    cd spikes/componentize-go/runner && npm run transpile-compose && node run-compose-browser.mjs

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

# --- M2 browser mosh ------------------------------------------------------

# The M2 gate: xterm.js + engine in headless Chromium over the ws bridge
# (prompt, echo, resize, prediction-under-latency).
m2: engine-transpile
    cd host-test && node browser-smoke.mjs

# Manual browser mosh: prints a URL; every tab gets its own shell.
web-serve: engine-transpile
    cd host-test && node browser-smoke.mjs --serve

# --- M3 composed client core (D7/B2) ---------------------------------------

# Build the client-core glue component.
client-core-build:
    cd client-core && cargo build --target wasm32-wasip2 --release

# Fuse engine + glue + endpoint into the composed client artifact.
compose-client: engine-build client-core-build
    wac plug client-core/target/wasm32-wasip2/release/client_core.wasm --plug engine-go/main.wasm --plug .deps/polymorph-iroh/target/wasm32-wasip2/release/iroh_endpoint.wasm -o client-core/composed-client.wasm

# The M3 gate: the composed core under wasmtime speaks mosh over iroh
# datagrams to a stock mosh-server behind an upstream-iroh forwarder.
m3: compose-client
    cd host-test/composed-e2e && cargo run --release -- ../../client-core/composed-client.wasm

# --- M4 proxy (C/D9) --------------------------------------------------------

# Build the proxy-core brain component.
proxy-core-build:
    cd proxy-core && cargo build --target wasm32-wasip2 --release

# Fuse proxy-core + endpoint into the composed proxy artifact.
compose-proxy: proxy-core-build
    wac plug proxy-core/target/wasm32-wasip2/release/proxy_core.wasm --plug .deps/polymorph-iroh/target/wasm32-wasip2/release/iroh_endpoint.wasm -o proxy/composed-proxy.wasm

# Build the native proxy shell binary.
proxy-build:
    cd proxy && cargo build --release

# The M4 gate: composed client ↔ proxy (thin shell + composed
# proxy-core) ↔ proxy-spawned stock mosh-server, over real iroh —
# control channel, TOFU, negative pairing-token path, and >1162 B
# server datagrams sub-framed through the tunnel.
m4: compose-client compose-proxy proxy-build
    cd host-test/proxy-e2e && cargo run --release

# --- M5 browser client (D, unblocked parts) ---------------------------------

# Node + headless-Chromium gates for the M5 browser modules:
# connstring parsing, the localStorage schema, IndexedDB CryptoKey
# persistence (identity survives reloads), bootstrap panel flows.
m5-web:
    cd host-test && npm run web-tests

# Probe the A3-blocked leg: the composed client transpiled by the
# pinned jco fork (JSPI) against a real proxy. Prints a classification;
# currently THROWS AT INSTANTIATION (composed-resource TDZ,
# lann/jco#51 — minimal repro in spikes/compose-async-tdz/).
m5-jco-probe: compose-client compose-proxy proxy-build
    cd host-test && npm run jco-probe

# The loopback netem matrix over the M3 gate (needs passwordless sudo
# for tc): delay/loss cells, per-phase timings as the measurement.
m5-netem:
    scripts/netem-matrix.sh

# The unblocked-parts gate.
m5: m5-web
