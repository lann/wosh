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

# Run the sync spike's exports under deltic (runtime-linked, Deno).
spike-sync-deltic: spike-sync-build
    cd spikes/componentize-go/runner && DELTIC_TRANSLATOR=$(just _translator) deno run --config ../../../deno.json --frozen -A run-sync-deltic.mjs

# Build the async/goroutine-abstraction spike component.
spike-async-build:
    cd spikes/componentize-go/async && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" componentize-go bindings --format && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" go mod tidy && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" componentize-go build

# Run the async spike under wasmtime (component-model async + p3).
spike-async-wasmtime: spike-async-build
    spikes/componentize-go/run-wasmtime-async.sh

# Run the async spike under deltic (component-model async; no engine
# flags needed — asyncness comes from the binary, not JSPI).
spike-async-deltic: spike-async-build
    cd spikes/componentize-go/runner && DELTIC_TRANSLATOR=$(just _translator) deno run --config ../../../deno.json --frozen -A run-async-deltic.mjs

# All spike legs, in gate order.
spikes: spike-sync-wasmtime spike-sync-deltic spike-async-wasmtime spike-async-deltic spike-keepalive-deltic spike-compose-wasmtime spike-compose-deltic

# Keep-alive probes (settlement pump / embedder-api A11): goroutine liveness
# between export calls — finding 31, wosh#25. Runs on the LOCAL deltic
# checkout (deno-local-deltic.json): A11 has no JSR prerelease yet.
spike-keepalive-deltic: spike-async-build
    cd spikes/componentize-go/runner && DELTIC_TRANSLATOR=$(just _translator) deno run --config deno-local-deltic.json --no-lock -A run-keepalive-deltic.mjs

# --- composition spike (D7) ----------------------------------------------

# Build the Rust adapter and wac-plug it with the engine component.
spike-compose-build: engine-build
    cd spikes/compose/adapter && cargo build --target wasm32-wasip2 --release
    wac plug spikes/compose/adapter/target/wasm32-wasip2/release/compose_spike_adapter.wasm --plug engine-go/main.wasm -o spikes/compose/composed.wasm

# Composed component under wasmtime (WAVE --invoke, exact answers).
spike-compose-wasmtime: spike-compose-build
    spikes/compose/run-wasmtime.sh

# Composed component runtime-linked by deltic, Deno leg.
spike-compose-deltic: spike-compose-build
    cd spikes/componentize-go/runner && DELTIC_TRANSLATOR=$(just _translator) deno run --config ../../../deno.json --frozen -A run-compose-deltic.mjs

# --- M1 engine + conformance -------------------------------------------

# Build the mosh engine component (bindings are committed; see below).
engine-build:
    cd engine-go && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" componentize-go build

# Regenerate bindings after a wit/mosh.wit change. componentize-go
# rewrites go.mod, so the .deps replace directive and pins are
# reapplied afterwards. Commit the result.
engine-bindings:
    cd engine-go && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" componentize-go bindings --format && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" go mod edit -replace github.com/unixshells/mosh-go=../.deps/mosh-go -require=github.com/unixshells/mosh-go@v0.5.3-0.20260405220648-8dca5c67ec8e -require=github.com/unixshells/vt-go@v0.1.0 && PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH" go mod tidy

# --- deltic host lane (the jco replacement) -------------------------------

# The deltic translator shim (built by scripts/setup.sh from the pinned
# .deps/deltic checkout); prints its path. Recipes capture it as
# DELTIC_TRANSLATOR for the Deno-lane drivers and the /dist route.
_translator:
    @test -f .deps/deltic/target/wasm32-unknown-unknown/release/translator_shim.wasm || { echo ".deps/deltic translator shim missing — run scripts/setup.sh" >&2; exit 1; }
    @realpath .deps/deltic/target/wasm32-unknown-unknown/release/translator_shim.wasm

# Engine instantiation smoke under wasmtime (version probe).
engine-wasmtime-smoke: engine-build
    wasmtime run --invoke 'version()' engine-go/main.wasm

# Conformance gate: engine (deltic/Deno, loopback UDP) vs stock C mosh-server.
conformance-c: engine-build
    cd host-test && DELTIC_TRANSLATOR=$(just _translator) deno run --config ../deno.json --frozen -A run-conformance.mjs --server c

# Same driver vs mosh-go's native server.
conformance-go: engine-build
    cd host-test && DELTIC_TRANSLATOR=$(just _translator) PATH="$HOME/.local/go/bin:$PATH" deno run --config ../deno.json --frozen -A run-conformance.mjs --server go

# All M1 legs, gate order.
m1: engine-wasmtime-smoke conformance-c conformance-go

# --- M2 browser mosh ------------------------------------------------------

# Bundle the deltic host layer for the page (web/dist/deltic.js). The
# Deno-only WebRTC backends stay external: in-browser the module uses the
# platform RTCPeerConnection and those dynamic imports never execute.
web-bundle:
    deno bundle --platform browser --format esm --config deno.json --external node-datachannel --external node-datachannel/polyfill --external werift -o web/dist/deltic.js web/deltic-entry.ts

# The M2 gate: xterm.js + engine in headless Chromium over the ws bridge
# (prompt, echo, resize, prediction-under-latency).
m2: engine-build web-bundle
    cd host-test && DELTIC_TRANSLATOR=$(just _translator) node browser-smoke.mjs

# Manual browser mosh: prints a URL; every tab gets its own shell.
web-serve: engine-build web-bundle
    cd host-test && DELTIC_TRANSLATOR=$(just _translator) node browser-smoke.mjs --serve

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
# control channel, TOFU, negative pairing-token path, >1162 B
# server datagrams sub-framed through the tunnel, and the console
# shutdown discipline (SIGINT graceful even mid-TOFU-prompt;
# double-SIGINT force-quit).
m4: compose-client compose-proxy proxy-build
    cd host-test/proxy-e2e && cargo run --release

# --- M5 browser client (D, unblocked parts) ---------------------------------

# Node + headless-Chromium gates for the M5 browser modules:
# connstring parsing, the localStorage schema, IndexedDB CryptoKey
# persistence (identity survives reloads), bootstrap panel flows.
m5-web:
    cd host-test && npm run web-tests

# The composed client on the Deno lane: the SAME artifact + deltic host
# modules the browser uses (relay wire, no UDP), against a real proxy —
# connect-proxy, M1 trio, stats, detach. The fast diagnostic between
# "components broke" and "the browser page broke".
m5-client-deno: compose-client compose-proxy proxy-build
    cd host-test && DELTIC_TRANSLATOR=$(just _translator) deno run --config ../deno.json --frozen -A client-e2e-deno.mjs

# The M5 browser E2E — the leg jco could never run (A3): the composed
# client runtime-linked by deltic IN THE PAGE speaks real mosh through a
# live proxy over iroh from headless Chromium; negative token path,
# M1 trio, stats, detach. Relay port :3352.
m5-browser-e2e: compose-client compose-proxy proxy-build web-bundle
    cd host-test && DELTIC_TRANSLATOR=$(just _translator) node browser-e2e.mjs

# The loopback netem matrix over the M3 gate (needs passwordless sudo
# for tc): delay/loss cells, per-phase timings as the measurement.
m5-netem:
    scripts/netem-matrix.sh

# The full M5 gate: web modules + both composed-client legs.
m5: m5-web m5-client-deno m5-browser-e2e

# --- M6 passkeys (E) ---------------------------------------------------------

# The M6 gate: passkey ceremonies over the control channel against a
# real webauthn-rs RP (soft authenticator), escrowed {key, seq-floor}
# blob returned verbatim, detach keeps the persistent session, and a
# FRESH client process reattaches: assertion-gated, crypto sequence
# above the escrowed floor, SSP state numbers adopted live from the
# server (finding 20), pre-detach screen resynced via the resize
# dance. Browser-side PRF wrap/unwrap + the D4 policy guard ride
# `just m5-web` (web-tests phase 3, CDP virtual authenticator); the
# full browser↔proxy ceremony E2E stays A3-blocked.
m6: compose-client compose-proxy proxy-build
    cd host-test/passkey-e2e && cargo run --release

# The M6 browser ceremony leg (finding 24 unblocked it): the full
# passkey lifecycle from the real page against the proxy's webauthn-rs
# RP — register, PRF-wrapped escrow, detach, reload (fresh client),
# assertion-gated reattach with screen resync, floor-jump re-escrow.
# CDP virtual authenticator (ctap2.1 + prf); page at localhost:3354,
# relay :3353.
m6-browser: compose-client compose-proxy proxy-build web-bundle
    cd host-test && DELTIC_TRANSLATOR=$(just _translator) node passkey-browser-e2e.mjs

# --- M7 inner ssh (F) ---------------------------------------------------------

# The M7 gate: DEPRIVILEGED proxy (no --personal — it spawns nothing
# and never sees mosh keys) with --ssh-target pointing at a russh
# sshd stand-in on loopback. The composed client dials over iroh,
# opens an SSH_FORWARD stream, speaks real ssh (x/crypto/ssh in the
# engine) through the tunnel, boots its own mosh-server via ssh exec,
# routes the datagram tunnel to it (ForwardDatagrams), and passes the
# M1 trio. Negatives: NewSession refused without --personal; wrong
# password fails legibly; wrong expected host key fails BEFORE the
# password is ever sent (stand-in observes zero auth attempts).
m7: compose-client compose-proxy proxy-build
    cd host-test/ssh-e2e && cargo run --release

# The M7 browser leg (last of the finding-24 unblocks): inner ssh from
# the real page through a DEPRIVILEGED proxy to the russh stand-in
# (ssh-e2e's sshd-standin bin) — TOFU host-key pin on first contact, a
# tampered pin refused BEFORE the password (stand-in's attempt counter
# proves it), restored pin reconnects. Relay :3355.
m7-browser: compose-client compose-proxy proxy-build web-bundle
    cd host-test/ssh-e2e && cargo build --release
    cd host-test && DELTIC_TRANSLATOR=$(just _translator) node ssh-browser-e2e.mjs

# --- running it (see README "Running the server") -----------------------------

# Build everything and run the proxy in personal mode (it spawns
# mosh-server as you on connect; needs mosh-server on PATH). The home
# relay defaults to n0's public NA-east iroh relay — the same relays
# stock iroh uses; RELAY=<url> overrides (other regions:
# usw1-1/euc1-1/aps1-1.relay.n0.iroh.link, or a self-hosted/loopback
# one as the e2e gates spawn). QR and passkey-RP defaults point at the
# deployed Pages client; extra args pass through to wosh-proxy, and
# later flags win (e.g. `just proxy-personal --yes --no-qr`).
proxy-personal *args: compose-proxy proxy-build
    proxy/target/release/wosh-proxy --relay "${RELAY:-https://use1-1.relay.n0.iroh.link}" \
        --rp-id lann.github.io --rp-origin https://lann.github.io \
        --personal {{args}}
