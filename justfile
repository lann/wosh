set shell := ["bash", "-cu"]

# componentize-go installs to GOBIN, and needs a newer Go than most
# distributions ship; prefer a locally-installed one.
export PATH := env_var('HOME') + "/.local/go/bin:" + env_var('HOME') + "/go/bin:" + env_var('PATH')

ENDPOINT := ".deps/polymorph-iroh/target/wasm32-wasip2/release/iroh_endpoint.wasm"
RELAY    := ".deps/polymorph-iroh/.deps/iroh/target/release/iroh-relay"

default:
    @just --list

# Pins + builds every external dependency into .deps/ (idempotent).
setup:
    scripts/setup.sh

# --- components -------------------------------------------------------

# The wasi:cli@0.3.1 listener component.
listener-core:
    cargo build --target wasm32-wasip2 --release -p wosh-listener-core

# The browser SSH client: x/crypto/ssh over iroh, one Go component.
client:
    cd client-go && componentize-go build

# Fuse each component with the polymorph-iroh endpoint.
compose: listener-core client
    mkdir -p target/components
    wac plug target/wasm32-wasip2/release/wosh_listener_core.wasm \
        --plug {{ENDPOINT}} -o target/components/wosh-listener.wasm
    wac plug client-go/main.wasm --plug {{ENDPOINT}} \
        -o target/components/wosh-ssh-client.wasm

# Native hosts.
hosts:
    cargo build --release -p wosh-listener-host

build: compose hosts

# --- running ----------------------------------------------------------

# A local relay, for development and the gates.
relay:
    {{RELAY}} --dev

# Run the listener. Defaults to the public iroh relay and --target
# 127.0.0.1:22; extra args pass through, e.g.
#   just listener --no-token
#   just listener --relay http://127.0.0.1:3340   # local dev (or RELAY_URL=)
listener *args: build
    target/release/wosh-listener {{args}}

# --- the static site --------------------------------------------------

# Bundle the deltic host layer for the page. The Deno-only WebRTC
# backends stay external: in a browser the module uses the platform's
# RTCPeerConnection and those dynamic imports never execute.
web-bundle:
    mkdir -p site/dist
    deno bundle --platform browser --format esm --config deno.json \
        --external node-datachannel --external node-datachannel/polyfill --external werift \
        -o site/dist/deltic.js site/deltic-entry.ts

# xterm assets + the browser-gate driver (once).
web-deps:
    cd site && npm install --no-fund --no-audit
    npm install --prefix host-test --no-fund --no-audit

# Assemble a servable tree in out/.
site out="out": compose web-bundle
    scripts/site-deploy-tree.sh {{out}}

# Serve it locally.
serve out="out": (site out)
    python3 -m http.server -d {{out}} 8080

# --- gates ------------------------------------------------------------

# The connection-string format (shared by both ends).
test-connstring:
    cargo test -p wosh-connstring

# The three componentize-go async measurements behind this design; see
# README "Findings". The lifting probe is two direct wasmtime invokes
# because the first is expected to trap.
spike-async:
    cd spikes/go-async && componentize-go build
    cargo build --release -p wosh-spike-go-async-host
    target/release/wosh-spike-go-async-host spikes/go-async/main.wasm all
    @echo "--- lifting: a SYNC export calling an async import must TRAP ---"
    @! wasmtime run -W component-model-async=y --invoke 'sync-calls-async(50)' \
        spikes/go-async/main.wasm 2>&1 | grep -q 'unreachable' \
        && echo "UNEXPECTED: it did not trap" && exit 1 || echo "traps, as expected"
    wasmtime run -W component-model-async=y --invoke 'async-calls-async(50)' \
        spikes/go-async/main.wasm

# End to end: the composed client under wasmtime, over real iroh,
# through the listener, into a REAL OpenSSH sshd, authenticated with
# the non-extractable WebCrypto key the component mints for itself.
#
# Brings up everything it needs: a local relay, a throwaway sshd, and a
# listener pointed at it. smoke-test is excluded from the workspace
# (it drives an artifact rather than being one), so it builds via its
# own manifest.
e2e: compose
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --release -p wosh-smoke-test
    pgrep -f 'iroh-rela[y]' >/dev/null || { {{RELAY}} --dev & sleep 3; }
    scripts/test-sshd.sh start
    pkill -f 'wosh-listene[r]' 2>/dev/null || true
    sleep 1
    target/release/wosh-listener --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr > /tmp/wosh-e2e-listener.log 2>&1 &
    sleep 7
    cs=$(grep '^connstring: ' /tmp/wosh-e2e-listener.log | cut -d" " -f2)
    target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs" --user "$USER" \
        --authorized-keys "$(scripts/test-sshd.sh authorized-keys)" \
        --expect-host-key "$(scripts/test-sshd.sh fingerprint)"

# Keyboard-interactive, end to end: the same composed client, over the
# same real iroh path, against the scripted x/crypto stand-in server
# (real sshd cannot do kbd-interactive as a user process -- its only
# backends are PAM and BSDAuth). Positive leg answers two prompt
# batches (echoed + masked, then a second round); negative leg proves
# a wrong answer fails legibly.
e2e-kbdint: compose
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --release -p wosh-smoke-test
    (cd kbdint-sshd && go build -o ../target/gate/kbdint-sshd .)
    pgrep -f 'iroh-rela[y]' >/dev/null || { {{RELAY}} --dev & sleep 3; }
    pkill -f 'wosh-listene[r]' 2>/dev/null || true
    pkill -f 'kbdint-ssh[d]' 2>/dev/null || true
    sleep 1
    target/gate/kbdint-sshd --port 2223 > /tmp/wosh-kbdint-sshd.log 2>&1 &
    sleep 1
    fp=$(grep '^fingerprint: ' /tmp/wosh-kbdint-sshd.log | cut -d" " -f2)
    target/release/wosh-listener --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:2223 --no-qr > /tmp/wosh-kbdint-listener.log 2>&1 &
    sleep 7
    cs=$(grep '^connstring: ' /tmp/wosh-kbdint-listener.log | cut -d" " -f2)
    target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs" --user gate --auth kbd \
        --kbd-answers 'gate-token-123,gate-passphrase-456,gate-otp-789' \
        --expect-host-key "$fp"
    target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs" --user gate --auth kbd \
        --kbd-answers 'gate-token-123,WRONG,gate-otp-789' \
        --expect-auth-fail

# Browser gate: deltic instantiates the SSH client component in a real
# headless Chromium and runs guest code in-page. Needs `just site` first.
browser: site
    node host-test/browser-identity.mjs

# Smoke-check the DEPLOYED site (real https origin, so this also
# exercises service-worker registration, which local http cannot).
live:
    node host-test/live-check.mjs

check: test-connstring spike-async e2e e2e-kbdint browser
