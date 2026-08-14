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

# The browser SSH client, two components: the sans-I/O SSH core (Go,
# x/crypto/ssh as a byte-and-tick machine) and the wosh-client
# orchestrator (Rust: connstring, the iroh dial, byte pumping, the
# identity-store signature relay).
client:
    cd ssh-core && componentize-go build
    cargo build --target wasm32-wasip2 --release -p wosh-client

# Fuse the pieces: the listener with the endpoint; the client with the
# SSH core and the endpoint.
compose: listener-core client
    mkdir -p target/components
    wac plug target/wasm32-wasip2/release/wosh_listener_core.wasm \
        --plug {{ENDPOINT}} -o target/components/wosh-listener.wasm
    wac plug target/wasm32-wasip2/release/wosh_client.wasm \
        --plug ssh-core/main.wasm --plug {{ENDPOINT}} \
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

# The connection-string format: the Rust crate is the single owner and
# decoder now (the Go core never sees a connstring).
test-connstring:
    cargo test -p wosh-connstring

# The sans-I/O SSH core's host-side tests: a real x/crypto/ssh server
# bridged over the shuttle, covering the host-key gate, every auth
# method, the signature and prompt park-and-poll surfaces, and wire
# teardown.
test-ssh-core:
    cd ssh-core && go vet ./core/ && go test ./core/

# The three componentize-go async measurements behind this design; see
# README "Findings". The lifting probe is two direct wasmtime invokes
# because the first is expected to trap.
spike-async:
    # go.sum is deliberately not committed for the spike (.gitignore);
    # regenerate it so a fresh tree builds (`go mod download` is not
    # enough: it records the go.mod hash only, not the module sum).
    cd spikes/go-async && go mod tidy && componentize-go build
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
# Two legs: explicit publickey, then auto -- the sshd speaks only
# publickey, so auto must resolve to the same silent signature flow.
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
    target/release/wosh-listener --identity-dir .deps/test-listener-data \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr > /tmp/wosh-e2e-listener.log 2>&1 &
    sleep 7
    cs=$(grep '^connstring: ' /tmp/wosh-e2e-listener.log | cut -d" " -f2)
    target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs" --user "$USER" \
        --authorized-keys "$(scripts/test-sshd.sh authorized-keys)" \
        --expect-host-key "$(scripts/test-sshd.sh fingerprint)"
    target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs" --user "$USER" --auth auto \
        --authorized-keys "$(scripts/test-sshd.sh authorized-keys)" \
        --expect-host-key "$(scripts/test-sshd.sh fingerprint)"

# Keyboard-interactive, end to end: the same composed client, over the
# same real iroh path, against the scripted x/crypto stand-in server
# (real sshd cannot do kbd-interactive as a user process -- its only
# backends are PAM and BSDAuth). Positive leg answers two prompt
# batches (echoed + masked, then a second round); negative leg proves
# a wrong answer fails legibly; auto leg proves the server steers auto
# to keyboard-interactive when that is all it offers.
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
    target/release/wosh-listener --identity-dir .deps/test-listener-data \
        --relay http://127.0.0.1:3340 \
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
    target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs" --user gate --auth auto \
        --kbd-answers 'gate-token-123,gate-passphrase-456,gate-otp-789' \
        --expect-host-key "$fp"

# Passkey, end to end: the same composed client, over the same real
# iroh path, into the same real OpenSSH sshd -- but authenticated by
# `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` instead of plain
# publickey. This is what proves the OpenSSH webauthn WIRE FORMAT
# (authenticatorData, clientDataJSON, the DER signature, the
# authorized_keys line's `application` field) against a stock,
# unmodified sshd -- no browser, no server-side change, just a
# software authenticator standing in for the platform one (see
# smoke-test/src/passkey.rs). What this gate cannot prove is the
# ceremony itself (the user gesture, the platform prompt); that stays
# the browser gate's job. If this leg passes, the browser gate only
# has to show the ceremony happens -- the bytes it produces are
# already proven to authenticate for real.
e2e-passkey: compose
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --release -p wosh-smoke-test
    pgrep -f 'iroh-rela[y]' >/dev/null || { {{RELAY}} --dev & sleep 3; }
    scripts/test-sshd.sh start
    pkill -f 'wosh-listene[r]' 2>/dev/null || true
    sleep 1
    target/release/wosh-listener --identity-dir .deps/test-listener-data \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr > /tmp/wosh-e2e-passkey-listener.log 2>&1 &
    sleep 7
    cs=$(grep '^connstring: ' /tmp/wosh-e2e-passkey-listener.log | cut -d" " -f2)
    target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs" --user "$USER" --auth passkey \
        --authorized-keys "$(scripts/test-sshd.sh authorized-keys)" \
        --expect-host-key "$(scripts/test-sshd.sh fingerprint)"

# Recovery, end to end: a client that lost its stored passkey identity
# (browser storage evicted -- simulated here by `forget-passkey`) but
# still has the passkey ITSELF reconstructs the exact same SSH identity
# from two WebAuthn assertions alone, and authenticates with it against
# a real, unmodified sshd -- without ever touching the
# `authorized_keys` line already installed on the target. That last
# part is the whole property under test: recovery is only useful if it
# lands on the SAME key the target already trusts, not merely a
# working one. See `wosh-webauthn-ssh::recover_public_key` for the
# maths and `wosh-client/src/passkey.rs::recover()` for the client
# flow; this leg proves both end to end with no browser involved (see
# smoke-test/src/passkey.rs's `assert_unknown`/`remember`).
e2e-passkey-recover: compose
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --release -p wosh-smoke-test
    pgrep -f 'iroh-rela[y]' >/dev/null || { {{RELAY}} --dev & sleep 3; }
    scripts/test-sshd.sh start
    pkill -f 'wosh-listene[r]' 2>/dev/null || true
    sleep 1
    target/release/wosh-listener --identity-dir .deps/test-listener-data \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr > /tmp/wosh-e2e-passkey-recover-listener.log 2>&1 &
    sleep 7
    cs=$(grep '^connstring: ' /tmp/wosh-e2e-passkey-recover-listener.log | cut -d" " -f2)
    target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs" --user "$USER" --auth passkey-recover \
        --authorized-keys "$(scripts/test-sshd.sh authorized-keys)" \
        --expect-host-key "$(scripts/test-sshd.sh fingerprint)"

# Pairing, end to end: a client that once presented a valid token is
# REMEMBERED (its iroh id is enrolled), so a printed QR keeps working
# for that device across listener restarts and token rotation -- while
# a NEW device with the same stale connstring is refused. This is the
# gate for the stale-QR trap: rotation gates new devices only.
e2e-pairing: compose
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --release -p wosh-smoke-test
    pgrep -f 'iroh-rela[y]' >/dev/null || { {{RELAY}} --dev & sleep 3; }
    scripts/test-sshd.sh start
    pkill -f 'wosh-listene[r]' 2>/dev/null || true
    sleep 1
    rm -rf .deps/test-pairing && mkdir -p .deps/test-pairing
    # --- run 1: pair with a valid token --------------------------------
    target/release/wosh-listener --identity-dir .deps/test-pairing \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr > /tmp/wosh-pairing-1.log 2>&1 &
    sleep 7
    cs1=$(grep '^connstring: ' /tmp/wosh-pairing-1.log | cut -d" " -f2)
    target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs1" --user "$USER" \
        --authorized-keys "$(scripts/test-sshd.sh authorized-keys)" \
        --pairing-store .deps/test-pairing/client-blob
    grep -q 'paired (valid token' /tmp/wosh-pairing-1.log
    pkill -f 'wosh-listene[r]' 2>/dev/null || true
    sleep 1
    # --- run 2: same listener identity, ROTATED token ------------------
    target/release/wosh-listener --identity-dir .deps/test-pairing \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr > /tmp/wosh-pairing-2.log 2>&1 &
    sleep 7
    cs2=$(grep '^connstring: ' /tmp/wosh-pairing-2.log | cut -d" " -f2)
    test "$cs1" != "$cs2"   # same identity, different token: genuinely stale
    # the PAIRED device, still holding the run-1 connstring: must work
    target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs1" --user "$USER" \
        --authorized-keys "$(scripts/test-sshd.sh authorized-keys)" \
        --pairing-store .deps/test-pairing/client-blob
    # a NEW device with the stale connstring: must be refused
    ! target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs1" --user "$USER" \
        --authorized-keys "$(scripts/test-sshd.sh authorized-keys)" 2>&1 \
        | grep -q 'E2E PASS'
    # Wait for the refusal, do not race it: the client learns it was
    # refused over the tunnel, which can beat the listener's own log
    # write to disk. Grepping once turns that ordering into a flake.
    for _ in $(seq 50); do
        grep -q 'refused: bad pairing token (and not a paired device)' /tmp/wosh-pairing-2.log && break
        sleep 0.2
    done
    grep -q 'refused: bad pairing token (and not a paired device)' /tmp/wosh-pairing-2.log
    echo "E2E-PAIRING PASS: enrollment survives token rotation; new devices still need a live token"

# Extra-keys bar gesture gate: a key fires on a tap and never on a drag
# (the strip scrolls under the same thumb). Drives site/mobile.mjs and
# the page's own stylesheet with synthesized touch in headless Chromium
# -- no component, no relay -- so it needs no `just site`, only
# `just web-deps` once.
browser-keys:
    node host-test/browser-keys.mjs

# Browser gate: deltic instantiates the SSH client component in a real
# headless Chromium and runs guest code in-page. Needs `just site` first.
browser: site
    node host-test/browser-identity.mjs

# Browser END TO END: the real page -- form, interactive host-key
# prompt, xterm -- in headless Chromium, over real iroh, through the
# listener, into a real sshd. This is the gate that fails if the page
# ever skips the interactive fingerprint confirmation (TOFU): the
# native e2e drives the component through typed bindings and cannot
# see how the page reads deltic's JS conventions.
browser-e2e: site hosts
    #!/usr/bin/env bash
    set -euo pipefail
    pgrep -f 'iroh-rela[y]' >/dev/null || { {{RELAY}} --dev & sleep 3; }
    scripts/test-sshd.sh start
    pkill -f 'wosh-listene[r]' 2>/dev/null || true
    sleep 1
    target/release/wosh-listener --identity-dir .deps/test-listener-data \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr > /tmp/wosh-browser-e2e-listener.log 2>&1 &
    sleep 7
    cs=$(grep '^connstring: ' /tmp/wosh-browser-e2e-listener.log | cut -d" " -f2)
    WOSH_CONNSTRING="$cs" \
    WOSH_AUTHORIZED_KEYS="$(scripts/test-sshd.sh authorized-keys)" \
    WOSH_EXPECT_FP="$(scripts/test-sshd.sh fingerprint)" \
        node host-test/browser-e2e.mjs

# Browser passkey gate: the real page enrolling and authenticating with
# a WebAuthn passkey (a CDP virtual authenticator standing in for a
# platform one), through the real listener into a real sshd. This
# proves the CEREMONY -- enrol/adopt/forget UI, the ceremony gate's
# user-gesture prompt, the actual navigator.credentials calls; e2e-passkey
# (above) is the sibling that proves the wire format (the OpenSSH
# webauthn algorithm bytes) against real sshd with a software
# authenticator and no browser at all. Each covers what the other
# cannot.
browser-passkey: site hosts
    #!/usr/bin/env bash
    set -euo pipefail
    pgrep -f 'iroh-rela[y]' >/dev/null || { {{RELAY}} --dev & sleep 3; }
    scripts/test-sshd.sh start
    pkill -f 'wosh-listene[r]' 2>/dev/null || true
    sleep 1
    target/release/wosh-listener --identity-dir .deps/test-listener-data \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr > /tmp/wosh-browser-passkey-listener.log 2>&1 &
    sleep 7
    cs=$(grep '^connstring: ' /tmp/wosh-browser-passkey-listener.log | cut -d" " -f2)
    WOSH_CONNSTRING="$cs" \
    WOSH_AUTHORIZED_KEYS="$(scripts/test-sshd.sh authorized-keys)" \
    WOSH_EXPECT_FP="$(scripts/test-sshd.sh fingerprint)" \
        node host-test/browser-passkey.mjs

# Browser idle survival: the real page stays connected across an idle
# window longer than QUIC's 30s max_idle_timeout, and a post-idle
# keystroke still round-trips. Guards the polymorph-iroh keepalive pin
# (its #70: an idle session used to die at ~30s, and on the
# pre-refactor client the death wedged the guest into a "deadlock
# detected" trap on the next keystroke). ~50s of deliberate idle, so it
# runs after the fast browser legs.
browser-idle-e2e: site hosts
    #!/usr/bin/env bash
    set -euo pipefail
    pgrep -f 'iroh-rela[y]' >/dev/null || { {{RELAY}} --dev & sleep 3; }
    scripts/test-sshd.sh start
    pkill -f 'wosh-listene[r]' 2>/dev/null || true
    sleep 1
    target/release/wosh-listener --identity-dir .deps/test-listener-data \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr > /tmp/wosh-browser-idle-listener.log 2>&1 &
    sleep 7
    cs=$(grep '^connstring: ' /tmp/wosh-browser-idle-listener.log | cut -d" " -f2)
    WOSH_CONNSTRING="$cs" \
    WOSH_AUTHORIZED_KEYS="$(scripts/test-sshd.sh authorized-keys)" \
        node host-test/browser-idle-e2e.mjs

# Resume, end to end in a real browser: a live session must survive a
# relay restart -- client endpoint rebind + resume machine, listener
# accept-loop rebind + re-registration, offset-exchange replay. This
# gate RESTARTS THE RELAY; it runs last so it cannot destabilize the
# other gates' listeners.
browser-resume: site hosts
    #!/usr/bin/env bash
    set -euo pipefail
    pgrep -f 'iroh-rela[y]' >/dev/null || { {{RELAY}} --dev & sleep 3; }
    scripts/test-sshd.sh start
    pkill -f 'wosh-listene[r]' 2>/dev/null || true
    sleep 1
    target/release/wosh-listener --identity-dir .deps/test-listener-data \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr > /tmp/wosh-browser-resume-listener.log 2>&1 &
    sleep 7
    cs=$(grep '^connstring: ' /tmp/wosh-browser-resume-listener.log | cut -d" " -f2)
    WOSH_CONNSTRING="$cs" \
    WOSH_AUTHORIZED_KEYS="$(scripts/test-sshd.sh authorized-keys)" \
    WOSH_RELAY_BIN="{{RELAY}}" \
        node host-test/browser-resume.mjs

# Smoke-check the DEPLOYED site (real https origin, so this also
# exercises service-worker registration, which local http cannot).
live:
    node host-test/live-check.mjs

check: test-connstring test-ssh-core test-tunnel test-webauthn-ssh spike-async e2e e2e-passkey e2e-passkey-recover e2e-kbdint e2e-pairing browser-keys browser browser-e2e browser-passkey browser-idle-e2e browser-resume

# The tunnel framing (protocol v2): codec golden bytes + replay
# bookkeeping, shared by wosh-client and listener-core.
test-tunnel:
    cargo test -p wosh-tunnel

# The WebAuthn-to-SSH wire mapping: the authorized_keys line a passkey
# produces, and the layout of the signature that answers for it. Every
# rule in here is one sshd enforces silently several round trips away,
# so these are the cheap versions of the e2e-passkey failure.
test-webauthn-ssh:
    cargo test -p wosh-webauthn-ssh
