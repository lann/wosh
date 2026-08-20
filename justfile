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

# The same listener with a WORKTREE-LOCAL identity, for hacking: each
# checkout gets its own endpoint id, so two of these coexist instead of
# fighting over the one identity in ~/.local/share/wosh (whose lock
# lets exactly one win). `just listener` keeps the machine-global
# identity -- that one is somebody's actual way in, and re-keying it
# would silently unpair their browsers.
dev-listener *args: build
    target/release/wosh-listener --identity-dir .deps/dev-identity {{args}}

# --- the static site --------------------------------------------------

# Bundle the deltic host layer for the page. The Deno-only WebRTC
# backends stay external: in a browser the module uses the platform's
# RTCPeerConnection and those dynamic imports never execute.
web-bundle:
    mkdir -p site/dist
    deno bundle --platform browser --format esm --config deno.json \
        --external node-datachannel --external node-datachannel/polyfill --external werift \
        --external "npm:node-datachannel*" --external "npm:werift*" \
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

# Gate processes are OWNED, never pattern-killed. scripts/gate-proc.sh
# starts each background process under a name, records its pid, and a
# recipe-level trap stops exactly those. Every gate here used to open
# with `pkill -f 'wosh-listene[r]'`, which killed other worktrees'
# gates and the operator's own dev listener along with the strays it
# was aiming at -- and it was there because nothing stopped what it
# started, so strays were the norm.
#
# Test listeners are --ephemeral-identity too: no identity on disk
# means no shared directory, no lock to contend for, and nothing left
# behind for the next run to trip over. e2e-pairing is the exception,
# because an enrollment outliving a restart is precisely its subject.
#
# Logs and pidfiles live under .deps/run/, which is per worktree; the
# logs gates grep their connstrings out of used to be fixed /tmp paths
# that two worktrees would clobber -- and then read each other's
# connstring out of, silently dialing the wrong listener.

# The ownership rules above, tested against a stand-in process: needs
# nothing built, and fails if `stop` ever reaches past its own pid.
test-gate-proc:
    scripts/gate-proc-test.sh

# Stop every gate process THIS worktree started, by pid. Never another
# worktree's, never your dev listener.
gates-down:
    scripts/gate-proc.sh stop-all

# The session-manager knowledge in site/sessions.mjs: what the presets
# run, what a session name may contain, which command lines read back
# as which preset, and the four list parsers against golden samples of
# what dtach, abduco, tmux and screen actually print. Pure node -- no
# browser, no listener, no target -- because the parsers are the part
# most likely to be subtly wrong and the part a browser gate can least
# easily reach.
test-sessions:
    node host-test/sessions-parse.mjs

# The passive host-key observer and its known_hosts policy: SSH
# handshake framing fed at every chunk boundary, host-pattern matching
# (globs, negation, hashed entries, @revoked, @cert-authority), and the
# full print/refuse table. All of it is invisible in the e2e gates --
# they run one loopback sshd whose key nothing corroborates -- so this
# is the only place the refusal paths are exercised at all.
test-hostkey:
    cargo test -p wosh-hostkey

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
    trap 'scripts/gate-proc.sh stop e2e' EXIT
    trap 'exit 130' INT TERM # cleanup stays in ONE place: the EXIT trap
    scripts/gate-proc.sh start e2e target/release/wosh-listener --ephemeral-identity \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr
    sleep 7
    cs=$(scripts/gate-proc.sh field e2e connstring)
    # The probe leg: a second channel on the live connection, its
    # output unmangled by any pty, run mid-session so the round-trip
    # right after it proves the interactive shell was never disturbed.
    target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs" --user "$USER" \
        --authorized-keys "$(scripts/test-sshd.sh authorized-keys)" \
        --expect-host-key "$(scripts/test-sshd.sh fingerprint)" \
        --probe 'echo probe-ok; echo probe-err >&2; exit 3' \
        --probe-expect-exit 3 --probe-expect-output probe-ok
    target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs" --user "$USER" --auth auto \
        --authorized-keys "$(scripts/test-sshd.sh authorized-keys)" \
        --expect-host-key "$(scripts/test-sshd.sh fingerprint)"
    # The exec leg: same channel and pty as the shell leg above, but
    # the on-connect command (the dtach/tmux/abduco reattach mechanism
    # in real use) runs instead of a shell, and its output and exit
    # status must surface to the caller.
    target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs" --user "$USER" \
        --authorized-keys "$(scripts/test-sshd.sh authorized-keys)" \
        --expect-host-key "$(scripts/test-sshd.sh fingerprint)" \
        --command 'echo wosh-exec-ok; exit 7' \
        --expect-output wosh-exec-ok --expect-exit 7

# The legibility gate for a passkey a server will not take.
#
# The sshd here is the one almost everyone actually runs -- password
# auth on, and the browser-webauthn algorithm left at its pre-10.3
# default of NOT enabled -- which is the combination behind the only
# bug this feature has had in the field. The key is refused, the server
# then offers password, and this client declines it; x/crypto reports
# the LAST error any method produced, so a careless decline ("password
# auth not selected") became the entire explanation of a failure that
# had nothing to do with passwords, and sent its reader looking in the
# wrong place.
#
# So this gate asserts the failure TEXT, not merely the failure. It
# runs its own sshd beside the shared one rather than reconfiguring it:
# `test-sshd.sh start` is idempotent, and a differently-configured sshd
# left running would be adopted by every later gate as the usual one.
e2e-passkey-unprepared: compose
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --release -p wosh-smoke-test
    pgrep -f 'iroh-rela[y]' >/dev/null || { {{RELAY}} --dev & sleep 3; }
    export WOSH_SSHD_NAME=unprepared WOSH_SSHD_UNPREPARED=1 WOSH_SSHD_PORT=2225
    scripts/test-sshd.sh start
    trap 'scripts/gate-proc.sh stop e2e-passkey-unprepared; scripts/test-sshd.sh stop' EXIT
    trap 'exit 130' INT TERM
    scripts/gate-proc.sh start e2e-passkey-unprepared target/release/wosh-listener --ephemeral-identity \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr
    sleep 7
    cs=$(scripts/gate-proc.sh field e2e-passkey-unprepared connstring)
    out=.deps/run/e2e-passkey-unprepared.out
    set +e
    target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs" --user "$USER" --auth passkey \
        --authorized-keys "$(scripts/test-sshd.sh authorized-keys)" \
        --expect-host-key "$(scripts/test-sshd.sh fingerprint)" > "$out" 2>&1
    rc=$?
    set -e
    if [ $rc -eq 0 ]; then
        echo "UNEXPECTED: the passkey authenticated against an sshd that never enabled the algorithm" >&2
        cat "$out" >&2; exit 1
    fi
    # It must blame the KEY and name the algorithm: that name is the
    # whole actionable content, since the cure is one sshd_config line.
    grep -q 'did not accept the offered key' "$out"
    grep -q 'webauthn-sk-ecdsa-sha2-nistp256@openssh.com' "$out"
    # ...and must not blame the password method, which was never part
    # of this.
    ! grep -q 'password auth not selected' "$out"
    echo
    echo "E2E-PASSKEY-UNPREPARED PASS: a server that has not enabled the algorithm fails legibly -- the error names the refused key, not the password method it also offered"

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
    trap 'scripts/gate-proc.sh stop kbdint kbdint-sshd' EXIT
    trap 'exit 130' INT TERM
    scripts/gate-proc.sh start kbdint-sshd target/gate/kbdint-sshd --port 2223
    fp=$(scripts/gate-proc.sh field kbdint-sshd fingerprint)
    scripts/gate-proc.sh start kbdint target/release/wosh-listener --ephemeral-identity \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:2223 --no-qr
    sleep 7
    cs=$(scripts/gate-proc.sh field kbdint connstring)
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
    trap 'scripts/gate-proc.sh stop e2e-passkey' EXIT
    trap 'exit 130' INT TERM
    scripts/gate-proc.sh start e2e-passkey target/release/wosh-listener --ephemeral-identity \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr
    sleep 7
    cs=$(scripts/gate-proc.sh field e2e-passkey connstring)
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
    trap 'scripts/gate-proc.sh stop e2e-passkey-recover' EXIT
    trap 'exit 130' INT TERM
    scripts/gate-proc.sh start e2e-passkey-recover target/release/wosh-listener --ephemeral-identity \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr
    sleep 7
    cs=$(scripts/gate-proc.sh field e2e-passkey-recover connstring)
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
    trap 'scripts/gate-proc.sh stop pairing-1 pairing-2' EXIT
    trap 'exit 130' INT TERM
    rm -rf .deps/test-pairing && mkdir -p .deps/test-pairing
    # --- run 1: pair with a valid token --------------------------------
    # The one gate that needs a listener identity on disk: enrollment
    # outliving a restart is what it is about. Its dir is its own.
    scripts/gate-proc.sh start pairing-1 target/release/wosh-listener --identity-dir .deps/test-pairing \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr
    sleep 7
    cs1=$(scripts/gate-proc.sh field pairing-1 connstring)
    target/release/wosh-smoke-test \
        --component target/components/wosh-ssh-client.wasm \
        --connstring "$cs1" --user "$USER" \
        --authorized-keys "$(scripts/test-sshd.sh authorized-keys)" \
        --pairing-store .deps/test-pairing/client-blob
    grep -q 'paired (valid token' "$(scripts/gate-proc.sh log pairing-1)"
    scripts/gate-proc.sh stop pairing-1
    sleep 1 # the identity dir's lock is released as run 1 exits
    # --- run 2: same listener identity, ROTATED token ------------------
    scripts/gate-proc.sh start pairing-2 target/release/wosh-listener --identity-dir .deps/test-pairing \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr
    sleep 7
    cs2=$(scripts/gate-proc.sh field pairing-2 connstring)
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
    log2=$(scripts/gate-proc.sh log pairing-2)
    for _ in $(seq 50); do
        grep -q 'refused: bad pairing token (and not a paired device)' "$log2" && break
        sleep 0.2
    done
    grep -q 'refused: bad pairing token (and not a paired device)' "$log2"
    echo "E2E-PAIRING PASS: enrollment survives token rotation; new devices still need a live token"

# The mobile layer under synthesized touch: a key fires on a tap and
# never on a drag (the strip scrolls under the same thumb), a freshly
# opened page leaves the soft keyboard reachable (nothing may hold a
# focus that cannot summon it), and a finger scrolls the TERMINAL
# rather than the page -- xterm answers only to a mouse and a wheel, so
# that gesture is the mobile layer's to drive. Drives site/mobile.mjs
# and the page's own stylesheet in headless Chromium -- no component,
# no relay -- so it needs no `just site`, only `just web-deps` once
# (the scrolling legs mount the real xterm from site/node_modules).
# Also the connect panel's shape, against the real boot.mjs with a
# stubbed component: setup stays folded, prompts land above the folds.
browser-mobile:
    node host-test/browser-mobile.mjs

# Browser gate: deltic instantiates the SSH client component in a real
# headless Chromium and runs guest code in-page. Needs `just site` first.
browser: site
    node host-test/browser-identity.mjs

# The addon family and the link policy, against the real assembled
# site with nothing else running (links, widths, and sixels work on
# whatever is in the buffer): unicode-11 widths active (an emoji is
# two cells), OSC 52 clipboard wired write-only, the webgl renderer
# up, a sixel decoding into the image addon -- and links opening on a
# single click only through the confirmation dialog: verbatim URI,
# cancel costs nothing, "always open" is opt-in and persists.
browser-links: site
    node host-test/browser-links.mjs

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
    trap 'scripts/gate-proc.sh stop browser-e2e' EXIT
    trap 'exit 130' INT TERM
    scripts/gate-proc.sh start browser-e2e target/release/wosh-listener --ephemeral-identity \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr
    sleep 7
    cs=$(scripts/gate-proc.sh field browser-e2e connstring)
    fp="$(scripts/test-sshd.sh fingerprint)"
    WOSH_CONNSTRING="$cs" \
    WOSH_AUTHORIZED_KEYS="$(scripts/test-sshd.sh authorized-keys)" \
    WOSH_EXPECT_FP="$fp" \
        node host-test/browser-e2e.mjs
    # The listener's own host-key line, checked against the SAME
    # fingerprint the page just made a human confirm. This is the only
    # place the two observers meet: the browser reads the key end to
    # end through the tunnel, the listener sniffs it off the cleartext
    # handshake it is proxying, and if those two ever disagree the
    # printout is worse than useless -- it would talk an operator into
    # approving something else.
    log="$(scripts/gate-proc.sh log browser-e2e)"
    if ! grep -q "host key of .*: $fp" "$log"; then
        echo "FAIL: the listener never printed sshd's fingerprint ($fp); its host-key lines were:" >&2
        grep -n 'host key' "$log" >&2 || echo "  (none)" >&2
        exit 1
    fi
    echo "[HK] the listener's sniffed fingerprint matches the one the page confirmed"

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
    trap 'scripts/gate-proc.sh stop browser-passkey' EXIT
    trap 'exit 130' INT TERM
    scripts/gate-proc.sh start browser-passkey target/release/wosh-listener --ephemeral-identity \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr
    sleep 7
    cs=$(scripts/gate-proc.sh field browser-passkey connstring)
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
    trap 'scripts/gate-proc.sh stop browser-idle' EXIT
    trap 'exit 130' INT TERM
    scripts/gate-proc.sh start browser-idle target/release/wosh-listener --ephemeral-identity \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr
    sleep 7
    cs=$(scripts/gate-proc.sh field browser-idle connstring)
    WOSH_CONNSTRING="$cs" \
    WOSH_AUTHORIZED_KEYS="$(scripts/test-sshd.sh authorized-keys)" \
        node host-test/browser-idle-e2e.mjs

# The mobile-background story: a FROZEN page (SIGSTOP on the renderer,
# the same not-scheduled-at-all a backgrounded phone performs) runs
# nothing for 45s, so its transport dies of silence and the listener
# parks the session. The thaw must recover it without a human:
# wake-probe (a tunnel PING instead of waiting out QUIC's idle
# timeout), resume, replay.
#
# This drill flushed out THREE upstream bugs. Two are fixed in the
# pinned chain, which is what lets this gate run in `check`:
#  - polymorph-iroh: a resource outliving its connection acted on the
#    slot's next occupant (handle reuse) -- its drop-implied reset(0)
#    killed every freshly resumed connection at birth. Fixed by the
#    epoch guard the PIROH_PIN carries (polymorph-iroh#78/#79).
#  - polymorph-webrtc-datachannels: the wasmtime host ran webrtc's
#    per-connection driver tasks on the embedder's own runtime, so one
#    wedged driver froze the whole component (deaf endpoint, zombie
#    sessions never idle-timing-out) AND starved the teardown that
#    would have ended the wedge. Fixed by driver reactor isolation,
#    carried by the datachannels rev pin (#158/#159): the wedge costs
#    a pool thread, then self-heals.
#  - The wedge's root -- rtc-ice pins a failed agent's wake-up
#    deadline in the past, and the webrtc driver loop spins on it at
#    full speed -- is fixed upstream in lann/rtc#2 (plus a
#    forward-progress floor handed to lann/webrtc); not needed for
#    this gate once the isolation is in, but worth landing.
browser-freeze: site hosts
    #!/usr/bin/env bash
    set -euo pipefail
    pgrep -f 'iroh-rela[y]' >/dev/null || { {{RELAY}} --dev & sleep 3; }
    scripts/test-sshd.sh start
    trap 'scripts/gate-proc.sh stop browser-freeze' EXIT
    trap 'exit 130' INT TERM
    scripts/gate-proc.sh start browser-freeze target/release/wosh-listener --ephemeral-identity \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr
    sleep 7
    cs=$(scripts/gate-proc.sh field browser-freeze connstring)
    WOSH_CONNSTRING="$cs" \
    WOSH_AUTHORIZED_KEYS="$(scripts/test-sshd.sh authorized-keys)" \
    WOSH_LISTENER_LOG="$(scripts/gate-proc.sh log browser-freeze)" \
        node host-test/browser-freeze.mjs

# The fall-through: a session no resume can bridge (the LISTENER
# restarts; its registry is memory) must end as `lost` and the page
# must open a fresh session by itself -- pinned host key answering the
# TOFU gate, pairing enrollment outliving the token rotation, the
# browser key signing silently, and a dim [wosh] divider marking the
# seam in the scrollback. The listener keeps its identity across the
# restart (its own dir), because that is what keeps the pin and the
# enrollment meaningful.
browser-fallthrough: site hosts
    #!/usr/bin/env bash
    set -euo pipefail
    pgrep -f 'iroh-rela[y]' >/dev/null || { {{RELAY}} --dev & sleep 3; }
    scripts/test-sshd.sh start
    trap 'scripts/gate-proc.sh stop browser-fallthrough' EXIT
    trap 'exit 130' INT TERM
    rm -rf .deps/test-fallthrough && mkdir -p .deps/test-fallthrough
    start="scripts/gate-proc.sh start browser-fallthrough target/release/wosh-listener \
        --identity-dir .deps/test-fallthrough \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr"
    $start
    sleep 7
    cs=$(scripts/gate-proc.sh field browser-fallthrough connstring)
    WOSH_CONNSTRING="$cs" \
    WOSH_AUTHORIZED_KEYS="$(scripts/test-sshd.sh authorized-keys)" \
    WOSH_STOP_CMD="scripts/gate-proc.sh stop browser-fallthrough" \
    WOSH_START_CMD="$start" \
        node host-test/browser-fallthrough.mjs

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
    trap 'scripts/gate-proc.sh stop browser-resume' EXIT
    trap 'exit 130' INT TERM
    scripts/gate-proc.sh start browser-resume target/release/wosh-listener --ephemeral-identity \
        --relay http://127.0.0.1:3340 \
        --target 127.0.0.1:$(scripts/test-sshd.sh port) --no-qr
    sleep 7
    cs=$(scripts/gate-proc.sh field browser-resume connstring)
    WOSH_CONNSTRING="$cs" \
    WOSH_AUTHORIZED_KEYS="$(scripts/test-sshd.sh authorized-keys)" \
    WOSH_RELAY_BIN="{{RELAY}}" \
        node host-test/browser-resume.mjs

# Smoke-check the DEPLOYED site (real https origin, so this also
# exercises service-worker registration, which local http cannot).
live:
    node host-test/live-check.mjs

check: test-gate-proc test-sessions test-connstring test-hostkey test-ssh-core test-tunnel test-webauthn-ssh spike-async e2e e2e-passkey e2e-passkey-recover e2e-passkey-unprepared e2e-kbdint e2e-pairing browser-mobile browser browser-links browser-e2e browser-passkey browser-idle-e2e browser-freeze browser-fallthrough browser-resume

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
