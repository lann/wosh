//! The end-to-end gate: the composed browser SSH client, under
//! wasmtime, dialing a real listener over real iroh, proxied to a
//! **real OpenSSH sshd**, authenticated by publickey through the
//! host's `identity-store` (in a browser that is a non-extractable
//! WebCrypto key in IndexedDB; here, a per-run key this host holds).
//!
//! Everything the browser would do, minus the browser: the same
//! composed artifact, the same `wosh:terminal` interface, the same
//! polymorph host implementations. What a browser adds on top is
//! polyengine and xterm.js, not different component behaviour.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use ed25519_dalek::Signer as _;
use polymorph_webcrypto_wasmtime::{WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView};
use wasmtime::component::{Accessor, Component, HasSelf, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_webrtc_datachannels::{self as webrtc_host, WebrtcCtx, WebrtcCtxView, WebrtcView};
use wasmtime_websocket::{WasiWebsocketCtx, WasiWebsocketCtxView, WasiWebsocketView};

mod passkey;
mod transfer;

mod bindings {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "composed-client",
        imports: { default: async | store | trappable },
        exports: { default: async },
        // `transfer-io`'s two resources are HOST resources: the
        // component holds handles, the host holds the actual bytes.
        // Naming the concrete types here is what lets this host push
        // them into its own `ResourceTable` (an unmapped resource
        // binds to an uninhabited enum, which nothing can construct).
        with: {
            "wosh:terminal/transfer-io.source": crate::transfer::MemSource,
            "wosh:terminal/transfer-io.sink": crate::transfer::FileSink,
        },
    });
}

use bindings::exports::wosh::terminal::terminal::Status;
use bindings::wosh::terminal::identity_store;
use bindings::wosh::terminal::pairing_store;
use bindings::wosh::terminal::passkey_store;
use bindings::wosh::terminal::transfer_io;

struct Ctx {
    wasi: WasiCtx,
    webrtc: WebrtcCtx,
    webcrypto: WasiWebcryptoCtx,
    websocket: WasiWebsocketCtx,
    /// The run's SSH identity, behind `wosh:terminal/identity-store`.
    /// Minted fresh per run -- a gate run IS one browser visit; what
    /// persistence adds in a real browser (IndexedDB) is the browser
    /// gate's to assert. Sign-only surface, exactly like the page's.
    identity: ed25519_dalek::SigningKey,
    /// The run's software WebAuthn authenticator, behind
    /// `wosh:terminal/passkey-store`. See `passkey.rs`.
    passkey: passkey::SoftAuthenticator,
    /// The pairing blob behind `wosh:terminal/pairing-store`. In
    /// memory by default (fresh client per run); `--pairing-store
    /// <file>` persists it, which is what lets the pairing gate span
    /// two invocations the way a browser's IndexedDB spans reloads.
    pairing_path: Option<PathBuf>,
    pairing_blob: Option<Vec<u8>>,
    table: ResourceTable,
}

impl WasiView for Ctx {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.wasi, table: &mut self.table }
    }
}
impl WebrtcView for Ctx {
    fn webrtc(&mut self) -> WebrtcCtxView<'_> {
        WebrtcCtxView { ctx: &mut self.webrtc, table: &mut self.table }
    }
}
impl WasiWebcryptoView for Ctx {
    fn webcrypto(&mut self) -> WasiWebcryptoCtxView<'_> {
        WasiWebcryptoCtxView { ctx: &mut self.webcrypto, table: &mut self.table }
    }
}
impl WasiWebsocketView for Ctx {
    fn websocket(&mut self) -> WasiWebsocketCtxView<'_> {
        WasiWebsocketCtxView { ctx: &mut self.websocket, table: &mut self.table }
    }
}

impl identity_store::Host for Ctx {}

impl identity_store::HostWithStore<Ctx> for HasSelf<Ctx> {
    async fn public_key(
        accessor: &Accessor<Ctx, Self>,
    ) -> wasmtime::Result<std::result::Result<Vec<u8>, String>> {
        Ok(Ok(accessor.with(|mut a| a.get().identity.verifying_key().to_bytes().to_vec())))
    }

    async fn sign(
        accessor: &Accessor<Ctx, Self>,
        data: Vec<u8>,
    ) -> wasmtime::Result<std::result::Result<Vec<u8>, String>> {
        Ok(Ok(accessor.with(|mut a| a.get().identity.sign(&data).to_bytes().to_vec())))
    }
}

impl passkey_store::Host for Ctx {}

impl passkey_store::HostWithStore<Ctx> for HasSelf<Ctx> {
    async fn identity(
        accessor: &Accessor<Ctx, Self>,
    ) -> wasmtime::Result<std::result::Result<Option<passkey_store::PasskeyIdentity>, String>> {
        Ok(Ok(accessor.with(|mut a| {
            a.get().passkey.identity().map(|(public_key, relying_party)| {
                passkey_store::PasskeyIdentity { public_key, relying_party }
            })
        })))
    }

    async fn enroll(
        accessor: &Accessor<Ctx, Self>,
    ) -> wasmtime::Result<std::result::Result<passkey_store::PasskeyIdentity, String>> {
        Ok(Ok(accessor.with(|mut a| {
            let (public_key, relying_party) = a.get().passkey.enroll();
            passkey_store::PasskeyIdentity { public_key, relying_party }
        })))
    }

    async fn adopt(
        accessor: &Accessor<Ctx, Self>,
        identity: passkey_store::PasskeyIdentity,
    ) -> wasmtime::Result<std::result::Result<(), String>> {
        Ok(accessor
            .with(|mut a| a.get().passkey.adopt(&identity.public_key, &identity.relying_party))
            .map_err(|e| e.to_string()))
    }

    async fn forget(
        accessor: &Accessor<Ctx, Self>,
    ) -> wasmtime::Result<std::result::Result<(), String>> {
        accessor.with(|mut a| a.get().passkey.forget());
        Ok(Ok(()))
    }

    async fn assert(
        accessor: &Accessor<Ctx, Self>,
        challenge: Vec<u8>,
    ) -> wasmtime::Result<std::result::Result<passkey_store::Assertion, String>> {
        Ok(Ok(accessor.with(|mut a| {
            let assertion = a.get().passkey.assert(&challenge);
            passkey_store::Assertion {
                authenticator_data: assertion.authenticator_data,
                client_data_json: assertion.client_data_json,
                signature: assertion.signature,
            }
        })))
    }

    async fn assert_unknown(
        accessor: &Accessor<Ctx, Self>,
        challenge: Vec<u8>,
    ) -> wasmtime::Result<std::result::Result<passkey_store::RecoveryAssertion, String>> {
        Ok(Ok(accessor.with(|mut a| {
            let (credential_id, relying_party, assertion) =
                a.get().passkey.assert_unknown(&challenge);
            passkey_store::RecoveryAssertion {
                credential_id,
                relying_party,
                assertion: passkey_store::Assertion {
                    authenticator_data: assertion.authenticator_data,
                    client_data_json: assertion.client_data_json,
                    signature: assertion.signature,
                },
            }
        })))
    }

    async fn remember(
        accessor: &Accessor<Ctx, Self>,
        identity: passkey_store::PasskeyIdentity,
        _credential_id: Vec<u8>,
    ) -> wasmtime::Result<std::result::Result<(), String>> {
        // The soft authenticator has no need for `credential_id` here
        // (it only ever has one credential to check the claim
        // against); a real platform authenticator's host would use it
        // to pick which stored credential the claim is being recorded
        // against.
        Ok(accessor
            .with(|mut a| a.get().passkey.remember(&identity.public_key, &identity.relying_party))
            .map_err(|e| e.to_string()))
    }
}

impl pairing_store::Host for Ctx {}

impl pairing_store::HostWithStore<Ctx> for HasSelf<Ctx> {
    async fn load(
        accessor: &Accessor<Ctx, Self>,
    ) -> wasmtime::Result<std::result::Result<Option<Vec<u8>>, String>> {
        Ok(Ok(accessor.with(|mut a| {
            let ctx = a.get();
            match &ctx.pairing_path {
                Some(p) => std::fs::read(p).ok(), // absent file = no blob yet
                None => ctx.pairing_blob.clone(),
            }
        })))
    }

    async fn store(
        accessor: &Accessor<Ctx, Self>,
        blob: Vec<u8>,
    ) -> wasmtime::Result<std::result::Result<(), String>> {
        Ok(accessor.with(|mut a| {
            let ctx = a.get();
            match &ctx.pairing_path {
                Some(p) => std::fs::write(p, &blob)
                    .map_err(|e| format!("pairing store {}: {e}", p.display())),
                None => {
                    ctx.pairing_blob = Some(blob);
                    Ok(())
                }
            }
        }))
    }
}

struct Args {
    component: PathBuf,
    connstring: String,
    user: String,
    /// Where to append the component's own public key so sshd will
    /// accept it (the browser equivalent: the user pastes this line).
    authorized_keys: PathBuf,
    /// `SHA256:...` of the sshd host key, to check the fingerprint the
    /// component reports before anything is authenticated.
    expect_host_key: Option<String>,
    /// "publickey" (default), "kbd" (keyboard-interactive against the
    /// scripted stand-in; see kbdint-sshd/), "auto" (the server
    /// steers: with no --kbd-answers this leg must complete silently
    /// via publickey; with them it must ride the prompt loop),
    /// "passkey" (WebAuthn publickey auth via a software authenticator
    /// standing in for a browser's platform authenticator; see
    /// passkey.rs), or "passkey-recover" (same, but the client's
    /// stored identity is forgotten -- simulating evicted browser
    /// storage -- and reconstructed via `recover-passkey` before
    /// authenticating, proving recovery lands on the SAME identity
    /// already installed on the target).
    auth: String,
    /// Answers for the keyboard-interactive rounds, consumed in prompt
    /// order across however many batches the server issues.
    kbd_answers: Vec<String>,
    /// Invert the verdict: authentication must FAIL, legibly.
    expect_auth_fail: bool,
    /// Persist the pairing identity blob here across invocations
    /// (default: in-memory, a fresh client per run).
    pairing_store: Option<PathBuf>,
    /// Linger this long with the shell open (after the round trip,
    /// before detaching). A window for an external orchestrator to act
    /// on the live session -- freeze this process, cut its network.
    hold_ms: u64,
    /// The on-connect command (terminal.wit `connect`'s `command`):
    /// sent as an SSH `exec` request in place of the default `shell`
    /// request. Presence of this flag selects the exec leg entirely,
    /// in place of the interactive-shell legs above.
    command: Option<String>,
    /// Expected exit status of the on-connect command.
    expect_exit: Option<i32>,
    /// A substring that must appear in the command's pty output
    /// (matched against raw bytes including \r\n, so pass just the
    /// marker text, not a full line).
    expect_output: Option<String>,
    /// A command to run on the probe's second channel, DURING the
    /// live interactive session in the first (plain publickey) leg,
    /// after its echo round-trip and before detach. Proves the probe
    /// channel leaves the interactive channel undisturbed.
    probe: Option<String>,
    /// Expected exit status of the probe command.
    probe_expect_exit: Option<i32>,
    /// A substring that must appear in the probe's output.
    probe_expect_output: Option<String>,
    /// Run the FILE TRANSFER legs against this directory on the target
    /// (absolute path; it is wiped and re-seeded server-side). Rides
    /// the same live publickey session as `--probe`, after the shell
    /// round-trip, so the transfer plane is exercised alongside a
    /// working interactive channel rather than instead of one.
    transfer_dir: Option<String>,
    /// Where this host stages the bytes a download's `sink` keeps.
    /// Defaults to a temp directory.
    transfer_stage: Option<PathBuf>,
    /// A host shell command run ONCE, partway through the transfer
    /// leg's final upload, to tear the transport out from under a live
    /// transfer (the gate supplies the relay kill/restart). Its
    /// presence is what selects the resume leg.
    mid_transfer_cmd: Option<String>,
}

fn parse_args() -> Result<Args> {
    let mut a = Args {
        component: PathBuf::from("target/components/wosh-ssh-client.wasm"),
        connstring: String::new(),
        user: std::env::var("USER").unwrap_or_else(|_| "root".into()),
        authorized_keys: PathBuf::new(),
        expect_host_key: None,
        auth: "publickey".into(),
        kbd_answers: Vec::new(),
        expect_auth_fail: false,
        pairing_store: None,
        hold_ms: 0,
        command: None,
        expect_exit: None,
        expect_output: None,
        probe: None,
        probe_expect_exit: None,
        probe_expect_output: None,
        transfer_dir: None,
        transfer_stage: None,
        mid_transfer_cmd: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(f) = it.next() {
        let mut v = || it.next().ok_or_else(|| anyhow!("{f} needs a value"));
        match f.as_str() {
            "--component" => a.component = PathBuf::from(v()?),
            "--connstring" => a.connstring = v()?,
            "--user" => a.user = v()?,
            "--authorized-keys" => a.authorized_keys = PathBuf::from(v()?),
            "--expect-host-key" => a.expect_host_key = Some(v()?),
            "--auth" => a.auth = v()?,
            "--kbd-answers" => {
                a.kbd_answers = v()?.split(',').map(str::to_owned).collect()
            }
            "--expect-auth-fail" => a.expect_auth_fail = true,
            "--pairing-store" => a.pairing_store = Some(PathBuf::from(v()?)),
            "--hold-ms" => a.hold_ms = v()?.parse().map_err(|e| anyhow!("--hold-ms: {e}"))?,
            "--command" => a.command = Some(v()?),
            "--expect-exit" => {
                a.expect_exit = Some(v()?.parse().map_err(|e| anyhow!("--expect-exit: {e}"))?)
            }
            "--expect-output" => a.expect_output = Some(v()?),
            "--probe" => a.probe = Some(v()?),
            "--probe-expect-exit" => {
                a.probe_expect_exit =
                    Some(v()?.parse().map_err(|e| anyhow!("--probe-expect-exit: {e}"))?)
            }
            "--probe-expect-output" => a.probe_expect_output = Some(v()?),
            "--transfer-dir" => a.transfer_dir = Some(v()?),
            "--transfer-stage" => a.transfer_stage = Some(PathBuf::from(v()?)),
            "--mid-transfer-cmd" => a.mid_transfer_cmd = Some(v()?),
            other => bail!("unknown flag {other}"),
        }
    }
    if a.connstring.is_empty() {
        bail!("--connstring is required");
    }
    match a.auth.as_str() {
        "publickey" | "kbd" | "auto" | "passkey" | "passkey-recover" => {}
        other => {
            bail!("--auth must be publickey, kbd, auto, passkey or passkey-recover, not {other}")
        }
    }
    Ok(a)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    // The two flow shapes: the prompt loop (keyboard-interactive, and
    // auto when the server is expected to steer somewhere that asks),
    // or silent-to-ready (publickey, and auto when it must resolve to
    // the key with no prompt at all).
    let interactive = args.auth == "kbd" || (args.auth == "auto" && !args.kbd_answers.is_empty());
    // Decided here because `args` moves into the gate closure below;
    // the prompt-loop legs print their own verdicts inline.
    let final_pass = match (args.auth.as_str(), interactive) {
        ("publickey", _) => {
            Some("\nE2E PASS: browser SSH client -> iroh -> listener -> OpenSSH sshd")
        }
        ("auto", false) => {
            Some("\nE2E AUTO PASS: the server steered auto to publickey; no prompt surfaced")
        }
        _ => None,
    };

    let mut config = Config::new();
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_file(&engine, &args.component)
        .map_err(|e| anyhow!("loading {}: {e}", args.component.display()))?;

    let mut linker: Linker<Ctx> = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi::p3::add_to_linker(&mut linker)?;
    webrtc_host::add_to_linker(&mut linker)?;
    polymorph_webcrypto_wasmtime::add_to_linker(&mut linker)?;
    wasmtime_websocket::add_to_linker(&mut linker)?;
    identity_store::add_to_linker::<Ctx, HasSelf<Ctx>>(&mut linker, |ctx| ctx)?;
    passkey_store::add_to_linker::<Ctx, HasSelf<Ctx>>(&mut linker, |ctx| ctx)?;
    pairing_store::add_to_linker::<Ctx, HasSelf<Ctx>>(&mut linker, |ctx| ctx)?;
    transfer_io::add_to_linker::<Ctx, HasSelf<Ctx>>(&mut linker, |ctx| ctx)?;

    let mut wasi = WasiCtx::builder();
    wasi.inherit_stdio().inherit_network();
    let mut store = Store::new(
        &engine,
        Ctx {
            wasi: wasi.build(),
            webrtc: WebrtcCtx::new(),
            webcrypto: WasiWebcryptoCtx::new(),
            websocket: WasiWebsocketCtx::new(),
            identity: ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),
            passkey: passkey::SoftAuthenticator::new(),
            pairing_path: args.pairing_store.clone(),
            pairing_blob: None,
            table: ResourceTable::new(),
        },
    );

    let client =
        bindings::ComposedClient::instantiate_async(&mut store, &component, &linker).await?;

    let outcome = store
        .run_concurrent(async move |acc| -> Result<()> {
            let iface = client.wosh_terminal_terminal();
            let session = iface.session();

            // No keepalive: the wosh-client Rust component's runtime
            // (wit-bindgen) tracks its own spawned tasks, so the
            // caller supplies nothing to keep background I/O alive.

            let gate = async {

            if args.auth == "passkey" || args.auth == "passkey-recover" {
                // --- 1p. enrol the software passkey identity -------
                // Check both directions of passkey-openssh's contract
                // in one pass: none before enrolment, the SAME line
                // after (see the doc comment on `passkey-openssh` in
                // terminal.wit -- it is the portable form of the
                // identity, not just a getter).
                let before = iface
                    .call_passkey_openssh(acc)
                    .await?
                    .map_err(|e| anyhow!("passkey-openssh (pre-enrol): {e}"))?;
                if before.is_some() {
                    bail!("passkey-openssh reported an identity before enroll-passkey: {before:?}");
                }
                println!("[1p] passkey-openssh is none before enrolment, as expected");

                let line = iface
                    .call_enroll_passkey(acc)
                    .await?
                    .map_err(|e| anyhow!("enroll-passkey: {e}"))?;
                println!("[1p] enrolled passkey identity (host-held, via passkey-store):\n    {line}");
                // The whole point of this gate: an ordinary
                // security-key authorized_keys line, verified by a real
                // unmodified sshd binary. (The test sshd_config does
                // enable the algorithm, which every OpenSSH before 10.3
                // requires -- see scripts/test-sshd.sh, and the WIT doc
                // comment on `passkey-store`.)
                if !line.starts_with("sk-ecdsa-sha2-nistp256@openssh.com ") {
                    bail!("passkey identity is not a sk-ecdsa-sha2-nistp256@openssh.com authorized_keys line: {line}");
                }

                let after = iface
                    .call_passkey_openssh(acc)
                    .await?
                    .map_err(|e| anyhow!("passkey-openssh (post-enrol): {e}"))?;
                if after.as_deref() != Some(line.as_str()) {
                    bail!(
                        "passkey-openssh after enrol does not match enroll-passkey's own line:\n  enroll-passkey: {line}\n  passkey-openssh: {after:?}"
                    );
                }
                println!("[1p] passkey-openssh agrees with enroll-passkey's line after enrolment");

                if !args.authorized_keys.as_os_str().is_empty() {
                    std::fs::write(&args.authorized_keys, format!("{line}\n"))?;
                    println!("[1p] installed into {}", args.authorized_keys.display());
                }

                if args.auth == "passkey-recover" {
                    // --- 1r. simulate evicted browser storage --------
                    // The credential survives in the (software)
                    // authenticator; only the client's RECORD of it
                    // (the public key, tucked away for `passkey-openssh`)
                    // is gone -- exactly the scenario `recover-passkey`
                    // exists for (see its doc comment in terminal.wit).
                    iface
                        .call_forget_passkey(acc)
                        .await?
                        .map_err(|e| anyhow!("forget-passkey: {e}"))?;
                    let forgotten = iface
                        .call_passkey_openssh(acc)
                        .await?
                        .map_err(|e| anyhow!("passkey-openssh (post-forget): {e}"))?;
                    if forgotten.is_some() {
                        bail!("passkey-openssh still reports an identity after forget-passkey: {forgotten:?}");
                    }
                    println!("[1r] forgot the passkey identity; passkey-openssh is none again (storage eviction, simulated)");

                    // --- 2r. recover it from the credential itself ---
                    // Two assertions (different challenges, same
                    // credential) determine the public key that made
                    // them. The property that matters: the line this
                    // reconstructs must be BYTE-IDENTICAL to the one
                    // from step [1p], because that line is already
                    // sitting untouched in the target's
                    // authorized_keys -- recovery has to reproduce the
                    // same identity, not merely produce *an* identity.
                    let recovered = iface
                        .call_recover_passkey(acc)
                        .await?
                        .map_err(|e| anyhow!("recover-passkey: {e}"))?;
                    if recovered != line {
                        bail!(
                            "recovered passkey line does not match the originally enrolled line:\n  enrolled:  {line}\n  recovered: {recovered}"
                        );
                    }
                    println!("[2r] recover-passkey reconstructed the SAME authorized_keys line as enroll-passkey");

                    let after_recover = iface
                        .call_passkey_openssh(acc)
                        .await?
                        .map_err(|e| anyhow!("passkey-openssh (post-recover): {e}"))?;
                    if after_recover.as_deref() != Some(line.as_str()) {
                        bail!(
                            "passkey-openssh after recovery does not match the recovered line:\n  recovered: {recovered}\n  passkey-openssh: {after_recover:?}"
                        );
                    }
                    println!("[2r] passkey-openssh agrees with the recovered line (remember persisted it, not just returned it)");

                    // Deliberately NOT reinstalling into
                    // args.authorized_keys: authenticating below
                    // against the line installed back in [1p] is what
                    // proves recovery found the SAME identity, rather
                    // than merely a working one.
                }

                // --- 2p. dial over iroh -----------------------------
                let s = session
                    .call_connect(acc, args.connstring.clone(), args.user.clone(), 80, 24, None)
                    .await?
                    .map_err(|e| anyhow!("connect: {e}"))?;
                println!("[2p] dialed the listener over iroh");

                // --- 3p. host-key gate -------------------------------
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    match session.call_status(acc, s).await? {
                        Status::HostKeyCheck => break,
                        Status::Closed(why) => bail!("closed before the host-key gate: {why}"),
                        _ if Instant::now() > deadline => {
                            bail!("timed out reaching the host-key gate")
                        }
                        _ => tokio::time::sleep(Duration::from_millis(20)).await,
                    }
                }
                let fp = session
                    .call_host_key_fingerprint(acc, s)
                    .await?
                    .ok_or_else(|| anyhow!("no fingerprint at the host-key gate"))?;
                println!("[3p] server host key: {fp}");
                if let Some(expected) = &args.expect_host_key {
                    if &fp != expected {
                        bail!("host key mismatch:\n  reported {fp}\n  expected {expected}");
                    }
                    println!("[3p] fingerprint matches the sshd host key");
                }
                session.call_confirm_host_key(acc, s, true).await?;

                // --- 4p. passkey auth --------------------------------
                // Unlike publickey, the ceremony (here: the soft
                // authenticator's assert()) is triggered DURING
                // authentication, once the session id exists -- see
                // the doc comment on `authenticate-passkey`.
                session
                    .call_authenticate_passkey(acc, s)
                    .await?
                    .map_err(|e| anyhow!("authenticate-passkey: {e}"))?;

                let deadline = Instant::now() + Duration::from_secs(60);
                loop {
                    match session.call_status(acc, s).await? {
                        Status::Ready => break,
                        Status::Closed(why) => bail!("passkey authentication failed: {why}"),
                        Status::AuthPrompts => {
                            bail!("a prompt batch surfaced in the passkey (promptless) leg")
                        }
                        _ if Instant::now() > deadline => bail!("timed out waiting for the shell"),
                        _ => tokio::time::sleep(Duration::from_millis(25)).await,
                    }
                }
                println!("[4p] authenticated via webauthn-sk-ecdsa-sha2-nistp256@openssh.com; shell is up");

                // --- 5p. interactive shell ---------------------------
                let marker = "WOSH_PASSKEY_OK";
                session
                    .call_write_input(acc, s, format!("echo {marker}\n").into_bytes())
                    .await?;
                let mut screen = String::new();
                let deadline = Instant::now() + Duration::from_secs(30);
                while Instant::now() < deadline {
                    let chunk = session.call_drain_output(acc, s).await?;
                    if !chunk.is_empty() {
                        screen.push_str(&String::from_utf8_lossy(&chunk));
                    }
                    // Echoed command line + actual output: require it twice.
                    if screen.matches(marker).count() >= 2 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                if screen.matches(marker).count() < 2 {
                    bail!("shell never produced {marker}; saw:\n{screen}");
                }
                println!("[5p] interactive shell round-trip through the tunnel OK");

                session.call_detach(acc, s).await?;
                println!("[6p] detached cleanly");
                if args.auth == "passkey-recover" {
                    println!(
                        "\nE2E-PASSKEY-RECOVER PASS: recovered the SAME identity from the credential \
                         alone -- byte-identical authorized_keys line, still verified by a real, \
                         unmodified sshd against the line already installed there"
                    );
                } else {
                    println!(
                        "\nE2E-PASSKEY PASS: webauthn-sk-ecdsa-sha2-nistp256@openssh.com verified by \
                         a real, unmodified sshd against a software authenticator"
                    );
                }
                return Ok::<(), anyhow::Error>(());
            }

            if let Some(command) = &args.command {
                // The exec leg: same channel and pty as the shell legs
                // above, but terminal.wit's `connect` sends `command`
                // as an SSH `exec` request (RFC 4254 s6.5) in place of
                // `shell` once authentication succeeds. Reuse the
                // publickey plumbing verbatim -- only what happens
                // after `ready` (or, for a fast-exiting command,
                // instead of ever observing it) differs.

                // --- 1e. identity, exactly like the publickey leg --
                let line = iface
                    .call_identity_openssh(acc)
                    .await?
                    .map_err(|e| anyhow!("identity: {e}"))?;
                println!("[1e] identity (host-held, via identity-store):\n    {line}");
                if !args.authorized_keys.as_os_str().is_empty() {
                    std::fs::write(&args.authorized_keys, format!("{line}\n"))?;
                    println!("[1e] installed into {}", args.authorized_keys.display());
                }

                // --- 2e. dial, carrying the on-connect command ------
                let s = session
                    .call_connect(
                        acc,
                        args.connstring.clone(),
                        args.user.clone(),
                        80,
                        24,
                        Some(command.clone()),
                    )
                    .await?
                    .map_err(|e| anyhow!("connect: {e}"))?;
                println!("[2e] dialed with on-connect command: {command:?}");

                // --- 3e. host-key gate -------------------------------
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    match session.call_status(acc, s).await? {
                        Status::HostKeyCheck => break,
                        Status::Closed(why) => bail!("closed before the host-key gate: {why}"),
                        _ if Instant::now() > deadline => {
                            bail!("timed out reaching the host-key gate")
                        }
                        _ => tokio::time::sleep(Duration::from_millis(20)).await,
                    }
                }
                let fp = session
                    .call_host_key_fingerprint(acc, s)
                    .await?
                    .ok_or_else(|| anyhow!("no fingerprint at the host-key gate"))?;
                println!("[3e] server host key: {fp}");
                if let Some(expected) = &args.expect_host_key {
                    if &fp != expected {
                        bail!("host key mismatch:\n  reported {fp}\n  expected {expected}");
                    }
                    println!("[3e] fingerprint matches the sshd host key");
                }
                session.call_confirm_host_key(acc, s, true).await?;

                // --- 4e. publickey auth, exactly like the publickey leg
                session
                    .call_authenticate_publickey(acc, s)
                    .await?
                    .map_err(|e| anyhow!("publickey auth: {e}"))?;

                // --- 5e. drive the exec to completion ---------------
                // Deliberately do NOT wait for `ready` first: the
                // on-connect command supplants the shell entirely, and
                // a fast-exiting one (`exit 7` finishes essentially
                // instantly) can carry the session from authenticating
                // straight through `ready` to `closed` between two
                // polls, so a loop gated on observing `ready` first
                // could miss it and hang. `exited` is the only
                // observation this leg can rely on.
                let mut screen = String::new();
                let deadline = Instant::now() + Duration::from_secs(60);
                loop {
                    let chunk = session.call_drain_output(acc, s).await?;
                    if !chunk.is_empty() {
                        screen.push_str(&String::from_utf8_lossy(&chunk));
                    }
                    if session.call_exited(acc, s).await? {
                        break;
                    }
                    if Instant::now() > deadline {
                        bail!("timed out waiting for the on-connect command to exit");
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                // One more drain: output produced between the last
                // observed chunk and the exit becoming visible must
                // not be dropped.
                let chunk = session.call_drain_output(acc, s).await?;
                if !chunk.is_empty() {
                    screen.push_str(&String::from_utf8_lossy(&chunk));
                }
                println!("[5e] on-connect command exited");

                if let Some(expect) = args.expect_exit {
                    let status = session.call_exit_status(acc, s).await?;
                    if status != Some(expect) {
                        bail!("exit status mismatch: got {status:?}, expected {expect}");
                    }
                    println!("[5e] exit status matches: {expect}");
                }
                if let Some(expect) = &args.expect_output {
                    // Pty output carries \r\n line endings, so this is
                    // a substring match on the marker text alone, not
                    // a full-line comparison.
                    if !screen.contains(expect.as_str()) {
                        bail!("expected output {expect:?} not found; saw:\n{screen}");
                    }
                    println!("[5e] output contains expected marker: {expect}");
                }

                session.call_detach(acc, s).await?;
                println!("[6e] detached cleanly");
                println!(
                    "\nE2E-EXEC PASS: on-connect command ran in place of the shell over the \
                     same channel and pty; output and exit status verified"
                );
                return Ok(());
            }

            // --- 1. the browser's own SSH identity -----------------
            let line = iface
                .call_identity_openssh(acc)
                .await?
                .map_err(|e| anyhow!("identity: {e}"))?;
            println!("[1] identity (host-held, via identity-store):\n    {line}");
            if !line.starts_with("ssh-ed25519 ") {
                bail!("identity is not an ssh-ed25519 authorized_keys line: {line}");
            }
            if !args.authorized_keys.as_os_str().is_empty() {
                std::fs::write(&args.authorized_keys, format!("{line}\n"))?;
                println!("[1] installed into {}", args.authorized_keys.display());
            }

            // --- 2. dial over iroh --------------------------------
            let s = session
                .call_connect(acc, args.connstring.clone(), args.user.clone(), 80, 24, None)
                .await?
                .map_err(|e| anyhow!("connect: {e}"))?;
            println!("[2] dialed the listener over iroh");

            // --- 3. host-key gate ---------------------------------
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                match session.call_status(acc, s).await? {
                    Status::HostKeyCheck => break,
                    Status::Closed(why) => bail!("closed before the host-key gate: {why}"),
                    _ if Instant::now() > deadline => bail!("timed out reaching the host-key gate"),
                    _ => tokio::time::sleep(Duration::from_millis(20)).await,
                }
            }
            let fp = session
                .call_host_key_fingerprint(acc, s)
                .await?
                .ok_or_else(|| anyhow!("no fingerprint at the host-key gate"))?;
            println!("[3] server host key: {fp}");
            if let Some(expected) = &args.expect_host_key {
                if &fp != expected {
                    bail!("host key mismatch:\n  reported {fp}\n  expected {expected}");
                }
                println!("[3] fingerprint matches the sshd host key");
            }

            session.call_confirm_host_key(acc, s, true).await?;

            if interactive {
                // --- 4k. prompt-driven auth -----------------------
                // keyboard-interactive explicitly, or auto steered to
                // it by the server. The exports latch and resolve at
                // once; every state transition below is observed by
                // polling, and each `auth-prompts` round is answered
                // from the queue.
                if args.auth == "auto" {
                    session
                        .call_authenticate_auto(acc, s)
                        .await?
                        .map_err(|e| anyhow!("authenticate-auto: {e}"))?;
                } else {
                    session
                        .call_authenticate_interactive(acc, s)
                        .await?
                        .map_err(|e| anyhow!("authenticate-interactive: {e}"))?;
                }

                let mut queue = args.kbd_answers.clone().into_iter();
                let mut rounds = 0usize;
                let mut saw_echo = false;
                let mut saw_masked = false;
                let deadline = Instant::now() + Duration::from_secs(60);
                let auth_failure = loop {
                    if Instant::now() > deadline {
                        bail!("timed out during keyboard-interactive auth");
                    }
                    match session.call_status(acc, s).await? {
                        Status::AuthPrompts => {
                            let batch = session
                                .call_pending_prompts(acc, s)
                                .await?
                                .ok_or_else(|| anyhow!("auth-prompts status but no pending batch"))?;
                            if batch.prompts.is_empty() {
                                bail!("a surfaced batch must carry prompts");
                            }
                            rounds += 1;
                            println!(
                                "[4k] round {rounds}: instruction {:?}, {} prompt(s)",
                                batch.instruction,
                                batch.prompts.len()
                            );
                            let mut answers = Vec::new();
                            for p in &batch.prompts {
                                println!("      prompt {:?} echo={}", p.text, p.echo);
                                if p.echo { saw_echo = true } else { saw_masked = true }
                                answers.push(queue.next().ok_or_else(|| {
                                    anyhow!("ran out of --kbd-answers at round {rounds}")
                                })?);
                            }
                            session
                                .call_answer_prompts(acc, s, answers)
                                .await?
                                .map_err(|e| anyhow!("answer-prompts: {e}"))?;
                        }
                        Status::Ready => break None,
                        Status::Closed(why) => break Some(why),
                        _ => tokio::time::sleep(Duration::from_millis(20)).await,
                    }
                };

                if args.expect_auth_fail {
                    let why = auth_failure
                        .ok_or_else(|| anyhow!("authenticated despite wrong answers"))?;
                    if !why.contains("ssh:") {
                        bail!("wanted a legible ssh auth failure, got: {why}");
                    }
                    println!("[4k] wrong answers were refused, legibly: {why}");
                    println!("\nE2E-KBDINT NEGATIVE PASS: wrong answers do not authenticate");
                    return Ok(());
                }
                if let Some(why) = auth_failure {
                    bail!("keyboard-interactive auth failed: {why}");
                }
                if rounds < 2 {
                    bail!("expected the scripted server to issue two rounds, saw {rounds}");
                }
                if !(saw_echo && saw_masked) {
                    bail!("expected both an echoed and a masked prompt (echo flag plumbing)");
                }
                println!("[4k] authenticated after {rounds} prompt rounds; shell is up");

                // --- 5k. echo round-trip --------------------------
                // The stand-in's shell is a byte echo (no pty), so the
                // marker comes back exactly once.
                let marker = "WOSH_KBDINT_OK";
                session
                    .call_write_input(acc, s, format!("{marker}\n").into_bytes())
                    .await?;
                let mut screen = String::new();
                let deadline = Instant::now() + Duration::from_secs(30);
                while Instant::now() < deadline && !screen.contains(marker) {
                    let chunk = session.call_drain_output(acc, s).await?;
                    if !chunk.is_empty() {
                        screen.push_str(&String::from_utf8_lossy(&chunk));
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                if !screen.contains(marker) {
                    bail!("echo shell never returned {marker}; saw:\n{screen}");
                }
                println!("[5k] interactive round-trip through the tunnel OK");

                session.call_detach(acc, s).await?;
                println!("[6k] detached cleanly");
                if args.auth == "auto" {
                    println!("\nE2E AUTO-KBDINT PASS: the server steered auto to \
                              keyboard-interactive; prompt batches answered over the tunnel");
                } else {
                    println!("\nE2E-KBDINT PASS: prompt batches answered over the tunnel, shell reached");
                }
                return Ok(());
            }

            // --- 4. publickey auth via WebCrypto ------------------
            // Auto must land here too when the server offers nothing
            // interactive: against the publickey-only sshd it has to
            // resolve to the same silent signature flow.
            if args.auth == "auto" {
                session
                    .call_authenticate_auto(acc, s)
                    .await?
                    .map_err(|e| anyhow!("authenticate-auto: {e}"))?;
            } else {
                session
                    .call_authenticate_publickey(acc, s)
                    .await?
                    .map_err(|e| anyhow!("publickey auth: {e}"))?;
            }

            // The call latches the credential and returns at once;
            // authentication and the pty/shell setup run in the
            // background, so readiness is observed by polling.
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                match session.call_status(acc, s).await? {
                    Status::Ready => break,
                    Status::Closed(why) => bail!("authentication failed: {why}"),
                    // Neither mode in this leg may ask a human for
                    // anything: publickey carries no prompts at all,
                    // and auto against a publickey-only server must
                    // stay exactly as silent.
                    Status::AuthPrompts => bail!("a prompt batch surfaced in a promptless leg"),
                    _ if Instant::now() > deadline => bail!("timed out waiting for the shell"),
                    _ => tokio::time::sleep(Duration::from_millis(25)).await,
                }
            }
            println!("[4] authenticated (signature produced through identity-store); shell is up");

            // --- 5. interactive shell -----------------------------
            let marker = "WOSH_E2E_OK";
            session
                .call_write_input(acc, s, format!("echo {marker}\n").into_bytes())
                .await?;

            let mut screen = String::new();
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline {
                let chunk = session.call_drain_output(acc, s).await?;
                if !chunk.is_empty() {
                    screen.push_str(&String::from_utf8_lossy(&chunk));
                }
                // The echoed command line also contains the marker, so
                // require it twice: once echoed by the pty, once as
                // the command's actual output.
                if screen.matches(marker).count() >= 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            if screen.matches(marker).count() < 2 {
                bail!("shell never produced {marker}; saw:\n{screen}");
            }
            println!("[5] interactive shell round-trip through the tunnel OK");

            session.call_resize(acc, s, 100, 40).await?;
            println!("[6] resize accepted");

            if let Some(cmd) = &args.probe {
                // --- 8. probe on the second channel, mid-session ---
                // The point of running this HERE, with the interactive
                // shell still live, is that it proves the two channels
                // are actually independent: the probe rides a second
                // SSH channel of the same authenticated connection, no
                // pty attached, so its output comes back unmangled --
                // and the round-trip that follows proves the
                // interactive channel above never noticed.
                let result = session
                    .call_probe(acc, s, cmd.clone())
                    .await?
                    .map_err(|e| anyhow!("probe: {e}"))?;
                println!(
                    "[8] probe {cmd:?} -> exit {:?}, {} byte(s) of output",
                    result.exit_status,
                    result.output.len()
                );
                if let Some(expect) = args.probe_expect_exit {
                    if result.exit_status != Some(expect) {
                        bail!(
                            "probe exit status mismatch: got {:?}, expected {expect}",
                            result.exit_status
                        );
                    }
                    println!("[8] probe exit status matches: {expect}");
                }
                if let Some(expect) = &args.probe_expect_output {
                    let output = String::from_utf8_lossy(&result.output);
                    if !output.contains(expect.as_str()) {
                        bail!("probe output missing {expect:?}; saw:\n{output}");
                    }
                    println!("[8] probe output contains expected marker: {expect}");
                }

                // Prove the interactive shell still answers after the
                // probe ran alongside it.
                let marker2 = "WOSH_E2E_POST_PROBE_OK";
                session
                    .call_write_input(acc, s, format!("echo {marker2}\n").into_bytes())
                    .await?;
                let mut screen2 = String::new();
                let deadline = Instant::now() + Duration::from_secs(30);
                while Instant::now() < deadline {
                    let chunk = session.call_drain_output(acc, s).await?;
                    if !chunk.is_empty() {
                        screen2.push_str(&String::from_utf8_lossy(&chunk));
                    }
                    if screen2.matches(marker2).count() >= 2 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                if screen2.matches(marker2).count() < 2 {
                    bail!("shell never produced {marker2} after the probe; saw:\n{screen2}");
                }
                println!("[8] interactive shell still answers after the probe -- channels are independent");
                println!("\nE2E-PROBE PASS: second-channel probe ran mid-session without disturbing the interactive shell");
            }

            if let Some(dir) = &args.transfer_dir {
                // --- 9. the file-transfer plane, mid-session --------
                // Deliberately on the SAME live session as the shell
                // above: SFTP rides a second bulk channel, and the
                // interactive channel must be no more disturbed by a
                // multi-megabyte transfer than it was by the probe.
                let stage = match &args.transfer_stage {
                    Some(p) => p.clone(),
                    None => std::env::temp_dir()
                        .join(format!("wosh-transfer-{}", std::process::id())),
                };
                std::fs::create_dir_all(&stage)?;
                transfer::run(
                    acc,
                    iface,
                    s,
                    dir,
                    &stage,
                    args.mid_transfer_cmd.as_deref(),
                )
                .await?;
            }

            if args.hold_ms > 0 {
                // Linger with the session open: gives an external
                // orchestrator a window to act on THIS process (stop
                // it, cut its network) while the session is live.
                println!("[hold] session held open for {}ms", args.hold_ms);
                tokio::time::sleep(Duration::from_millis(args.hold_ms)).await;
            }

            session.call_detach(acc, s).await?;
            println!("[7] detached cleanly");
            Ok::<(), anyhow::Error>(())
            };

            futures::pin_mut!(gate);
            gate.await
        })
        .await?;

    outcome?;
    if let Some(msg) = final_pass {
        println!("{msg}");
    }
    Ok(())
}
