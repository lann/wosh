//! The end-to-end gate: the composed browser SSH client, under
//! wasmtime, dialing a real listener over real iroh, proxied to a
//! **real OpenSSH sshd**, authenticated with the non-extractable
//! WebCrypto key the component mints for itself.
//!
//! Everything the browser would do, minus the browser: the same
//! composed artifact, the same `wosh:terminal` interface, the same
//! polymorph host implementations. What a browser adds on top is
//! deltic and xterm.js, not different component behaviour.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use polymorph_webcrypto_wasmtime::{
    WasiWebcrypto, WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView,
};
use wasmtime::component::{Accessor, Component, Linker, Resource, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_webrtc_datachannels::{self as webrtc_host, WebrtcCtx, WebrtcCtxView, WebrtcView};
use wasmtime_websocket::{WasiWebsocketCtx, WasiWebsocketCtxView, WasiWebsocketView};

mod bindings {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "composed-client",
        imports: { default: async | store | trappable },
        exports: { default: async },
        // `identity-store` uses the signature resources, and the handles
        // it returns must be THE SAME host resource types the webcrypto
        // linker entries registered -- so those interfaces map onto the
        // polymorph crate's generated bindings instead of regenerating.
        with: {
            "polymorph:webcrypto/types@0.1.0": polymorph_webcrypto_wasmtime::bindings::webcrypto::types,
            "polymorph:webcrypto/signature@0.1.0": polymorph_webcrypto_wasmtime::bindings::webcrypto::signature,
        },
    });
}

use bindings::exports::wosh::terminal::terminal::Status;
use bindings::wosh::terminal::identity_store;
use polymorph_webcrypto_wasmtime::bindings::webcrypto::ed25519_sign;
use polymorph_webcrypto_wasmtime::bindings::webcrypto::signature::{
    HostSigningKeyOptions, SigningKey, VerifyingKey,
};

struct Ctx {
    wasi: WasiCtx,
    webrtc: WebrtcCtx,
    webcrypto: WasiWebcryptoCtx,
    websocket: WasiWebsocketCtx,
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

// `wosh:terminal/identity-store`, natively: mint a fresh pair per run
// through the SAME webcrypto host implementation the component uses for
// everything else. No persistence -- a gate run IS one browser visit;
// what persistence adds in a real browser (IndexedDB) is exercised by
// the browser gate. Implemented on `WasiWebcrypto` (the polymorph
// crate's data marker) so the accessor is already shaped for calling
// its `generate-key`.
impl identity_store::Host for WasiWebcryptoCtxView<'_> {}

impl identity_store::HostWithStore<Ctx> for WasiWebcrypto {
    async fn identity(
        accessor: &Accessor<Ctx, Self>,
    ) -> wasmtime::Result<std::result::Result<(Resource<SigningKey>, Resource<VerifyingKey>), String>>
    {
        // Mint-time policy, exactly as the browser host: sign granted,
        // extractable left at its default (false).
        let options = accessor.with(|mut access| {
            let mut view = access.get();
            let options = HostSigningKeyOptions::new(&mut view)?;
            let borrow = Resource::new_borrow(options.rep());
            HostSigningKeyOptions::can_sign(&mut view, borrow, true)?;
            Ok::<_, wasmtime::Error>(options)
        })?;
        let pair = <Self as ed25519_sign::HostWithStore<Ctx>>::generate_key(accessor, options)
            .await?
            .map_err(|e| format!("generate ssh identity: {e:?}"));
        Ok(pair)
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
}

fn parse_args() -> Result<Args> {
    let mut a = Args {
        component: PathBuf::from("target/components/wosh-ssh-client.wasm"),
        connstring: String::new(),
        user: std::env::var("USER").unwrap_or_else(|_| "root".into()),
        authorized_keys: PathBuf::new(),
        expect_host_key: None,
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
            "--keepalive-only" => {}
            other => bail!("unknown flag {other}"),
        }
    }
    if a.connstring.is_empty() {
        bail!("--connstring is required");
    }
    Ok(a)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;

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
    identity_store::add_to_linker::<Ctx, WasiWebcrypto>(&mut linker, |ctx| ctx.webcrypto())?;

    let mut wasi = WasiCtx::builder();
    wasi.inherit_stdio().inherit_network();
    let mut store = Store::new(
        &engine,
        Ctx {
            wasi: wasi.build(),
            webrtc: WebrtcCtx::new(),
            webcrypto: WasiWebcryptoCtx::new(),
            websocket: WasiWebsocketCtx::new(),
            table: ResourceTable::new(),
        },
    );

    let client =
        bindings::ComposedClient::instantiate_async(&mut store, &component, &linker).await?;

    let outcome = store
        .run_concurrent(async move |acc| -> Result<()> {
            let iface = client.wosh_terminal_terminal();
            let session = iface.session();

            // The keepalive task holds the guest's async runtime open;
            // without it the SSH goroutines lose their host task the
            // moment they park (see README "Findings" 3). It never
            // returns, so it is raced against the gate rather than
            // awaited.
            let keepalive = iface.call_keepalive(acc);

            // Isolation probe: run ONLY the keepalive, so its ticks are
            // unambiguous evidence it is (or is not) being driven.
            if std::env::args().any(|a| a == "--keepalive-only") {
                futures::pin_mut!(keepalive);
                let timer = tokio::time::sleep(Duration::from_secs(3));
                futures::pin_mut!(timer);
                futures::future::select(keepalive, timer).await;
                println!("(keepalive-only probe done)");
                return Ok(());
            }

            let gate = async {

            // --- 1. the browser's own SSH identity -----------------
            let line = iface
                .call_identity_openssh(acc)
                .await?
                .map_err(|e| anyhow!("identity: {e}"))?;
            println!("[1] identity (non-extractable WebCrypto key):\n    {line}");
            if !line.starts_with("ssh-ed25519 ") {
                bail!("identity is not an ssh-ed25519 authorized_keys line: {line}");
            }
            if !args.authorized_keys.as_os_str().is_empty() {
                std::fs::write(&args.authorized_keys, format!("{line}\n"))?;
                println!("[1] installed into {}", args.authorized_keys.display());
            }

            // --- 2. dial over iroh --------------------------------
            let s = session
                .call_connect(acc, args.connstring.clone(), args.user.clone(), 80, 24)
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

            // --- 4. publickey auth via WebCrypto ------------------
            session
                .call_authenticate_publickey(acc, s)
                .await?
                .map_err(|e| anyhow!("publickey auth: {e}"))?;

            // The call latches the credential and returns at once;
            // authentication and the pty/shell setup run in the
            // background, so readiness is observed by polling.
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                match session.call_status(acc, s).await? {
                    Status::Ready => break,
                    Status::Closed(why) => bail!("authentication failed: {why}"),
                    _ if Instant::now() > deadline => bail!("timed out waiting for the shell"),
                    _ => tokio::time::sleep(Duration::from_millis(25)).await,
                }
            }
            println!("[4] authenticated (signature produced by the WebCrypto key); shell is up");

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

            session.call_detach(acc, s).await?;
            println!("[7] detached cleanly");
            Ok::<(), anyhow::Error>(())
            };

            futures::pin_mut!(keepalive, gate);
            match futures::future::select(keepalive, gate).await {
                futures::future::Either::Left((r, _)) => {
                    r?;
                    bail!("keepalive returned; it must run for the session's lifetime");
                }
                futures::future::Either::Right((r, _)) => r,
            }
        })
        .await?;

    outcome?;
    println!("\nE2E PASS: browser SSH client -> iroh -> listener -> OpenSSH sshd");
    Ok(())
}
