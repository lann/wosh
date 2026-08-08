//! M6 gate: passkey-gated session persistence, end-to-end and native.
//!
//!   relay (child) ← proxy (child: shell + proxy-core + endpoint;
//!                    webauthn-rs RP, escrow store, persistence policy)
//!                     ↑ iroh QUIC (control stream + framed datagrams)
//!   composed-client.wasm under wasmtime (this process)
//!   + webauthn-authenticator-rs SoftPasskey (the "user")
//!
//! Flow under test: new session → register (real WebAuthn ceremony,
//! soft authenticator) → make-persistent (escrow carries {key,
//! seq-floor} — finding 13) → detach (server survives) → reattach
//! denied to strangers/bad assertions → reattach with a verified
//! assertion returns the escrow verbatim → attach with a
//! strictly-forward initial sequence → the SAME shell session is live
//! (pre-detach screen state resyncs) and the engine really does resume
//! above the floor. Escrow here uses the `plain` arm: the PRF arm is
//! browser-side crypto (web-tests phase 3); the proxy never parses
//! either.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use experiment_mosh_proto as proto;
use polymorph_webcrypto_wasmtime::{WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView};
use tokio::io::{AsyncBufReadExt, BufReader};
use url::Url;
use wasmtime::component::{Component, HasData, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_webrtc_datachannels::{
    self as webrtc_host, WasiWebrtcCtx, WasiWebrtcCtxView, WasiWebrtcView,
};
use wasmtime_websocket::{WasiWebsocketCtx, WasiWebsocketCtxView, WasiWebsocketView};
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
use webauthn_rs_proto::{CreationChallengeResponse, RequestChallengeResponse};

mod bindings {
    wasmtime::component::bindgen!({
        path: "../../client-core/wit",
        world: "composed-client",
        imports: {
            default: async | store | trappable,
        },
        exports: {
            default: async,
        },
    });
}

const RELAY_PORT: u16 = 3349;
const TOKEN: &str = "t3st-passkey";
const RP_ORIGIN: &str = "http://localhost";
const HARD_TIMEOUT: Duration = Duration::from_secs(120);
/// Reattach sequence margin over the escrowed floor (finding 13:
/// large forward jumps are legal; gaps are fine).
const SEQ_MARGIN: u64 = 10_000;

struct Ctx {
    wasi: WasiCtx,
    webrtc: WasiWebrtcCtx,
    webcrypto: WasiWebcryptoCtx,
    websocket: WasiWebsocketCtx,
    table: ResourceTable,
}

impl HasData for Ctx {
    type Data<'a> = &'a mut Self;
}

impl WasiView for Ctx {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl WasiWebrtcView for Ctx {
    fn webrtc(&mut self) -> WasiWebrtcCtxView<'_> {
        WasiWebrtcCtxView {
            ctx: &mut self.webrtc,
            table: &mut self.table,
        }
    }
}

impl WasiWebcryptoView for Ctx {
    fn webcrypto(&mut self) -> WasiWebcryptoCtxView<'_> {
        WasiWebcryptoCtxView {
            ctx: &mut self.webcrypto,
            table: &mut self.table,
        }
    }
}

impl WasiWebsocketView for Ctx {
    fn websocket(&mut self) -> WasiWebsocketCtxView<'_> {
        WasiWebsocketCtxView {
            ctx: &mut self.websocket,
            table: &mut self.table,
        }
    }
}

fn manifest_path(rel: &str) -> String {
    format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"))
}

async fn start_relay() -> Result<tokio::process::Child> {
    let dir = std::env::temp_dir().join("experiment-mosh-m6");
    std::fs::create_dir_all(&dir)?;
    let cfg = dir.join("relay.toml");
    std::fs::write(
        &cfg,
        format!("http_bind_addr = \"127.0.0.1:{RELAY_PORT}\"\nenable_metrics = false\n"),
    )?;
    let bin = manifest_path("../../.deps/polymorph-iroh/.deps/iroh/target/release/iroh-relay");
    let child = tokio::process::Command::new(&bin)
        .arg("--dev")
        .arg("-c")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning {bin}"))?;
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", RELAY_PORT))
            .await
            .is_ok()
        {
            return Ok(child);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    bail!("relay never came up on :{RELAY_PORT}")
}

struct ProxyProc {
    child: tokio::process::Child,
    endpoint_id_hex: String,
    direct: String,
    lines: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl ProxyProc {
    fn saw(&self, needle: &str) -> bool {
        self.lines.lock().unwrap().iter().any(|l| l.contains(needle))
    }

    fn term(&self) {
        if let Some(pid) = self.child.id() {
            let _ = std::process::Command::new("kill")
                .arg(pid.to_string())
                .status();
        }
    }

    /// Happy-path teardown: SIGTERM → the proxy reaps its sessions
    /// (persistent mosh-servers included) and exits.
    async fn shutdown(&mut self) -> Result<()> {
        self.term();
        tokio::time::timeout(Duration::from_secs(5), self.child.wait())
            .await
            .context("proxy did not exit on SIGTERM")??;
        Ok(())
    }
}

/// Failure-path teardown: still SIGTERM first (kill_on_drop's SIGKILL
/// would orphan persistent mosh-servers), give the reap a moment, then
/// let kill_on_drop deliver the SIGKILL backstop.
impl Drop for ProxyProc {
    fn drop(&mut self) {
        if self.child.id().is_some() {
            self.term();
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

async fn start_proxy() -> Result<ProxyProc> {
    let state =
        std::env::temp_dir().join(format!("experiment-mosh-m6-state-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    let bin = manifest_path("../../proxy/target/release/experiment-mosh-proxy");
    let mut child = tokio::process::Command::new(&bin)
        .args([
            "--relay",
            &format!("http://127.0.0.1:{RELAY_PORT}"),
            "--token",
            TOKEN,
            "--no-qr",
            "--yes",
            // M6 uses proxy-spawned sessions (D2 interim), opt-in
            // since M7's deprivileged default.
            "--personal",
            "--state-dir",
            state.to_str().unwrap(),
            "--component",
            &manifest_path("../../proxy/composed-proxy.wasm"),
            "--shell",
            "bash --noprofile --norc -i",
            "--rp-id",
            "localhost",
            "--rp-origin",
            RP_ORIGIN,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning {bin}"))?;

    let stdout = child.stdout.take().context("proxy stdout")?;
    let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let lines_bg = lines.clone();
    tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            println!("[proxy] {line}");
            lines_bg.lock().unwrap().push(line);
        }
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let (mut id, mut direct) = (None, None);
    while id.is_none() || direct.is_none() {
        if tokio::time::Instant::now() > deadline {
            bail!("proxy never printed connstring/direct-addr");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        for line in lines.lock().unwrap().iter() {
            if let Some(cs) = line.strip_prefix("connstring: ") {
                let mut parts = cs.splitn(4, '.');
                parts.next();
                id = Some(parts.next().context("connstring id")?.to_string());
            }
            if let Some(d) = line.strip_prefix("direct-addr: ") {
                direct = Some(d.replace("0.0.0.0", "127.0.0.1"));
            }
        }
    }
    Ok(ProxyProc {
        child,
        endpoint_id_hex: id.unwrap(),
        direct: direct.unwrap(),
        lines,
    })
}

/// Strip ANSI control/escape sequences (assertions on visible text).
fn strip_ansi(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.next() {
                Some('[') => {
                    for f in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&f) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(f) = chars.next() {
                        if f == '\u{07}' {
                            break;
                        }
                        if f == '\u{1b}' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            },
            '\n' => out.push('\n'),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {}
            c => out.push(c),
        }
    }
    out
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = env_logger::try_init();
    tokio::time::timeout(HARD_TIMEOUT, run())
        .await
        .map_err(|_| anyhow!("hard timeout after {HARD_TIMEOUT:?}"))?
}

async fn run() -> Result<()> {
    let log = |m: &str| println!("[passkey-e2e] {m}");

    let _relay = start_relay().await?;
    log(&format!("relay on http://127.0.0.1:{RELAY_PORT}"));
    let mut proxy = start_proxy().await?;
    log(&format!(
        "proxy up: id={} direct={}",
        proxy.endpoint_id_hex, proxy.direct
    ));

    // The "user": a software passkey (user-verifying) driven through
    // the real webauthn-rs ceremony types.
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let origin = Url::parse(RP_ORIGIN)?;

    // --- the composed client under wasmtime --------------------------------
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_file(
        &engine,
        manifest_path("../../client-core/composed-client.wasm"),
    )?;
    let mut linker: Linker<Ctx> = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi::p3::add_to_linker(&mut linker)?;
    webrtc_host::add_to_linker(&mut linker)?;
    polymorph_webcrypto_wasmtime::add_to_linker(&mut linker)?;
    wasmtime_websocket::add_to_linker(&mut linker)?;

    let mut wasi = WasiCtx::builder();
    wasi.inherit_stdio().inherit_env().inherit_network();
    let mut store = Store::new(
        &engine,
        Ctx {
            wasi: wasi.build(),
            webrtc: WasiWebrtcCtx::new(),
            webcrypto: WasiWebcryptoCtx::new(),
            websocket: WasiWebsocketCtx::new(),
            table: ResourceTable::new(),
        },
    );
    let client = bindings::ComposedClient::instantiate_async(&mut store, &component, &linker).await?;
    log("composed client instantiated");

    let relay_url = format!("http://127.0.0.1:{RELAY_PORT}");
    let peer_hex = proxy.endpoint_id_hex.clone();
    let direct = proxy.direct.clone();

    // Authenticator calls are pure crypto (no blocking I/O), so they
    // run inline inside run_concurrent; the authenticator travels
    // through the result so the reattach leg can reuse the same
    // credential ("same user, new device instance").
    let result: Result<(u64, proto::Escrow, WebauthnAuthenticator<SoftPasskey>)> = store
        .run_concurrent(async move |accessor| {
            let guest = client.experiment_mosh_client_client().client_session();

            // --- session 1: fresh, then made persistent -----------------
            let session = guest
                .call_connect_proxy(
                    accessor,
                    relay_url.clone(),
                    peer_hex.clone(),
                    Some(direct.clone()),
                    TOKEN.into(),
                    80,
                    24,
                )
                .await?
                .map_err(|e| anyhow!("connect-proxy: {e}"))?;
            let session_id = guest
                .call_session_id(accessor, session)
                .await?
                .context("proxy path must assign a session id")?;
            println!("[passkey-e2e] session {session_id} live");

            let mut visible = String::new();
            let wait_for = async |visible: &mut String, needle: &str, label: &str| -> Result<()> {
                for _ in 0..800 {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    let out = guest.call_drain_output(accessor, session).await?;
                    if !out.is_empty() {
                        visible.push_str(&strip_ansi(&out));
                    }
                    if visible.contains(needle) {
                        return Ok(());
                    }
                }
                bail!("timeout waiting for {label} ({needle:?})\n--- visible ---\n{visible}")
            };
            wait_for(&mut visible, "$", "shell prompt").await?;
            guest
                .call_feed_keys(accessor, session, b"echo persist_$(printf mark)er_ok\r".to_vec())
                .await?;
            wait_for(&mut visible, "persist_marker_ok", "pre-detach marker").await?;
            println!("[passkey-e2e] session 1 prompt + marker OK");

            // --- registration ceremony ----------------------------------
            let challenge = guest
                .call_register_start(accessor, session)
                .await?
                .map_err(|e| anyhow!("register-start: {e}"))?;
            let ccr: CreationChallengeResponse = serde_json::from_slice(&challenge)?;
            let reg = authenticator
                .do_registration(origin.clone(), ccr)
                .map_err(|e| anyhow!("soft authenticator registration: {e:?}"))?;
            guest
                .call_register_finish(accessor, session, serde_json::to_vec(&reg)?)
                .await?
                .map_err(|e| anyhow!("register-finish: {e}"))?;
            println!("[passkey-e2e] passkey registered (real ceremony, soft authenticator)");

            // --- escrow + persistence (plain arm; PRF is browser-side) --
            let key = guest.call_session_key(accessor, session).await?;
            let stats = guest.call_stats(accessor, session).await?;
            let escrow = proto::Escrow::Plain {
                key: key.clone(),
                seq_floor: stats.current_seq,
            };
            guest
                .call_make_persistent(accessor, session, escrow.to_json())
                .await?
                .map_err(|e| anyhow!("make-persistent: {e}"))?;
            println!(
                "[passkey-e2e] escrowed {{key, seq-floor={}}}; session persistent",
                stats.current_seq
            );

            guest.call_detach(accessor, session).await?;
            println!("[passkey-e2e] detached");
            Ok((session_id, escrow, authenticator))
        })
        .await?;
    let (session_id, escrow_stored, authenticator) = result?;

    // The proxy must have kept the server.
    tokio::time::sleep(Duration::from_millis(500)).await;
    if !proxy.saw("kept (persistent)") {
        bail!("proxy did not keep the persistent session on detach");
    }
    log("proxy kept mosh-server across detach");

    // --- reattach: negatives, then the real flow ----------------------------
    let mut store2 = Store::new(
        &engine,
        Ctx {
            wasi: {
                let mut b = WasiCtx::builder();
                b.inherit_stdio().inherit_env().inherit_network();
                b.build()
            },
            webrtc: WasiWebrtcCtx::new(),
            webcrypto: WasiWebcryptoCtx::new(),
            websocket: WasiWebsocketCtx::new(),
            table: ResourceTable::new(),
        },
    );
    let client2 =
        bindings::ComposedClient::instantiate_async(&mut store2, &component, &linker).await?;
    log("second composed client instantiated (fresh engine, fresh identity)");

    let relay_url = format!("http://127.0.0.1:{RELAY_PORT}");
    let peer_hex = proxy.endpoint_id_hex.clone();
    let direct = proxy.direct.clone();
    let mut authenticator2 = authenticator; // same soft passkey = same user
    let origin2 = Url::parse(RP_ORIGIN)?;

    let result: Result<()> = store2
        .run_concurrent(async move |accessor| {
            let guest = client2.experiment_mosh_client_client().client_session();
            let flow_guest = client2.experiment_mosh_client_client().reattach_flow();

            // Negative: reattach to a nonexistent session.
            let bogus = flow_guest
                .call_begin(
                    accessor,
                    relay_url.clone(),
                    peer_hex.clone(),
                    Some(direct.clone()),
                    TOKEN.into(),
                    9999,
                )
                .await?;
            if bogus.is_ok() {
                bail!("reattach to nonexistent session was not refused");
            }
            println!(
                "[passkey-e2e] bogus session refused OK ({})",
                bogus.unwrap_err()
            );

            // Negative: garbage assertion.
            let flow = flow_guest
                .call_begin(
                    accessor,
                    relay_url.clone(),
                    peer_hex.clone(),
                    Some(direct.clone()),
                    TOKEN.into(),
                    session_id,
                )
                .await?
                .map_err(|e| anyhow!("begin (negative leg): {e}"))?;
            let refused = flow_guest
                .call_finish(accessor, flow, b"{\"not\":\"an assertion\"}".to_vec())
                .await?;
            if refused.is_ok() {
                bail!("garbage assertion was accepted");
            }
            println!(
                "[passkey-e2e] garbage assertion refused OK ({})",
                refused.unwrap_err()
            );

            // The real flow: begin → assertion → escrow → attach.
            let flow = flow_guest
                .call_begin(
                    accessor,
                    relay_url.clone(),
                    peer_hex.clone(),
                    Some(direct.clone()),
                    TOKEN.into(),
                    session_id,
                )
                .await?
                .map_err(|e| anyhow!("reattach begin: {e}"))?;
            let challenge = flow_guest.call_challenge(accessor, flow).await?;
            let rcr: RequestChallengeResponse = serde_json::from_slice(&challenge)?;
            let assertion = authenticator2
                .do_authentication(origin2.clone(), rcr)
                .map_err(|e| anyhow!("soft authenticator assertion: {e:?}"))?;
            let escrow_back = flow_guest
                .call_finish(accessor, flow, serde_json::to_vec(&assertion)?)
                .await?
                .map_err(|e| anyhow!("reattach finish: {e}"))?;

            let escrow_parsed = proto::Escrow::from_json(&escrow_back)
                .map_err(|e| anyhow!("escrow decode: {e}"))?;
            if escrow_parsed != escrow_stored {
                bail!("escrow came back different from what was stored");
            }
            let proto::Escrow::Plain { key, seq_floor } = escrow_parsed else {
                bail!("expected the plain escrow arm");
            };
            println!("[passkey-e2e] assertion verified; escrow returned verbatim (floor={seq_floor})");

            let session = flow_guest
                .call_attach(accessor, flow, key, seq_floor + SEQ_MARGIN, 80, 24)
                .await?
                .map_err(|e| anyhow!("attach: {e}"))?;

            let mut visible = String::new();
            let wait_for = async |visible: &mut String, needle: &str, label: &str| -> Result<()> {
                for _ in 0..800 {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    let out = guest.call_drain_output(accessor, session).await?;
                    if !out.is_empty() {
                        visible.push_str(&strip_ansi(&out));
                    }
                    if visible.contains(needle) {
                        return Ok(());
                    }
                }
                bail!("timeout waiting for {label} ({needle:?})\n--- visible ---\n{visible}")
            };

            // The SAME session: pre-detach screen state resyncs without
            // typing anything (mosh diffs against client state 0).
            wait_for(&mut visible, "persist_marker_ok", "pre-detach marker resync").await?;
            println!("[passkey-e2e] pre-detach screen state resynced (same shell session)");

            guest
                .call_feed_keys(accessor, session, b"echo re_$(printf atta)ch_ok\r".to_vec())
                .await?;
            wait_for(&mut visible, "re_attach_ok", "post-reattach echo").await?;
            println!("[passkey-e2e] post-reattach echo OK");

            let stats = guest.call_stats(accessor, session).await?;
            if stats.current_seq <= seq_floor + SEQ_MARGIN {
                bail!(
                    "engine did not resume above the floor (current={} floor+margin={})",
                    stats.current_seq,
                    seq_floor + SEQ_MARGIN
                );
            }
            println!(
                "[passkey-e2e] sequence resumed above floor: current={} > {}",
                stats.current_seq,
                seq_floor + SEQ_MARGIN
            );

            guest.call_detach(accessor, session).await?;
            Ok(())
        })
        .await?;
    result?;

    tokio::time::sleep(Duration::from_millis(500)).await;
    // Second detach: still persistent, still kept.
    let kept_twice = proxy
        .lines
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.contains("kept (persistent)"))
        .count();
    if kept_twice < 2 {
        bail!("proxy did not keep the session on the second detach");
    }

    // Graceful teardown reaps the (deliberately still alive)
    // persistent mosh-server — a SIGKILLed proxy would orphan it.
    proxy.shutdown().await?;
    if !proxy.saw("reaped 1 session(s)") {
        bail!("proxy shutdown did not reap the persistent session");
    }
    println!("passkey E2E (M6 gate): OK");
    Ok(())
}
