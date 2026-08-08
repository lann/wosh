//! M7 gate: the composed client core dials the proxy over iroh, opens
//! the ssh-forwarding stream, speaks ssh (x/crypto/ssh in wasm)
//! through it to an in-process sshd stand-in, runs `mosh-server` via
//! ssh exec, and then runs mosh over the connection's datagram
//! tunnel. The proxy never sees the mosh key.
//!
//!   relay (child) ← proxy (child: deprivileged, --ssh-target stand-in)
//!                     ↑ iroh QUIC (control stream + ssh-forward stream + tunnel)
//!   composed-client.wasm under wasmtime (this process)
//!                     ↕ ssh (exec mosh-server)
//!   in-process sshd stand-in (this process, russh)

mod standin;

use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use polymorph_webcrypto_wasmtime::{WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView};
use tokio::io::{AsyncBufReadExt, BufReader};
use wasmtime::component::{Component, HasData, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_webrtc_datachannels::{
    self as webrtc_host, WasiWebrtcCtx, WasiWebrtcCtxView, WasiWebrtcView,
};
use wasmtime_websocket::{WasiWebsocketCtx, WasiWebsocketCtxView, WasiWebsocketView};

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

// 3345/3347/3348/3349 are taken by sibling harnesses (M3/M4/M5/M6).
const RELAY_PORT: u16 = 3350;
const TOKEN: &str = "t3st-pairing";
const HARD_TIMEOUT: Duration = Duration::from_secs(120);

// Synthetic test credentials for the in-process sshd stand-in only —
// never used against a real host.
const TEST_USER: &str = "testuser";
const TEST_PASSWORD: &str = "testpass";

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
    let dir = std::env::temp_dir().join("experiment-mosh-m7");
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
    /// Collected stdout lines (shared with the reader task).
    lines: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

/// Start the proxy pointed at the sshd stand-in, deliberately without
/// `--personal` — this gate proves the deprivileged posture (M7: the
/// proxy refuses to spawn sessions itself; the client must go through
/// inner ssh instead).
async fn start_proxy(standin_port: u16) -> Result<ProxyProc> {
    let state = std::env::temp_dir().join(format!("experiment-mosh-m7-state-{}", std::process::id()));
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
            "--state-dir",
            state.to_str().unwrap(),
            "--component",
            &manifest_path("../../proxy/composed-proxy.wasm"),
            "--ssh-target",
            &format!("127.0.0.1:{standin_port}"),
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
                // 1.<id-hex>.<token>.<relay-url>
                let mut parts = cs.splitn(4, '.');
                let v = parts.next().unwrap_or_default();
                if v != "1" {
                    bail!("unexpected connstring version in {cs}");
                }
                id = Some(parts.next().context("connstring id")?.to_string());
            }
            if let Some(d) = line.strip_prefix("direct-addr: ") {
                // The proxy binds 0.0.0.0; loopback-dial it.
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

/// Kills every stand-in-reported spawned pid (mosh-server daemonizes;
/// nothing else in the harness reaps it) even on failure paths.
struct PidReaper(std::sync::Arc<std::sync::Mutex<Vec<u32>>>);

impl Drop for PidReaper {
    fn drop(&mut self) {
        let pids = self.0.lock().unwrap();
        for pid in pids.iter() {
            println!("[ssh-e2e] reaping spawned pid {pid}");
            let _ = std::process::Command::new("kill")
                .args(["-9", &pid.to_string()])
                .status();
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = env_logger::try_init();
    tokio::time::timeout(HARD_TIMEOUT, run())
        .await
        .map_err(|_| anyhow!("hard timeout after {HARD_TIMEOUT:?}"))?
}

async fn run() -> Result<()> {
    let log = |m: &str| println!("[ssh-e2e] {m}");

    let sshd = standin::start().await.context("starting sshd stand-in")?;
    let _reaper = PidReaper(sshd.spawned_pids.clone());
    log(&format!(
        "sshd stand-in on 127.0.0.1:{} fp={}",
        sshd.port, sshd.host_key_fp
    ));

    let _relay = start_relay().await?;
    log(&format!("relay on http://127.0.0.1:{RELAY_PORT}"));
    let mut proxy = start_proxy(sshd.port).await?;
    log(&format!(
        "proxy up (deprivileged, --ssh-target 127.0.0.1:{}): id={} direct={}",
        sshd.port, proxy.endpoint_id_hex, proxy.direct
    ));

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
    let standin_fp = sshd.host_key_fp.clone();
    let password_attempts = sshd.password_attempts.clone();

    let result: Result<()> = store
        .run_concurrent(async move |accessor| {
            let guest = client.experiment_mosh_client_client().client_session();

            // --- Phase 1: NewSession refused without --personal ------------
            // Even the CORRECT pairing token must be rejected: this gate
            // proves the deprivileged proxy posture (it never spawns
            // sessions itself in this mode).
            let refused = guest
                .call_connect_proxy(
                    accessor,
                    relay_url.clone(),
                    peer_hex.clone(),
                    Some(direct.clone()),
                    TOKEN.into(),
                    80,
                    24,
                )
                .await?;
            let Err(msg) = refused else {
                bail!("connect-proxy succeeded despite no --personal");
            };
            if !msg.to_lowercase().contains("personal") {
                bail!("connect-proxy refusal didn't mention 'personal': {msg}");
            }
            println!("[ssh-e2e] phase 1: NewSession refused without --personal OK ({msg})");

            // --- Phase 2: wrong expected-host-key fails before auth --------
            let attempts_before = password_attempts.load(std::sync::atomic::Ordering::SeqCst);
            let bogus_fp = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
            let refused = guest
                .call_connect_ssh(
                    accessor,
                    relay_url.clone(),
                    peer_hex.clone(),
                    Some(direct.clone()),
                    TOKEN.into(),
                    TEST_USER.into(),
                    TEST_PASSWORD.into(),
                    Some(bogus_fp.into()),
                    None,
                    80,
                    24,
                )
                .await?;
            let Err(msg) = refused else {
                bail!("connect-ssh succeeded despite a bogus expected-host-key");
            };
            if !msg.to_lowercase().contains("host key mismatch") {
                bail!("host-key refusal didn't mention 'host key mismatch': {msg}");
            }
            let attempts_after = password_attempts.load(std::sync::atomic::Ordering::SeqCst);
            if attempts_after != attempts_before {
                bail!(
                    "password was sent to an unapproved host key (attempts {attempts_before} -> {attempts_after})"
                );
            }
            println!(
                "[ssh-e2e] phase 2: wrong expected-host-key failed before auth OK ({msg}); password_attempts unchanged ({attempts_after})"
            );

            // --- Phase 3: wrong password fails legibly ----------------------
            let attempts_before = password_attempts.load(std::sync::atomic::Ordering::SeqCst);
            let refused = guest
                .call_connect_ssh(
                    accessor,
                    relay_url.clone(),
                    peer_hex.clone(),
                    Some(direct.clone()),
                    TOKEN.into(),
                    TEST_USER.into(),
                    "wrongpass".into(),
                    Some(standin_fp.clone()),
                    None,
                    80,
                    24,
                )
                .await?;
            let Err(msg) = refused else {
                bail!("connect-ssh succeeded with the wrong password");
            };
            if !msg.to_lowercase().contains("auth") {
                bail!("wrong-password refusal didn't mention 'auth': {msg}");
            }
            let attempts_after = password_attempts.load(std::sync::atomic::Ordering::SeqCst);
            if attempts_after <= attempts_before {
                bail!(
                    "wrong-password attempt wasn't counted (attempts {attempts_before} -> {attempts_after})"
                );
            }
            println!(
                "[ssh-e2e] phase 3: wrong password failed legibly OK ({msg}); password_attempts {attempts_before} -> {attempts_after}"
            );

            // --- Phase 4: positive path --------------------------------------
            let session = guest
                .call_connect_ssh(
                    accessor,
                    relay_url.clone(),
                    peer_hex.clone(),
                    Some(direct.clone()),
                    TOKEN.into(),
                    TEST_USER.into(),
                    TEST_PASSWORD.into(),
                    None, // TOFU first contact
                    Some(
                        "mosh-server new -i 127.0.0.1 -c 256 -- bash --noprofile --norc -i"
                            .into(),
                    ),
                    80,
                    24,
                )
                .await?
                .map_err(|e| anyhow!("connect-ssh (positive): {e}"))?;
            println!("[ssh-e2e] phase 4: connect-ssh OK (inner ssh + mosh-server + tunnel)");

            let observed_fp = guest
                .call_ssh_host_key(accessor, session)
                .await?
                .context("ssh-host-key returned none after connect-ssh")?;
            if observed_fp != standin_fp {
                bail!(
                    "ssh-host-key mismatch: engine reported {observed_fp}, stand-in computed {standin_fp}"
                );
            }
            println!("[ssh-e2e] ssh-host-key matches stand-in fingerprint: {observed_fp}");

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
            println!("[ssh-e2e] prompt OK");

            guest
                .call_feed_keys(accessor, session, b"echo m0sh_$(printf ssh)_ok\r".to_vec())
                .await?;
            wait_for(&mut visible, "m0sh_ssh_ok", "echo marker").await?;
            println!("[ssh-e2e] echo round-trip OK");

            guest.call_resize(accessor, session, 100, 30).await?;
            guest
                .call_feed_keys(accessor, session, b"stty size\r".to_vec())
                .await?;
            wait_for(&mut visible, "30 100", "stty size after resize").await?;
            println!("[ssh-e2e] resize OK");

            let stats = guest.call_stats(accessor, session).await?;
            println!(
                "[ssh-e2e] stats: sent={} acked={} recv={} rto={}ms",
                stats.sent_num, stats.acked_num, stats.recv_num, stats.rto_ms
            );
            if stats.sent_num < 1 || stats.acked_num < 1 || stats.recv_num < 1 {
                bail!("stats sanity failed: {stats:?}");
            }

            guest.call_detach(accessor, session).await?;
            Ok(())
        })
        .await?;
    result?;

    proxy.child.kill().await.ok();
    println!("ssh E2E (M7 gate): OK");
    Ok(())
}
