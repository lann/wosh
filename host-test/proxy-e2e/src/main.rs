//! M4 gate: the composed client core connects through the real proxy
//! binary (thin shell + proxy-core component) to a stock mosh-server
//! the proxy spawned — full control channel (hello/pairing token/TOFU
//! --yes, new-session, key delivery) and the datagram tunnel with
//! sub-framing exercised by a bulk phase whose server datagrams
//! exceed the 1162 B ceiling.
//!
//!   relay (child) ← proxy (child: shell + proxy-core + endpoint)
//!                     ↑ iroh QUIC (control stream + framed datagrams)
//!   composed-client.wasm under wasmtime (this process)

use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use polymorph_webcrypto_wasmtime::{WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView};
use tokio::io::{AsyncBufReadExt, BufReader};
use wasmtime::component::{Component, HasData, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_webrtc_datachannels::{
    self as webrtc_host, WebrtcCtx, WebrtcCtxView, WebrtcView,
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

const RELAY_PORT: u16 = 3347;
const TOKEN: &str = "t3st-pairing";
const HARD_TIMEOUT: Duration = Duration::from_secs(120);

struct Ctx {
    wasi: WasiCtx,
    webrtc: WebrtcCtx,
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

impl WebrtcView for Ctx {
    fn webrtc(&mut self) -> WebrtcCtxView<'_> {
        WebrtcCtxView {
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
    let dir = std::env::temp_dir().join("wosh-m4");
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

async fn start_proxy() -> Result<ProxyProc> {
    let state = std::env::temp_dir().join(format!("wosh-m4-state-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    let bin = manifest_path("../../proxy/target/release/wosh-proxy");
    let mut child = tokio::process::Command::new(&bin)
        .args([
            "--relay",
            &format!("http://127.0.0.1:{RELAY_PORT}"),
            "--token",
            TOKEN,
            "--no-qr",
            "--yes",
            // M4 exercises proxy-spawned sessions (D2 interim), which
            // are opt-in since M7's deprivileged default.
            "--personal",
            "--state-dir",
            state.to_str().unwrap(),
            "--component",
            &manifest_path("../../proxy/composed-proxy.wasm"),
            "--shell",
            "bash --noprofile --norc -i",
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

#[tokio::main]
async fn main() -> Result<()> {
    let _ = env_logger::try_init();
    tokio::time::timeout(HARD_TIMEOUT, run())
        .await
        .map_err(|_| anyhow!("hard timeout after {HARD_TIMEOUT:?}"))?
}

async fn run() -> Result<()> {
    let log = |m: &str| println!("[proxy-e2e] {m}");

    let _relay = start_relay().await?;
    log(&format!("relay on http://127.0.0.1:{RELAY_PORT}"));
    let mut proxy = start_proxy().await?;
    log(&format!(
        "proxy up: id={} direct={}",
        proxy.endpoint_id_hex, proxy.direct
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
            webrtc: WebrtcCtx::new(),
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

    let result: Result<()> = store
        .run_concurrent(async move |accessor| {
            let guest = client.experiment_mosh_client_client().client_session();

            // Negative path: wrong pairing token ⇒ refused without
            // ceremony (the proxy stays up).
            let refused = guest
                .call_connect_proxy(
                    accessor,
                    relay_url.clone(),
                    peer_hex.clone(),
                    Some(direct.clone()),
                    "wrong-token".into(),
                    80,
                    24,
                )
                .await?;
            if refused.is_ok() {
                bail!("wrong pairing token was accepted");
            }
            println!("[proxy-e2e] wrong token refused OK ({})", refused.unwrap_err());

            // Real session.
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
            println!("[proxy-e2e] connect-proxy OK (control channel + key delivery)");

            let max = guest.call_max_datagram_size(accessor, session).await?;
            println!("[proxy-e2e] max-datagram-size: {max:?}");

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
            println!("[proxy-e2e] prompt OK");

            guest
                .call_feed_keys(accessor, session, b"echo m0sh_$(printf prox)_ok\r".to_vec())
                .await?;
            wait_for(&mut visible, "m0sh_prox_ok", "echo marker").await?;
            println!("[proxy-e2e] echo round-trip OK");

            guest.call_resize(accessor, session, 100, 30).await?;
            guest
                .call_feed_keys(accessor, session, b"stty size\r".to_vec())
                .await?;
            wait_for(&mut visible, "30 100", "stty size after resize").await?;
            println!("[proxy-e2e] resize OK");

            // Bulk: an incompressible full-screen paint forces the
            // stock server over 1162 B — mosh zlib-compresses its
            // diffs, so compressible output (`seq`) can stay under the
            // ceiling and leave sub-framing untested. 220×50 of base64
            // noise ≈ 11 KB raw ≈ 8 KB compressed ⇒ several full-size
            // (~1252 B) fragments regardless of how the server slices
            // its frames. Without proxy-side sub-framing this phase
            // stalls (send-datagram rejects oversized datagrams).
            guest.call_resize(accessor, session, 220, 50).await?;
            guest
                .call_feed_keys(
                    accessor,
                    session,
                    b"b=$(head -c 8192 /dev/urandom | base64 -w0); \
                      printf '%s\\n' \"$b\"; echo BULK_$(printf DO)NE\r"
                        .to_vec(),
                )
                .await?;
            wait_for(&mut visible, "BULK_DONE", "bulk done marker").await?;
            println!("[proxy-e2e] bulk over sub-framed tunnel OK");

            let stats = guest.call_stats(accessor, session).await?;
            println!(
                "[proxy-e2e] stats: sent={} acked={} recv={} rto={}ms",
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

    // The proxy logs a per-connection summary with the fragmented
    // count once the session closes; require ≥ 1.
    let mut fragmented: Option<u64> = None;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        for line in proxy.lines.lock().unwrap().iter() {
            if let Some(ix) = line.find("fragmented=") {
                let tail = &line[ix + "fragmented=".len()..];
                let n: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
                fragmented = n.parse().ok();
            }
        }
        if fragmented.is_some() {
            break;
        }
    }
    let fragmented = fragmented.context("proxy never logged a session summary")?;
    println!("[proxy-e2e] proxy fragmented {fragmented} oversized server datagrams");
    if fragmented < 1 {
        bail!("bulk phase produced no oversized datagrams — sub-framing untested");
    }

    proxy.child.kill().await.ok();
    println!("proxy E2E (M4 gate): OK");
    Ok(())
}
