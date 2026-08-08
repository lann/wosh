//! M3 gate: the wac-composed client core (mosh engine + client-core
//! glue + polymorph-iroh endpoint) runs under wasmtime and speaks real
//! mosh SSP over iroh QUIC datagrams to a stock C mosh-server.
//!
//! Topology (one process + two children):
//!
//!   composed-client.wasm            upstream iroh peer (this binary)
//!   [wasmtime store]                [tokio]
//!     engine⇄glue⇄endpoint  ──UDP──►  accept → datagram↔UDP pump ──► mosh-server
//!            │                           (M4's forwarder in miniature)
//!            └─── home relay (iroh-relay --dev, spawned child)
//!
//! The server side is the *real* iroh crate: every datagram the
//! composed client exchanges is RFC 9221 interop against upstream, not
//! just against polymorph's own stack. Assertions mirror the M1
//! conformance suite: prompt, echo round-trip, resize, stats, sizes.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use iroh::endpoint::presets;
use iroh::Endpoint;
use polymorph_webcrypto_wasmtime::{WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView};
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

const ALPN: &[u8] = b"experiment-mosh/0";
const RELAY_PORT: u16 = 3345;
const HARD_TIMEOUT: Duration = Duration::from_secs(90);

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

/// A spawned stock mosh-server: `new` prints MOSH CONNECT and
/// detaches; the daemon pid arrives on stderr.
struct MoshServer {
    port: u16,
    key: String,
    pid: Option<u32>,
}

impl MoshServer {
    fn spawn() -> Result<Self> {
        let out = std::process::Command::new("mosh-server")
            .args([
                "new", "-i", "127.0.0.1", "-c", "256", "--", "bash", "--noprofile", "--norc",
                "-i",
            ])
            .env("LC_ALL", "C.UTF-8")
            .env("TERM", "xterm-256color")
            .output()
            .context("spawning mosh-server")?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let connect = stdout
            .lines()
            .find_map(|l| l.strip_prefix("MOSH CONNECT "))
            .with_context(|| format!("no MOSH CONNECT line.\nstdout: {stdout}\nstderr: {stderr}"))?;
        let mut parts = connect.split_whitespace();
        let port: u16 = parts.next().context("port")?.parse()?;
        let key = parts.next().context("key")?.to_string();
        let pid = stderr
            .split("detached, pid = ")
            .nth(1)
            .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|s| s.parse().ok());
        Ok(Self { port, key, pid })
    }
}

impl Drop for MoshServer {
    fn drop(&mut self) {
        if let Some(pid) = self.pid {
            let _ = std::process::Command::new("kill")
                .args(["-9", &pid.to_string()])
                .status();
        }
    }
}

/// iroh-relay --dev on a fixed local port (the polymorph endpoint's
/// `bind` requires a home relay even for the UDP-direct path).
async fn start_relay() -> Result<tokio::process::Child> {
    let dir = std::env::temp_dir().join("experiment-mosh-m3");
    std::fs::create_dir_all(&dir)?;
    let cfg = dir.join("relay.toml");
    std::fs::write(
        &cfg,
        format!("http_bind_addr = \"127.0.0.1:{RELAY_PORT}\"\nenable_metrics = false\n"),
    )?;
    let bin = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.deps/polymorph-iroh/.deps/iroh/target/release/iroh-relay"
    );
    let child = tokio::process::Command::new(bin)
        .arg("--dev")
        .arg("-c")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning {bin}"))?;
    // Wait until it listens.
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

/// Strip ANSI control/escape sequences; assertions run on visible text.
fn strip_ansi(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.next() {
                Some('[') => {
                    // CSI: params/intermediates, then a final byte @-~.
                    for f in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&f) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // OSC: until BEL or ST (ESC \).
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
                _ => {} // 2-byte escape: skip the one char
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
    let component_path = std::env::args()
        .nth(1)
        .context("usage: composed-e2e <composed-client.wasm>")?;

    tokio::time::timeout(HARD_TIMEOUT, run(&component_path))
        .await
        .map_err(|_| anyhow!("hard timeout after {HARD_TIMEOUT:?}"))?
}

async fn run(component_path: &str) -> Result<()> {
    let log = |m: &str| println!("[composed-e2e] {m}");

    // --- the server side of the world ------------------------------------
    let mosh = MoshServer::spawn()?;
    log(&format!("mosh-server on 127.0.0.1:{} (pid {:?})", mosh.port, mosh.pid));
    let _relay = start_relay().await?;
    log(&format!("relay on http://127.0.0.1:{RELAY_PORT}"));

    // Upstream iroh peer: accept the composed client, pump datagrams
    // to/from the mosh-server over loopback UDP.
    let server = Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>()?)?
        .bind()
        .await?;
    let server_id_hex = hex::encode(server.id().as_bytes());
    let direct_addr = server
        .bound_sockets()
        .first()
        .copied()
        .context("no bound socket")?;
    log(&format!("upstream-iroh peer {server_id_hex} on {direct_addr}"));

    let mosh_port = mosh.port;
    let accept_endpoint = server.clone();
    tokio::spawn(async move {
        while let Some(incoming) = accept_endpoint.accept().await {
            let Ok(conn) = incoming.await else { continue };
            let Ok(udp) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else { continue };
            if udp.connect(("127.0.0.1", mosh_port)).await.is_err() {
                continue;
            }
            let udp = Arc::new(udp);

            // datagram → UDP
            let c1 = conn.clone();
            let u1 = udp.clone();
            tokio::spawn(async move {
                while let Ok(d) = c1.read_datagram().await {
                    let _ = u1.send(&d).await;
                }
            });
            // UDP → datagram
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                while let Ok(n) = udp.recv(&mut buf).await {
                    if conn.send_datagram(Bytes::copy_from_slice(&buf[..n])).is_err() {
                        break;
                    }
                }
            });
        }
    });

    // --- the composed client under wasmtime --------------------------------
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_file(&engine, component_path)?;
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
    let key = mosh.key.clone();
    let direct = direct_addr.to_string();

    let result: Result<()> = store
        .run_concurrent(async move |accessor| {
            let guest = client.experiment_mosh_client_client().client_session();

            let session = guest
                .call_dial(
                    accessor,
                    relay_url,
                    server_id_hex,
                    Some(direct),
                    key,
                    80,
                    24,
                )
                .await?
                .map_err(|e| anyhow!("dial: {e}"))?;
            println!("[composed-e2e] dial OK (mosh over iroh datagrams)");

            let max_dgram = guest.call_max_datagram_size(accessor, session).await?;
            println!("[composed-e2e] max-datagram-size: {max_dgram:?}");
            let max_dgram = max_dgram.context("peer accepts no datagrams")?;
            if max_dgram < 1138 {
                bail!("datagram ceiling {max_dgram} < engine wire max 1138");
            }

            // Conformance, M1-style.
            let mut visible = String::new();
            let wait_for = async |visible: &mut String, needle: &str, label: &str| -> Result<()> {
                for _ in 0..400 {
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
            println!("[composed-e2e] prompt OK");

            guest
                .call_feed_keys(accessor, session, b"echo m0sh_$(printf iroh)_ok\r".to_vec())
                .await?;
            wait_for(&mut visible, "m0sh_iroh_ok", "echo marker").await?;
            println!("[composed-e2e] echo round-trip OK");

            guest.call_resize(accessor, session, 100, 30).await?;
            guest
                .call_feed_keys(accessor, session, b"stty size\r".to_vec())
                .await?;
            wait_for(&mut visible, "30 100", "stty size after resize").await?;
            println!("[composed-e2e] resize OK");

            let stats = guest.call_stats(accessor, session).await?;
            println!(
                "[composed-e2e] stats: sent={} acked={} recv={} rto={}ms lastRecvAge={:?}ms",
                stats.sent_num, stats.acked_num, stats.recv_num, stats.rto_ms, stats.last_recv_age_ms
            );
            if stats.sent_num < 1 || stats.acked_num < 1 || stats.recv_num < 1 {
                bail!("stats sanity failed: {stats:?}");
            }

            guest.call_detach(accessor, session).await?;
            Ok(())
        })
        .await?;
    result?;

    server.close().await;
    println!("composed E2E (M3 gate): OK");
    Ok(())
}
