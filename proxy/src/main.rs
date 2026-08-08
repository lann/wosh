//! The experiment-mosh proxy (M4, workstream C).
//!
//! Runs on (or near) the target host. Embeds wasmtime + the
//! polymorph-iroh **endpoint component** (D1: the same component the
//! browser client composes — browsers reach the WebRTC-direct path
//! only via polymorph signaling, so the proxy exercises our stack,
//! not the upstream iroh crate). Per accepted connection it speaks
//! the control channel (proto), spawns `mosh-server -i 127.0.0.1`
//! (interim mode, D2 — the proxy runs as the target user), and pumps
//! datagrams between the iroh connection and the session's loopback
//! UDP socket, sub-framing oversized server datagrams (finding 9).
//!
//! Bootstrap: prints a connection string (`1.<endpoint-id-hex>.
//! <pairing-token>.<relay-url>`) and a QR of `<qr-base><connstring>`.
//! Unknown peers presenting the pairing token hit a TOFU prompt
//! (`--yes` auto-accepts, for harnesses); known peers connect without
//! ceremony; unknown peers without the token are dropped silently.

use std::collections::HashSet;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use polymorph_webcrypto_wasmtime::{WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView};
use rand::Rng;
use wasmtime::component::{Accessor, Component, HasData, Linker, ResourceAny, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_webrtc_datachannels::{
    self as webrtc_host, WasiWebrtcCtx, WasiWebrtcCtxView, WasiWebrtcView,
};
use wasmtime_websocket::{WasiWebsocketCtx, WasiWebsocketCtxView, WasiWebsocketView};

use experiment_mosh_proto as proto;

mod bindings {
    wasmtime::component::bindgen!({
        path: "../.deps/polymorph-iroh/wit",
        world: "iroh-endpoint",
        imports: {
            default: async | store | trappable,
        },
        exports: {
            default: async,
        },
    });
}

const ALPN: &[u8] = b"experiment-mosh/0";

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

struct Cli {
    relay: String,
    state_dir: PathBuf,
    qr_base: String,
    component: PathBuf,
    token: Option<String>,
    yes: bool,
    no_qr: bool,
}

fn usage() -> anyhow::Error {
    anyhow!(
        "usage: experiment-mosh-proxy --relay <url> [--state-dir <dir>] \
         [--qr-base <url>] [--component <iroh_endpoint.wasm>] \
         [--token <pairing-token>] [--yes] [--no-qr]"
    )
}

fn parse_args() -> Result<Cli> {
    let mut relay = None;
    let mut state_dir = None;
    let mut qr_base = None;
    let mut component = None;
    let mut token = None;
    let mut yes = false;
    let mut no_qr = false;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(usage);
        match flag.as_str() {
            "--relay" => relay = Some(value()?),
            "--state-dir" => state_dir = Some(PathBuf::from(value()?)),
            "--qr-base" => qr_base = Some(value()?),
            "--component" => component = Some(PathBuf::from(value()?)),
            "--token" => token = Some(value()?),
            "--yes" => yes = true,
            "--no-qr" => no_qr = true,
            _ => return Err(usage()),
        }
    }
    let state_dir = state_dir.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".local/state/experiment-mosh-proxy")
    });
    let component = component.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../.deps/polymorph-iroh/target/wasm32-wasip2/release/iroh_endpoint.wasm")
    });
    Ok(Cli {
        relay: relay.ok_or_else(usage)?,
        state_dir,
        qr_base: qr_base.unwrap_or_else(|| "https://experiment-mosh.invalid/#".into()),
        component,
        token,
        yes,
        no_qr,
    })
}

/// The TOFU store: one hex endpoint-id per line.
struct KnownClients {
    path: PathBuf,
    ids: HashSet<String>,
}

impl KnownClients {
    fn load(dir: &PathBuf) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("known_clients");
        let ids = match std::fs::read_to_string(&path) {
            Ok(s) => s
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect(),
            Err(_) => HashSet::new(),
        };
        Ok(Self { path, ids })
    }

    fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }

    fn add(&mut self, id: &str) -> Result<()> {
        if self.ids.insert(id.to_string()) {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            writeln!(f, "{id}")?;
        }
        Ok(())
    }
}

/// A spawned stock mosh-server (detaches; daemon pid on stderr).
struct MoshSession {
    port: u16,
    key: String,
    pid: Option<u32>,
}

impl MoshSession {
    fn spawn() -> Result<Self> {
        let out = std::process::Command::new("mosh-server")
            .args(["new", "-i", "127.0.0.1", "-c", "256"])
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

impl Drop for MoshSession {
    fn drop(&mut self) {
        if let Some(pid) = self.pid {
            let _ = std::process::Command::new("kill")
                .args(["-9", &pid.to_string()])
                .status();
        }
    }
}

fn random_token() -> String {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = env_logger::try_init();
    let cli = parse_args()?;
    let token = cli.token.clone().unwrap_or_else(random_token);
    let mut known = KnownClients::load(&cli.state_dir)?;

    let mut config = Config::new();
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_file(&engine, &cli.component)
        .with_context(|| format!("loading {}", cli.component.display()))?;
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
    let endpoint_world =
        bindings::IrohEndpoint::instantiate_async(&mut store, &component, &linker).await?;

    let relay = cli.relay.clone();
    store
        .run_concurrent(async move |accessor| -> Result<()> {
            let identity_gen = endpoint_world.polymorph_iroh_identity_generate();
            let ep_iface = endpoint_world.polymorph_iroh_endpoint();
            let options_res = ep_iface.endpoint_options();
            let endpoint_res = ep_iface.endpoint();
            let conn_res = ep_iface.connection();
            let send_res = ep_iface.send_stream();
            let recv_res = ep_iface.recv_stream();

            let identity = identity_gen
                .call_generate(accessor)
                .await?
                .map_err(|e| anyhow!("identity-generate: {e:?}"))?;

            let options = options_res.call_constructor(accessor, identity).await?;
            options_res
                .call_add_alpn(accessor, options, ALPN.to_vec())
                .await?;
            options_res
                .call_relay_url(accessor, options, relay.clone())
                .await?;
            options_res
                .call_udp_bind_addr(accessor, options, "0.0.0.0:0".into())
                .await?;

            let endpoint = endpoint_res
                .call_bind(accessor, options)
                .await?
                .map_err(|e| anyhow!("bind: {e:?}"))?;

            let id = endpoint_res.call_id(accessor, endpoint).await?;
            let id_hex = hex::encode(&id);
            let direct = endpoint_res.call_direct_addr(accessor, endpoint).await?;

            let connstring = format!("1.{id_hex}.{token}.{relay}");
            println!("connstring: {connstring}");
            if let Some(direct) = &direct {
                println!("direct-addr: {direct}");
            }
            if !cli.no_qr {
                let url = format!("{}{}", cli.qr_base, connstring);
                match qrcode::QrCode::new(url.as_bytes()) {
                    Ok(code) => {
                        let rendered = code
                            .render::<qrcode::render::unicode::Dense1x2>()
                            .quiet_zone(true)
                            .build();
                        println!("{rendered}");
                        println!("scan → {url}");
                    }
                    Err(e) => println!("(no QR: {e})"),
                }
            }
            println!("ready; pairing token: {token}");

            // One future per live connection, all sharing the accessor.
            let mut sessions = FuturesUnordered::new();
            let mut session_ids = 0u64;

            let handle_conn = |conn: ResourceAny, session_id: u64, accepted: bool| {
                let token = token.clone();
                async move {
                    let peer_hex = match conn_res.call_peer(accessor, conn).await {
                        Ok(p) => hex::encode(p),
                        Err(e) => {
                            eprintln!("[conn {session_id}] peer: {e:?}");
                            return;
                        }
                    };
                    let r = serve_connection(
                        accessor, &conn_res, &send_res, &recv_res, conn, session_id, &peer_hex,
                        &token, accepted,
                    )
                    .await;
                    match r {
                        Ok(summary) => println!("[conn {session_id}] {peer_hex}: {summary}"),
                        Err(e) => println!("[conn {session_id}] {peer_hex}: error: {e:#}"),
                    }
                    let _ = conn_res.call_close(accessor, conn, 0, "done".into()).await;
                }
            };

            loop {
                if sessions.is_empty() {
                    let conn = endpoint_res
                        .call_accept(accessor, endpoint)
                        .await?
                        .map_err(|e| anyhow!("accept: {e:?}"))?;
                    session_ids += 1;
                    let peer = conn_res.call_peer(accessor, conn).await?;
                    let peer_hex = hex::encode(&peer);
                    let accepted =
                        tofu_gate(&mut known, &peer_hex, cli.yes).await?;
                    sessions.push(handle_conn(conn, session_ids, accepted));
                } else {
                    futures::select! {
                        accepted = futures::FutureExt::fuse(endpoint_res.call_accept(accessor, endpoint)) => {
                            let conn = accepted?.map_err(|e| anyhow!("accept: {e:?}"))?;
                            session_ids += 1;
                            let peer = conn_res.call_peer(accessor, conn).await?;
                            let peer_hex = hex::encode(&peer);
                            let ok = tofu_gate(&mut known, &peer_hex, cli.yes).await?;
                            sessions.push(handle_conn(conn, session_ids, ok));
                        }
                        _ = sessions.next() => {}
                    }
                }
            }
        })
        .await??;

    Ok(())
}

/// TOFU: known peers pass; unknown peers are provisionally admitted
/// here and finally gated by the token + operator prompt inside the
/// control handshake (we only learn "has the token" from Hello).
/// Returns whether the peer was already known.
async fn tofu_gate(known: &mut KnownClients, peer_hex: &str, _yes: bool) -> Result<bool> {
    Ok(known.contains(peer_hex))
}

/// Everything for one accepted connection: control handshake (token +
/// TOFU prompt for unknown peers), session spawn, datagram pumps.
#[allow(clippy::too_many_arguments)]
async fn serve_connection<'a>(
    accessor: &Accessor<Ctx>,
    conn_res: &bindings::exports::polymorph::iroh::endpoint::GuestConnection<'a>,
    send_res: &bindings::exports::polymorph::iroh::endpoint::GuestSendStream<'a>,
    recv_res: &bindings::exports::polymorph::iroh::endpoint::GuestRecvStream<'a>,
    conn: ResourceAny,
    session_id: u64,
    peer_hex: &str,
    token: &str,
    known_peer: bool,
) -> Result<String> {
    // The client opens the control stream.
    let (ctl_send, ctl_recv) = conn_res
        .call_accept_bi(accessor, conn)
        .await?
        .map_err(|e| anyhow!("accept-bi: {e:?}"))?;

    let mut ctl_buf: Vec<u8> = Vec::new();
    let mut next_msg = async |buf: &mut Vec<u8>| -> Result<proto::Client> {
        loop {
            if let Some(m) = proto::decode::<proto::Client>(buf).map_err(|e| anyhow!(e))? {
                return Ok(m);
            }
            match recv_res
                .call_read(accessor, ctl_recv, 4096)
                .await?
                .map_err(|e| anyhow!("control read: {e:?}"))?
            {
                Some(bytes) => buf.extend_from_slice(&bytes),
                None => bail!("control stream closed"),
            }
        }
    };
    let send_msg = async |m: &proto::Proxy| -> Result<()> {
        send_res
            .call_write(accessor, ctl_send, proto::encode(m))
            .await?
            .map_err(|e| anyhow!("control write: {e:?}"))?;
        Ok(())
    };

    // Hello: version + pairing token; TOFU for unknown peers.
    match next_msg(&mut ctl_buf).await? {
        proto::Client::Hello {
            version,
            pairing_token,
        } => {
            if version != proto::CONTROL_VERSION {
                send_msg(&proto::Proxy::Error {
                    message: format!("control v{version} unsupported"),
                })
                .await?;
                bail!("client speaks control v{version}");
            }
            if !known_peer {
                if pairing_token != token {
                    // Silent rejection: no prompt fatigue for spam.
                    bail!("unknown peer with bad token (silently rejected)");
                }
                if !prompt_accept(peer_hex).await? {
                    send_msg(&proto::Proxy::Error {
                        message: "operator declined".into(),
                    })
                    .await?;
                    bail!("operator declined peer");
                }
                KNOWN_ADD.with(|f| f.borrow_mut()(peer_hex));
            }
        }
        other => bail!("expected Hello, got {other:?}"),
    }
    send_msg(&proto::Proxy::HelloAck {
        version: proto::CONTROL_VERSION,
    })
    .await?;

    // NewSession → spawn mosh-server, deliver the key.
    let (cols, rows) = match next_msg(&mut ctl_buf).await? {
        proto::Client::NewSession { cols, rows } => (cols, rows),
        other => bail!("expected NewSession, got {other:?}"),
    };
    let _ = (cols, rows); // client resizes over SSP; size here is advisory
    let session = MoshSession::spawn()?;
    println!(
        "[conn {session_id}] {peer_hex}: mosh-server on 127.0.0.1:{} (pid {:?})",
        session.port, session.pid
    );
    send_msg(&proto::Proxy::SessionReady {
        session_id,
        key: session.key.clone(),
    })
    .await?;

    // Datagram pumps with tunnel framing.
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    udp.connect(("127.0.0.1", session.port)).await?;
    let udp = Arc::new(udp);

    let max_size = conn_res
        .call_max_datagram_size(accessor, conn)
        .await?
        .context("peer accepts no datagrams")? as usize;

    let mut fragmented = 0u64;
    let mut forwarded_in = 0u64;
    let mut forwarded_out = 0u64;

    // conn → UDP (defragment)
    let inbound = async {
        let mut defrag = proto::Defragmenter::default();
        loop {
            match conn_res.call_recv_datagram(accessor, conn).await {
                Ok(Ok(datagram)) => {
                    if let Some(payload) = defrag.push(&datagram) {
                        forwarded_in += 1;
                        let _ = udp.send(&payload).await;
                    }
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }
        anyhow::Ok(())
    };

    // UDP → conn (fragment as needed)
    let udp2 = udp.clone();
    let outbound = async {
        let mut next_id = 0u8;
        let mut buf = vec![0u8; 2048];
        loop {
            let n = match udp2.recv(&mut buf).await {
                Ok(n) => n,
                Err(_) => break,
            };
            match proto::frame(&buf[..n], max_size, &mut next_id) {
                Ok(frames) => {
                    if frames.len() > 1 {
                        fragmented += 1;
                    }
                    for frame in frames {
                        forwarded_out += 1;
                        if conn_res
                            .call_send_datagram(accessor, conn, frame)
                            .await
                            .map(|r| r.is_err())
                            .unwrap_or(true)
                        {
                            // Lossy transport: only hard errors break.
                        }
                    }
                }
                Err(e) => eprintln!("[conn {session_id}] frame: {e}"),
            }
        }
        anyhow::Ok(())
    };

    // Run until the connection dies (either pump ends) — the control
    // stream idles for now (M6 ceremonies ride it later).
    futures::pin_mut!(inbound, outbound);
    let _ = futures::future::select(inbound, outbound).await;

    Ok(format!(
        "session closed (in={forwarded_in} out={forwarded_out} fragmented={fragmented})"
    ))
}

/// Operator TOFU prompt (auto-accepted under --yes, which is read from
/// the environment by main and baked in here via thread-local — see
/// PROMPT_AUTO).
async fn prompt_accept(peer_hex: &str) -> Result<bool> {
    if PROMPT_AUTO.with(|c| c.get()) {
        println!("TOFU: auto-accepting {peer_hex} (--yes)");
        return Ok(true);
    }
    println!("TOFU: unknown client {peer_hex} presented a valid pairing token.");
    print!("accept? [y/N] ");
    std::io::stdout().flush()?;
    let line = tokio::task::spawn_blocking(|| {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).map(|_| s)
    })
    .await??;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

thread_local! {
    static PROMPT_AUTO: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static KNOWN_ADD: std::cell::RefCell<Box<dyn FnMut(&str)>> =
        std::cell::RefCell::new(Box::new(|_| {}));
}
