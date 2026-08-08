//! The experiment-mosh proxy (M4, workstream C): a thin native shell
//! around the composed proxy-core component.
//!
//! Architecture (D1 + D9): the proxy's brain — accept loop, control
//! channel, TOFU flow, datagram tunnel with sub-framing — lives in
//! `proxy-core` (a wasm component, fused with the polymorph-iroh
//! endpoint component by wac). This binary provides exactly the OS
//! surface the component imports: spawn/reap `mosh-server -i
//! 127.0.0.1` (interim mode, D2 — the proxy runs as the target
//! user), the operator TOFU prompt, TOFU persistence, and logging —
//! plus bootstrap UX: the connection string and its QR code.

use std::collections::HashSet;
use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{anyhow, Context as _, Result};
use polymorph_webcrypto_wasmtime::{WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView};
use rand::Rng;
use wasmtime::component::{Component, HasData, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_webrtc_datachannels::{
    self as webrtc_host, WasiWebrtcCtx, WasiWebrtcCtxView, WasiWebrtcView,
};
use wasmtime_websocket::{WasiWebsocketCtx, WasiWebsocketCtxView, WasiWebsocketView};

mod bindings {
    wasmtime::component::bindgen!({
        path: "../proxy-core/wit",
        world: "composed-proxy",
        imports: {
            default: async | store | trappable,
        },
        exports: {
            default: async,
        },
    });
}

use bindings::experiment::mosh_proxy::host::{Host, SessionInfo};

struct Cli {
    relay: String,
    state_dir: PathBuf,
    qr_base: String,
    component: PathBuf,
    token: Option<String>,
    yes: bool,
    no_qr: bool,
    shell: Option<String>,
}

fn usage() -> anyhow::Error {
    anyhow!(
        "usage: experiment-mosh-proxy --relay <url> [--state-dir <dir>] \
         [--qr-base <url>] [--component <composed-proxy.wasm>] \
         [--token <pairing-token>] [--yes] [--no-qr] [--shell <cmd…>]"
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
    let mut shell = None;
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
            "--shell" => shell = Some(value()?),
            _ => return Err(usage()),
        }
    }
    let state_dir = state_dir.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".local/state/experiment-mosh-proxy")
    });
    let component = component.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("composed-proxy.wasm")
    });
    Ok(Cli {
        relay: relay.ok_or_else(usage)?,
        state_dir,
        qr_base: qr_base.unwrap_or_else(|| "https://experiment-mosh.invalid/#".into()),
        component,
        token,
        yes,
        no_qr,
        shell,
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
    /// `shell`: whitespace-split command appended after `--` (tests
    /// pin `bash --noprofile --norc -i`); none ⇒ the user's shell.
    fn spawn(shell: Option<&str>) -> Result<Self> {
        let mut args: Vec<String> = ["new", "-i", "127.0.0.1", "-c", "256"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        if let Some(shell) = shell {
            args.push("--".into());
            args.extend(shell.split_whitespace().map(|s| s.to_string()));
        }
        let out = std::process::Command::new("mosh-server")
            .args(&args)
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

    fn kill(&self) {
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

/// Host state behind the component's `host` import.
struct Ctx {
    wasi: WasiCtx,
    webrtc: WasiWebrtcCtx,
    webcrypto: WasiWebcryptoCtx,
    websocket: WasiWebsocketCtx,
    table: ResourceTable,
    known: KnownClients,
    sessions: Vec<MoshSession>,
    pairing_token: String,
    auto_accept: bool,
    shell: Option<String>,
}

impl Drop for Ctx {
    fn drop(&mut self) {
        for s in &self.sessions {
            s.kill();
        }
    }
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

impl bindings::experiment::mosh_proxy::host::Host for &mut Ctx {}

impl bindings::experiment::mosh_proxy::host::HostWithStore<Ctx> for Ctx {
    async fn authorize(
        accessor: &wasmtime::component::Accessor<Ctx, Self>,
        peer_id_hex: String,
        pairing_token: String,
    ) -> wasmtime::Result<bool> {
        let (known, token_ok, auto) = accessor.with(|mut a| {
            let ctx = a.get();
            (
                ctx.known.contains(&peer_id_hex),
                pairing_token == ctx.pairing_token,
                ctx.auto_accept,
            )
        });
        if known {
            return Ok(true);
        }
        if !token_ok {
            println!("refused unknown peer {peer_id_hex} (bad pairing token)");
            return Ok(false);
        }
        let accept = if auto {
            println!("TOFU: auto-accepting {peer_id_hex} (--yes)");
            true
        } else {
            println!("TOFU: unknown client {peer_id_hex} presented a valid pairing token.");
            print!("accept? [y/N] ");
            std::io::stdout().flush()?;
            let line = tokio::task::spawn_blocking(|| {
                let mut s = String::new();
                std::io::stdin().read_line(&mut s).map(|_| s)
            })
            .await??;
            matches!(line.trim(), "y" | "Y" | "yes")
        };
        if accept {
            accessor
                .with(|mut a| a.get().known.add(&peer_id_hex))
                .map_err(|e| wasmtime::Error::msg(format!("{e:#}")))?;
        }
        Ok(accept)
    }

    async fn new_session(
        accessor: &wasmtime::component::Accessor<Ctx, Self>,
    ) -> wasmtime::Result<Result<SessionInfo, String>> {
        let shell = accessor.with(|mut a| a.get().shell.clone());
        match MoshSession::spawn(shell.as_deref()) {
            Ok(s) => {
                let info = SessionInfo {
                    key: s.key.clone(),
                    udp_port: s.port,
                };
                accessor.with(|mut a| a.get().sessions.push(s));
                Ok(Ok(info))
            }
            Err(e) => Ok(Err(format!("{e:#}"))),
        }
    }

    async fn end_session(
        mut access: wasmtime::component::Access<'_, Ctx, Self>,
        udp_port: u16,
    ) -> wasmtime::Result<()> {
        access.get().sessions.retain(|s| {
            if s.port == udp_port {
                s.kill();
                false
            } else {
                true
            }
        });
        Ok(())
    }

    async fn log(
        _access: wasmtime::component::Access<'_, Ctx, Self>,
        message: String,
    ) -> wasmtime::Result<()> {
        println!("{message}");
        Ok(())
    }
}


#[tokio::main]
async fn main() -> Result<()> {
    let _ = env_logger::try_init();
    let cli = parse_args()?;
    let token = cli.token.clone().unwrap_or_else(random_token);
    let known = KnownClients::load(&cli.state_dir)?;

    let mut config = Config::new();
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_file(&engine, &cli.component)
        .map_err(|e| anyhow!("loading {}: {e}", cli.component.display()))?;
    let mut linker: Linker<Ctx> = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi::p3::add_to_linker(&mut linker)?;
    webrtc_host::add_to_linker(&mut linker)?;
    polymorph_webcrypto_wasmtime::add_to_linker(&mut linker)?;
    wasmtime_websocket::add_to_linker(&mut linker)?;
    bindings::ComposedProxy::add_to_linker::<Ctx, Ctx>(&mut linker, |ctx| ctx)?;

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
            known,
            sessions: Vec::new(),
            pairing_token: token.clone(),
            auto_accept: cli.yes,
            shell: cli.shell.clone(),
        },
    );
    let proxy = bindings::ComposedProxy::instantiate_async(&mut store, &component, &linker).await?;

    let relay = cli.relay.clone();
    store
        .run_concurrent(async move |accessor| -> Result<()> {
            let started = proxy
                .experiment_mosh_proxy_proxy()
                .call_start(accessor, relay.clone())
                .await?
                .map_err(|e| anyhow!("proxy start: {e}"))?;

            let connstring = format!("1.{}.{token}.{relay}", started.endpoint_id_hex);
            println!("connstring: {connstring}");
            if let Some(direct) = &started.direct_addr {
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

            // Park forever; the store keeps driving the component's
            // accept/session tasks. Ctrl-C exits (sessions reaped by
            // Ctx::drop via process teardown).
            std::future::pending::<()>().await;
            Ok(())
        })
        .await??;

    Ok(())
}
