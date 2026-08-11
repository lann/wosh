//! The wosh proxy (M4/M6, workstream C): a thin native
//! shell around the composed proxy-core component.
//!
//! Architecture (D1 + D9): the proxy's brain — accept loop, control
//! channel, TOFU flow, datagram tunnel with sub-framing, ceremony
//! routing — lives in `proxy-core` (a wasm component, fused with the
//! polymorph-iroh endpoint component by wac). This binary provides
//! exactly the OS/RP surface the component imports: spawn/reap
//! `mosh-server -i 127.0.0.1` (interim mode, D2 — the proxy runs as
//! the target user), the operator TOFU prompt, TOFU persistence,
//! logging, the WebAuthn relying party (webauthn-rs, M6), the escrow
//! store, and the session persistence policy — plus bootstrap UX: the
//! connection string and its QR code.
//!
//! wasmtime-47 bindgen conventions (worth keeping): async WIT imports
//! ⇒ `HostWithStore<T>` associated fns taking `&Accessor<Ctx, Self>`
//! with state via `accessor.with(|mut a| a.get()…)`; sync WIT imports
//! ⇒ still `async fn` but taking `Access<'_, Ctx, Self>` directly;
//! plus an empty `impl Host for &mut Ctx`.

use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{anyhow, Context as _, Result};
use polymorph_webcrypto_wasmtime::{WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView};
use rand::Rng;
use wasmtime::component::{Component, HasData, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_webrtc_datachannels::{
    self as webrtc_host, WebrtcCtx, WebrtcCtxView, WebrtcView,
};
use wasmtime_websocket::{WasiWebsocketCtx, WasiWebsocketCtxView, WasiWebsocketView};
use webauthn_rs::prelude::{
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    Url, Uuid, Webauthn, WebauthnBuilder,
};

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

use bindings::experiment::mosh_proxy::host::{CeremonyKind, ReattachInfo, SessionInfo};

struct Cli {
    relay: String,
    state_dir: PathBuf,
    qr_base: String,
    component: PathBuf,
    token: Option<String>,
    yes: bool,
    no_qr: bool,
    shell: Option<String>,
    rp_id: String,
    rp_origin: String,
    /// Personal mode (D2 interim, M7 opt-in): the proxy spawns
    /// mosh-server itself and custodies session keys. Default OFF —
    /// the deprivileged posture, where clients bring their own
    /// mosh-server through the forwarded ssh stream.
    personal: bool,
    /// Where SSH_FORWARD streams connect (loopback enforced: a
    /// forwarded ssh leg must never turn the proxy into an open
    /// relay off-host).
    ssh_target: std::net::SocketAddr,
}

fn usage() -> anyhow::Error {
    anyhow!(
        "usage: wosh-proxy --relay <url> [--state-dir <dir>] \
         [--qr-base <url>] [--component <composed-proxy.wasm>] \
         [--token <pairing-token>] [--yes] [--no-qr] [--personal] \
         [--shell <cmd…>] [--ssh-target <loopback-ip:port>] \
         [--rp-id <domain>] [--rp-origin <url>]"
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
    let mut rp_id = None;
    let mut rp_origin = None;
    let mut personal = false;
    let mut ssh_target = None;
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
            "--rp-id" => rp_id = Some(value()?),
            "--rp-origin" => rp_origin = Some(value()?),
            "--personal" => personal = true,
            "--ssh-target" => ssh_target = Some(value()?),
            _ => return Err(usage()),
        }
    }
    let ssh_target: std::net::SocketAddr = ssh_target
        .unwrap_or_else(|| "127.0.0.1:22".into())
        .parse()
        .context("--ssh-target must be an ip:port")?;
    if !ssh_target.ip().is_loopback() {
        return Err(anyhow!(
            "--ssh-target must be a loopback address, got {ssh_target}"
        ));
    }
    let state_dir = state_dir.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".local/state/wosh-proxy")
    });
    let component = component.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("composed-proxy.wasm")
    });
    Ok(Cli {
        relay: relay.ok_or_else(usage)?,
        state_dir,
        qr_base: qr_base.unwrap_or_else(|| "https://lann.github.io/wosh/#".into()),
        component,
        token,
        yes,
        no_qr,
        shell,
        // The production RP ID is the client site's registrable domain
        // (PLAN: bootstrap/session UX); localhost defaults serve the
        // native harness and local development.
        rp_id: rp_id.unwrap_or_else(|| "localhost".into()),
        rp_origin: rp_origin.unwrap_or_else(|| "http://localhost".into()),
        personal,
        ssh_target,
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
    id: u64,
    port: u16,
    key: String,
    pid: Option<u32>,
    /// Persistent sessions survive connection close (M6): the
    /// mosh-server keeps running and reattach is assertion-gated.
    persistent: bool,
}

impl MoshSession {
    /// `shell`: whitespace-split command appended after `--` (tests
    /// pin `bash --noprofile --norc -i`); none ⇒ the user's shell.
    fn spawn(id: u64, shell: Option<&str>) -> Result<Self> {
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
        Ok(Self {
            id,
            port,
            key,
            pid,
            persistent: false,
        })
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
    webrtc: WebrtcCtx,
    webcrypto: WasiWebcryptoCtx,
    websocket: WasiWebsocketCtx,
    table: ResourceTable,
    known: KnownClients,
    sessions: Vec<MoshSession>,
    next_session_id: u64,
    pairing_token: String,
    auto_accept: bool,
    shell: Option<String>,
    /// Personal mode: proxy-spawned sessions allowed (D2 interim).
    personal: bool,
    // --- the WebAuthn relying party + escrow store (M6) ---
    webauthn: Webauthn,
    reg_states: HashMap<u64, PasskeyRegistration>,
    auth_states: HashMap<u64, PasskeyAuthentication>,
    /// Verified credentials per session (webauthn-rs Passkey, serde).
    passkeys: HashMap<u64, Vec<webauthn_rs::prelude::Passkey>>,
    /// Opaque client-wrapped blobs; returned verbatim on reattach.
    escrows: HashMap<u64, Vec<u8>>,
    state_dir: PathBuf,
}

impl Ctx {
    /// Durable copy of credentials + escrows (state-dir JSON). The
    /// mosh-server processes themselves do not survive a proxy
    /// restart, so this durability serves escrow recovery and future
    /// multi-proxy work, not live-session recovery.
    fn persist_stores(&self) {
        #[derive(serde::Serialize)]
        struct Stores<'a> {
            passkeys: &'a HashMap<u64, Vec<webauthn_rs::prelude::Passkey>>,
            escrows: HashMap<u64, String>,
        }
        let stores = Stores {
            passkeys: &self.passkeys,
            escrows: self
                .escrows
                .iter()
                .map(|(k, v)| (*k, hex::encode(v)))
                .collect(),
        };
        if let Ok(json) = serde_json::to_vec_pretty(&stores) {
            let _ = std::fs::write(self.state_dir.join("passkeys.json"), json);
        }
    }
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
        let (personal, id, shell) = accessor.with(|mut a| {
            let ctx = a.get();
            if !ctx.personal {
                return (false, 0, None);
            }
            ctx.next_session_id += 1;
            (true, ctx.next_session_id, ctx.shell.clone())
        });
        if !personal {
            // Defense in depth: proxy-core already refuses NewSession
            // outside personal mode without calling us.
            return Ok(Err("personal mode disabled".into()));
        }
        match MoshSession::spawn(id, shell.as_deref()) {
            Ok(s) => {
                let info = SessionInfo {
                    session_id: id,
                    key: s.key.clone(),
                    udp_port: s.port,
                };
                accessor.with(|mut a| a.get().sessions.push(s));
                Ok(Ok(info))
            }
            Err(e) => Ok(Err(format!("{e:#}"))),
        }
    }

    async fn register_forward(
        accessor: &wasmtime::component::Accessor<Ctx, Self>,
        udp_port: u16,
    ) -> wasmtime::Result<Result<u64, String>> {
        Ok(accessor.with(|mut a| {
            let ctx = a.get();
            if udp_port == 0 {
                return Err("forward port 0 is not a session".into());
            }
            // One session entry per port: a forwarded session must
            // not alias (and later reap or shadow) an existing one.
            if ctx.sessions.iter().any(|s| s.port == udp_port) {
                return Err(format!("udp:{udp_port} already belongs to a session"));
            }
            ctx.next_session_id += 1;
            let id = ctx.next_session_id;
            // No key (client-managed), no pid (nothing to reap):
            // kill() no-ops on pid None and end_session's retain
            // treats the entry like any other — passkey binding is
            // keyed by session id and works unchanged.
            ctx.sessions.push(MoshSession {
                id,
                port: udp_port,
                key: String::new(),
                pid: None,
                persistent: false,
            });
            println!("session {id}: client-managed mosh-server on udp:{udp_port} (forwarded)");
            Ok(id)
        }))
    }

    async fn webauthn_step(
        accessor: &wasmtime::component::Accessor<Ctx, Self>,
        kind: CeremonyKind,
        session_id: u64,
        payload: Vec<u8>,
    ) -> wasmtime::Result<Result<Vec<u8>, String>> {
        Ok(accessor.with(|mut a| {
            let ctx = a.get();
            webauthn_step_impl(ctx, kind, session_id, &payload)
        }))
    }

    async fn make_persistent(
        accessor: &wasmtime::component::Accessor<Ctx, Self>,
        session_id: u64,
        escrow: Vec<u8>,
    ) -> wasmtime::Result<Result<(), String>> {
        Ok(accessor.with(|mut a| {
            let ctx = a.get();
            if !ctx.passkeys.contains_key(&session_id) {
                return Err("no registered passkey for this session".into());
            }
            let Some(s) = ctx.sessions.iter_mut().find(|s| s.id == session_id) else {
                return Err("no such session".into());
            };
            s.persistent = true;
            ctx.escrows.insert(session_id, escrow);
            ctx.persist_stores();
            println!("session {session_id} is now persistent (passkey-bound)");
            Ok(())
        }))
    }

    async fn reattach(
        accessor: &wasmtime::component::Accessor<Ctx, Self>,
        session_id: u64,
    ) -> wasmtime::Result<Result<ReattachInfo, String>> {
        Ok(accessor.with(|mut a| {
            let ctx = a.get();
            let Some(s) = ctx.sessions.iter().find(|s| s.id == session_id) else {
                return Err("no such session".into());
            };
            if !s.persistent {
                return Err("session is not persistent".into());
            }
            let escrow = ctx
                .escrows
                .get(&session_id)
                .ok_or("no escrow for this session")?
                .clone();
            Ok(ReattachInfo {
                udp_port: s.port,
                escrow,
            })
        }))
    }

    async fn end_session(
        mut access: wasmtime::component::Access<'_, Ctx, Self>,
        udp_port: u16,
    ) -> wasmtime::Result<()> {
        let ctx = access.get();
        ctx.sessions.retain(|s| {
            if s.port == udp_port {
                if s.persistent {
                    println!(
                        "session {} detached; mosh-server on udp:{} kept (persistent)",
                        s.id, s.port
                    );
                    return true;
                }
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

/// The RP state machine, one step per call (payloads are webauthn-rs
/// JSON). User identity is derived from the session id — a session's
/// passkey authorizes reattach to that session, nothing else.
fn webauthn_step_impl(
    ctx: &mut Ctx,
    kind: CeremonyKind,
    session_id: u64,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    match kind {
        CeremonyKind::RegisterStart => {
            if !ctx.sessions.iter().any(|s| s.id == session_id) {
                return Err("no such session".into());
            }
            let user = Uuid::new_v5(&Uuid::NAMESPACE_OID, session_id.to_string().as_bytes());
            let name = format!("session-{session_id}");
            let (ccr, state) = ctx
                .webauthn
                .start_passkey_registration(user, &name, &name, None)
                .map_err(|e| format!("start registration: {e}"))?;
            ctx.reg_states.insert(session_id, state);
            serde_json::to_vec(&ccr).map_err(|e| format!("encode: {e}"))
        }
        CeremonyKind::RegisterFinish => {
            let state = ctx
                .reg_states
                .remove(&session_id)
                .ok_or("no registration in flight")?;
            let cred: RegisterPublicKeyCredential =
                serde_json::from_slice(payload).map_err(|e| format!("decode: {e}"))?;
            let passkey = ctx
                .webauthn
                .finish_passkey_registration(&cred, &state)
                .map_err(|e| format!("registration refused: {e}"))?;
            ctx.passkeys.entry(session_id).or_default().push(passkey);
            ctx.persist_stores();
            println!("session {session_id}: passkey registered");
            Ok(Vec::new())
        }
        CeremonyKind::AuthStart => {
            let passkeys = ctx
                .passkeys
                .get(&session_id)
                .ok_or("no passkey bound to this session")?;
            let (rcr, state) = ctx
                .webauthn
                .start_passkey_authentication(passkeys)
                .map_err(|e| format!("start authentication: {e}"))?;
            ctx.auth_states.insert(session_id, state);
            serde_json::to_vec(&rcr).map_err(|e| format!("encode: {e}"))
        }
        CeremonyKind::AuthFinish => {
            let state = ctx
                .auth_states
                .remove(&session_id)
                .ok_or("no authentication in flight")?;
            let cred: PublicKeyCredential =
                serde_json::from_slice(payload).map_err(|e| format!("decode: {e}"))?;
            ctx.webauthn
                .finish_passkey_authentication(&cred, &state)
                .map_err(|e| format!("assertion refused: {e}"))?;
            println!("session {session_id}: assertion verified");
            Ok(Vec::new())
        }
    }
}

/// Signal orchestration (D2 console UX): the first SIGINT/SIGTERM asks
/// main for a graceful shutdown (reap sessions, exit 0); a second one
/// aborts a graceful shutdown that is taking too long and force-quits
/// with the conventional 128+SIGINT code. This runs as its own tokio
/// task, deliberately OUTSIDE the store's event loop: a `select!`
/// inside the `run_concurrent` closure is documented as unreliable
/// (wasmtime #11869/#11870 — the closure future can go unpolled while
/// the event loop is busy), which is one of the ways ctrl-c used to
/// wedge the console.
async fn watch_signals(shutdown: std::sync::Arc<tokio::sync::Notify>) {
    use tokio::signal::unix::{signal, SignalKind};
    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = int.recv() => {}
        _ = term.recv() => {}
    }
    println!("shutdown signal received (again to force-quit)");
    shutdown.notify_one();
    tokio::select! {
        _ = int.recv() => {}
        _ = term.recv() => {}
    }
    eprintln!("wosh-proxy: force quit; mosh-server sessions may be left running");
    std::process::exit(130);
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = env_logger::try_init();
    let cli = parse_args()?;
    let token = cli.token.clone().unwrap_or_else(random_token);
    let known = KnownClients::load(&cli.state_dir)?;

    let rp_origin = Url::parse(&cli.rp_origin)
        .with_context(|| format!("--rp-origin {}", cli.rp_origin))?;
    let webauthn = WebauthnBuilder::new(&cli.rp_id, &rp_origin)
        .context("webauthn RP")?
        .rp_name("wosh")
        .build()
        .context("webauthn RP")?;

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
            webrtc: WebrtcCtx::new(),
            webcrypto: WasiWebcryptoCtx::new(),
            websocket: WasiWebsocketCtx::new(),
            table: ResourceTable::new(),
            known,
            sessions: Vec::new(),
            next_session_id: 0,
            pairing_token: token.clone(),
            auto_accept: cli.yes,
            shell: cli.shell.clone(),
            personal: cli.personal,
            webauthn,
            reg_states: HashMap::new(),
            auth_states: HashMap::new(),
            passkeys: HashMap::new(),
            escrows: HashMap::new(),
            state_dir: cli.state_dir.clone(),
        },
    );
    let proxy = bindings::ComposedProxy::instantiate_async(&mut store, &component, &linker).await?;

    let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    tokio::spawn(watch_signals(shutdown.clone()));

    let relay = cli.relay.clone();
    let ssh_target = cli.ssh_target.to_string();
    let personal = cli.personal;
    let serve = store.run_concurrent(async move |accessor| -> Result<()> {
        let started = proxy
            .experiment_mosh_proxy_proxy()
            .call_start(accessor, relay.clone(), ssh_target.clone(), personal)
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
        println!(
            "ready; pairing token: {token} ({} mode; ssh-target {})",
            if cli.personal { "personal" } else { "deprivileged" },
            cli.ssh_target
        );

        // Park forever; the store keeps driving the component's
        // accept/session tasks. Shutdown is orchestrated outside
        // `run_concurrent` (see `watch_signals`).
        std::future::pending::<()>().await;
        Ok(())
    });

    enum Exit {
        /// The event loop itself finished — always unexpected (the
        /// serve closure parks forever), so an error even on Ok.
        Loop(wasmtime::Result<Result<()>>),
        Signal,
    }
    let exit = tokio::select! {
        r = serve => Exit::Loop(r),
        _ = shutdown.notified() => Exit::Signal,
    };
    let code = match exit {
        Exit::Loop(r) => {
            match r {
                Ok(Ok(())) => eprintln!("wosh-proxy: event loop exited unexpectedly"),
                Ok(Err(e)) => eprintln!("wosh-proxy: {e:#}"),
                Err(e) => eprintln!("wosh-proxy: {e:#}"),
            }
            1
        }
        Exit::Signal => {
            // Test-only knob (proxy-e2e): simulate a wedged graceful
            // shutdown so the double-SIGINT force-quit path can be
            // exercised deterministically.
            if std::env::var_os("WOSH_PROXY_TEST_WEDGE_SHUTDOWN").is_some() {
                std::future::pending::<()>().await;
            }
            // Reap sessions before exit: persistent sessions
            // deliberately outlive *connections* (M6), never the
            // proxy process — and process teardown without this
            // (SIGKILL, or default signal disposition) never runs
            // Ctx::drop, which would orphan every mosh-server.
            let ctx = store.data_mut();
            for s in &ctx.sessions {
                s.kill();
            }
            let n = ctx.sessions.len();
            ctx.sessions.clear();
            println!("shutting down; reaped {n} session(s)");
            0
        }
    };
    // On the error path Ctx::drop is the reaper.
    drop(store);
    // Explicit exit rather than returning: a pending TOFU prompt
    // (`authorize`) parks a spawn_blocking stdin read that tokio's
    // runtime-drop would join forever — the other historical ctrl-c
    // wedge. process::exit skips that join (stdout is line-buffered;
    // everything above is already flushed).
    std::process::exit(code);
}
