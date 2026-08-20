//! The native host shell for `wosh-listener-core`.
//!
//! The composed listener component (`wosh-listener-core` wac-plugged
//! with the polymorph-iroh endpoint component) needs three non-WASI
//! imports the endpoint pulls in regardless of which transport paths
//! are actually enabled: `polymorph:webcrypto` (Ed25519 identity
//! signing), `polymorph:websocket` (the relay connection), and
//! `polymorph:webrtc-datachannels` (answering browser peers' WebRTC
//! upgrade signaling). This binary supplies their native
//! (wasmtime-hosted) implementations plus stock WASI, then runs the
//! component as a normal `wasi:cli` command -- all of this project's
//! actual application logic (arg parsing, QR/connstring printing, the
//! accept loop, the TCP bridge) lives in the portable guest, not here.
//!
//! wasmtime-47 bindgen conventions (mirrors wosh's own proxy shell):
//! `wasmtime_wasi::p2::bindings::Command` is the pre-generated
//! `wasi:cli/command` world wrapper -- `Command::instantiate_async`
//! plus `.wasi_cli_run().call_run(&mut store)` runs any command
//! component without hand-written bindgen for the standard world.

use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;

use anyhow::Result;
use polymorph_webcrypto_wasmtime::{WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxView, WasiView};
use wasmtime_webrtc_datachannels::{self as webrtc_host, WebrtcCtx, WebrtcCtxView, WebrtcView};
use wasmtime_websocket::{WasiWebsocketCtx, WasiWebsocketCtxView, WasiWebsocketView};

mod bindings {
    // Hand-rolled because wasmtime-wasi 47 ships no `Command`
    // equivalent for p3 (its `p2::bindings::Command` only knows the
    // synchronous 0.2 `run`). All we need is the one async export.
    wasmtime::component::bindgen!({
        path: "wit",
        world: "composed-listener",
        imports: { default: async | store | trappable },
        exports: { default: async },
    });
}

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

/// Every argument except a leading `--component <path>` and
/// `--identity-dir <path>` (this host's only own flags) passes straight
/// through to the guest's `argv` -- `--relay`, `--target`, `--token`,
/// `--qr-base`, etc. are all parsed inside `wosh-listener-core`, not
/// here.
fn parse_host_args() -> (PathBuf, Option<PathBuf>, Vec<String>) {
    let default_component =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/components/wosh-listener.wasm");
    let mut component = default_component;
    let mut identity_dir = None;
    let mut guest_args = vec!["wosh-listener".to_string()];

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--component" {
            if let Some(path) = args.next() {
                component = PathBuf::from(path);
            }
        } else if a == "--identity-dir" {
            if let Some(path) = args.next() {
                identity_dir = Some(PathBuf::from(path));
            }
        } else {
            guest_args.push(a);
        }
    }
    (component, identity_dir, guest_args)
}

/// Where the listener's persistent identity lives:
/// `--identity-dir`, else `$XDG_DATA_HOME/wosh`, else
/// `~/.local/share/wosh` (the XDG data-dir fallback).
fn resolve_identity_dir(flag: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = flag {
        return Ok(dir);
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg).join("wosh"));
    }
    let home = std::env::var_os("HOME").filter(|v| !v.is_empty()).ok_or_else(|| {
        anyhow::anyhow!(
            "cannot resolve an identity dir: neither XDG_DATA_HOME nor HOME is set; \
             pass --identity-dir <path> (host flag) or --ephemeral-identity"
        )
    })?;
    Ok(PathBuf::from(home).join(".local/share/wosh"))
}

/// The largest known_hosts we will pass through. A wasi env var is
/// not a stream, and a very large one is a startup cost paid on every
/// run for a file that is almost certainly not what it looks like.
const KNOWN_HOSTS_LIMIT: usize = 1024 * 1024;

/// Collect the operator's known_hosts: the personal file first, then
/// the system-wide one, concatenated. Missing files are simply not
/// there.
///
/// Over the limit, this passes NOTHING and says so. Truncating would
/// be far worse than skipping: a cut-off file turns an entry the
/// listener would have REFUSED on into a host it has never heard of,
/// which is precisely the silent downgrade the host-key check exists
/// to prevent. Refusing to check at all is at least visible.
fn read_known_hosts() -> Result<Option<String>, String> {
    let mut text = String::new();
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        paths.push(PathBuf::from(home).join(".ssh/known_hosts"));
    }
    paths.push(PathBuf::from("/etc/ssh/ssh_known_hosts"));

    for path in &paths {
        if let Ok(contents) = std::fs::read_to_string(path) {
            text.push_str(&contents);
            if !text.ends_with('\n') {
                text.push('\n');
            }
        }
    }
    if text.is_empty() {
        return Ok(None);
    }
    if text.len() > KNOWN_HOSTS_LIMIT {
        return Err(format!(
            "known_hosts is {} bytes, over the {KNOWN_HOSTS_LIMIT}-byte limit -- \
             the listener's SSH host-key check was SKIPPED for this run (a truncated \
             known_hosts could turn a key mismatch into an unrecognised host, so \
             nothing was passed rather than part of it)",
            text.len()
        ));
    }
    Ok(Some(text))
}

#[tokio::main]
async fn main() -> Result<()> {
    let (component_path, identity_dir_flag, guest_args) = parse_host_args();

    let mut config = Config::new();
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_file(&engine, &component_path)
        .map_err(|e| anyhow::anyhow!("loading {}: {e}", component_path.display()))?;

    let mut linker: Linker<Ctx> = Linker::new(&engine);
    // p2 serves what Rust's std itself imports (stdio, env, exit,
    // filesystem -- all still @0.2.x even in a 0.3 component); p3
    // serves the 0.3 surface, including the sockets the TCP proxy leg
    // uses. The guest imports `wasi:sockets/types@0.3.1` while
    // wasmtime implements `@0.3.0`: those share the `@0.3`
    // compatibility track (major 0 => minor is the track), which is
    // exactly what wasmtime's linker name resolution is built to
    // bridge.
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi::p3::add_to_linker(&mut linker)?;
    webrtc_host::add_to_linker(&mut linker)?;
    polymorph_webcrypto_wasmtime::add_to_linker(&mut linker)?;
    wasmtime_websocket::add_to_linker(&mut linker)?;

    let mut wasi = WasiCtx::builder();
    wasi.inherit_stdio().inherit_env().inherit_network().args(&guest_args);

    // The operator's known_hosts, handed to the guest as CONTENT.
    //
    // Not as a preopened `~/.ssh`: that directory also holds private
    // keys, and this project's posture is that the component graph
    // never gets a handle to key material. A component that can read
    // known_hosts is a component that can check a fingerprint; a
    // component that can read the directory it lives in is one that
    // could exfiltrate an identity. Reading the file here, in native
    // code the operator already trusts with their whole session, is
    // the difference.
    match read_known_hosts() {
        Ok(Some(text)) => {
            wasi.env("WOSH_KNOWN_HOSTS", &text);
        }
        Ok(None) => {}
        Err(e) => eprintln!("{e}"),
    }

    // The guest's persistent identity lives under a `wosh-data`
    // preopen. Skipped entirely in ephemeral mode (that flag is the
    // guest's, but it is peeked at here so `--ephemeral-identity`
    // leaves no directory behind).
    let mut _identity_lock = None;
    if !guest_args.iter().any(|a| a == "--ephemeral-identity") {
        let dir = resolve_identity_dir(identity_dir_flag)?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700) // holds a private key
            .create(&dir)
            .map_err(|e| anyhow::anyhow!("creating {}: {e}", dir.display()))?;
        // Exactly ONE listener per identity, enforced with an advisory
        // lock held for this process's lifetime. Twins are not a
        // liveness problem but a ROUTING one: both register the same
        // endpoint id, the relay sends every dial to whichever
        // (re)registered last, and clients flap between a listener
        // that knows their enrollment and one that does not --
        // observed as "reconnect is inconsistent", with three
        // forgotten listeners sharing one identity dir.
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("lock"))
            .map_err(|e| anyhow::anyhow!("opening {}/lock: {e}", dir.display()))?;
        rustix::fs::flock(
            &lock,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|_| {
            anyhow::anyhow!(
                "another wosh-listener is already running with the identity in {} -- \
                 two listeners on one identity fight over the relay registration and \
                 clients flap between them. Stop the other one, or give this one its \
                 own --identity-dir (or --ephemeral-identity)",
                dir.display()
            )
        })?;
        _identity_lock = Some(lock);
        wasi.preopened_dir(&dir, "wosh-data", DirPerms::all(), FilePerms::all())
            .map_err(|e| anyhow::anyhow!("mounting {}: {e}", dir.display()))?;
        // The guest can only name its mount ("wosh-data/…"), which
        // exists nowhere on the operator's disk; say where that really
        // is, once. stderr: stdout carries the connstring contract.
        eprintln!("identity dir: {}", dir.display());
    }

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

    let listener =
        bindings::ComposedListener::instantiate_async(&mut store, &component, &linker).await?;

    // `run` is async-lifted (WASI 0.3.1), so it is driven through the
    // store's concurrent event loop rather than a plain call: that is
    // precisely what lets the guest suspend across the relay
    // handshake and then park forever in its accept loop.
    let result = store
        .run_concurrent(async move |accessor| listener.wasi_cli_run().call_run(accessor).await)
        .await??;

    match result {
        Ok(()) => Ok(()),
        Err(()) => std::process::exit(1),
    }
}
