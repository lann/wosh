//! The native host shell for `irsh-listener-core`.
//!
//! The composed listener component (`irsh-listener-core` wac-plugged
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

use std::path::PathBuf;

use anyhow::Result;
use polymorph_webcrypto_wasmtime::{WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
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

/// Every argument except a leading `--component <path>` (this host's
/// only own flag) passes straight through to the guest's `argv` --
/// `--relay`, `--target`, `--token`, `--qr-base`, etc. are all parsed
/// inside `irsh-listener-core`, not here.
fn parse_host_args() -> (PathBuf, Vec<String>) {
    let default_component =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/components/irsh-listener.wasm");
    let mut component = default_component;
    let mut guest_args = vec!["irsh-listener".to_string()];

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--component" {
            if let Some(path) = args.next() {
                component = PathBuf::from(path);
            }
        } else {
            guest_args.push(a);
        }
    }
    (component, guest_args)
}

#[tokio::main]
async fn main() -> Result<()> {
    let (component_path, guest_args) = parse_host_args();

    let mut config = Config::new();
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_file(&engine, &component_path)
        .map_err(|e| anyhow::anyhow!("loading {}: {e}", component_path.display()))?;

    let mut linker: Linker<Ctx> = Linker::new(&engine);
    // p2 serves what Rust's std itself imports (stdio, env, exit --
    // all still @0.2.x even in a 0.3 component); p3 serves the 0.3
    // surface, including the sockets the TCP proxy leg uses. The
    // guest imports `wasi:sockets/types@0.3.1` while wasmtime
    // implements `@0.3.0`: those share the `@0.3` compatibility track
    // (major 0 => minor is the track), which is exactly what
    // wasmtime's linker name resolution is built to bridge.
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi::p3::add_to_linker(&mut linker)?;
    webrtc_host::add_to_linker(&mut linker)?;
    polymorph_webcrypto_wasmtime::add_to_linker(&mut linker)?;
    wasmtime_websocket::add_to_linker(&mut linker)?;

    let mut wasi = WasiCtx::builder();
    wasi.inherit_stdio().inherit_env().inherit_network().args(&guest_args);
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
