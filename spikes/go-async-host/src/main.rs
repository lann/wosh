//! Driver for the componentize-go async probes.
//!
//! Three measurements, run against one instance:
//!
//! 1. sync-lifted vs async-lifted exports calling the same async
//!    import (`--probe lifting`);
//! 2. a goroutine parked in one export call, resumed by a later one
//!    (`--probe parking`);
//! 3. whether a never-returning "keepalive" export lets a background
//!    goroutine keep doing async imports while NO export call is
//!    active (`--probe keepalive`).
//!
//! (2) and (3) need several calls on one instance -- and (3) needs two
//! calls genuinely in flight at once -- which `wasmtime --invoke`
//! cannot express, since it runs a single export per process. Hence
//! this host.

use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

mod bindings {
    wasmtime::component::bindgen!({
        path: "../go-async/wit",
        world: "spike",
        imports: { default: async | store | trappable },
        exports: { default: async },
    });
}

struct Ctx {
    wasi: WasiCtx,
    table: ResourceTable,
}

impl WasiView for Ctx {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.wasi, table: &mut self.table }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let component_path = args.next().unwrap_or_else(|| "../go-async/main.wasm".into());
    let probe = args.next().unwrap_or_else(|| "all".into());

    let mut config = Config::new();
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_file(&engine, &component_path)?;
    let mut linker: Linker<Ctx> = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi::p3::add_to_linker(&mut linker)?;
    let mut wasi = WasiCtx::builder();
    wasi.inherit_stdio();
    let mut store = Store::new(&engine, Ctx { wasi: wasi.build(), table: ResourceTable::new() });
    let spike = bindings::Spike::instantiate_async(&mut store, &component, &linker).await?;

    let probe_for_msg = probe.clone();
    store
        .run_concurrent(async move |acc| -> Result<()> {
            let p = spike.spike_goasync_probe();

            if probe == "parking" || probe == "all" {
                // (2) Two SEPARATE export calls; the goroutine parked
                // by the first is resumed by the second.
                p.call_park(acc).await?;
                let out = p.call_release(acc, 7).await?;
                println!("[parking]  {out}");
                if !out.contains("resumed across export calls") {
                    bail!("goroutine did not survive across export calls");
                }
            }

            if probe == "keepalive" || probe == "all" {
                // (3) Start a task that never returns, and never await
                // it to completion. Then measure whether background
                // goroutine I/O progresses with no other call active.
                let keepalive = p.call_keepalive(acc);
                let measure = async {
                    p.call_start_bg(acc).await?;

                    // Deliberately make ZERO export calls for a while.
                    let quiet = Instant::now();
                    while quiet.elapsed() < Duration::from_millis(600) {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    let after_quiet = p.call_bg_count(acc).await?;
                    println!("[keepalive] after 600ms with ZERO export calls: bg-count = {after_quiet}");

                    let mut last = after_quiet;
                    for _ in 0..40 {
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        last = p.call_bg_count(acc).await?;
                        if last >= 20 {
                            break;
                        }
                    }
                    println!("[keepalive] after active polling:              bg-count = {last}");
                    println!(
                        "[keepalive] VERDICT: {}",
                        if after_quiet >= 15 {
                            "background goroutines RUN under the keepalive task"
                        } else if last > after_quiet {
                            "background goroutines progress ONLY while another export is active"
                        } else {
                            "no background progress at all"
                        }
                    );
                    Ok::<(), anyhow::Error>(())
                };

                futures::pin_mut!(keepalive, measure);
                match futures::future::select(keepalive, measure).await {
                    futures::future::Either::Left((r, _)) => {
                        r?;
                        bail!("keepalive returned; it is supposed to run forever");
                    }
                    futures::future::Either::Right((r, _)) => r?,
                }
            }

            Ok(())
        })
        .await??;

    if probe_for_msg == "lifting" || probe_for_msg == "all" {
        println!(
            "\n[lifting] run these two directly; the first is expected to TRAP:\n  \
             wasmtime run -W component-model-async=y --invoke 'sync-calls-async(50)'  {p}\n  \
             wasmtime run -W component-model-async=y --invoke 'async-calls-async(50)' {p}",
            p = component_path
        );
    }
    Ok(())
}
