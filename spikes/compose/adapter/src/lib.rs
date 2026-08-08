//! Composition-spike adapter: a synchronous Rust component that
//! imports the mosh engine's WIT surface and exposes probe exports.
//! `wac plug` fuses it with the componentize-go engine component; the
//! runners then drive the fused component under wasmtime, node, and
//! headless Chromium. See wit/world.wit for what each probe covers.

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "adapter",
        generate_all,
    });
}

use bindings::experiment::mosh::engine::{self, Session};
use bindings::exports::experiment::compose_spike::driver::{Guest, RoundTripReport};

struct Component;

impl Guest for Component {
    fn version_via_engine() -> String {
        engine::version()
    }

    fn session_round_trip(key: String, cols: u16, rows: u16) -> Result<RoundTripReport, String> {
        let session = Session::connect(&key, cols, rows)?;
        session.feed_keys(b"date\r");
        let datagrams = session.tick();
        let output = session.drain_output();
        let stats = session.stats();
        Ok(RoundTripReport {
            datagrams: datagrams.len() as u32,
            first_datagram_len: datagrams.first().map_or(0, |d| d.len() as u32),
            sent_num: stats.sent_num,
            output_len: output.len() as u32,
        })
        // `session` drops here: resource-drop across the composed boundary.
    }
}

bindings::export!(Component with_types_in bindings);
