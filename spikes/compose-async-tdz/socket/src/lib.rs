//! tdz:socket — async export calling the imported async factory.

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "socket-world",
        generate_all,
    });
}

use bindings::exports::tdz::socket::driver::Guest;
use bindings::exports::tdz::socket::handoff::Guest as HandoffGuest;
use bindings::tdz::plug::maker::{make, Widget};

struct Component;

impl Guest for Component {
    async fn run() -> Result<u32, String> {
        let widget = make().await?;
        Ok(widget.poke())
    }
}

impl HandoffGuest for Component {
    async fn accept(w: Widget) -> u32 {
        w.poke()
    }
}

bindings::export!(Component with_types_in bindings);
