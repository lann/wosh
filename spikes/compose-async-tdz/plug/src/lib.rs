//! tdz:plug — exports `maker` (async factory returning own<widget>).

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "plug-world",
    });
}

use bindings::exports::tdz::plug::maker::{Guest, GuestWidget, Widget};

struct WidgetRes(u32);

impl GuestWidget for WidgetRes {
    fn poke(&self) -> u32 {
        self.0
    }
}

struct Component;

impl Guest for Component {
    type Widget = WidgetRes;

    async fn make() -> Result<Widget, String> {
        Ok(Widget::new(WidgetRes(42)))
    }
}

bindings::export!(Component with_types_in bindings);
