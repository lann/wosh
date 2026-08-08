// Composition spike, node leg: the wac-composed component (Rust
// adapter + componentize-go engine) transpiled by the pinned jco fork,
// driven from JS. Same assertions as the wasmtime and browser legs.
import { driver } from "./generated-compose/compose-probe.js";
import { assertComposeProbe } from "./compose-assertions.mjs";

console.log(`compose spike node leg: ${await assertComposeProbe(driver)}`);
