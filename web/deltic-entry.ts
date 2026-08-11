// The browser bundle entry: everything the page needs to host wosh's
// components under deltic, bundled to web/dist/deltic.js by
// `just web-bundle` (deno bundle --platform browser). The page imports
// that bundle; nothing here is served raw.
//
// Two loaders, one per artifact:
//  - loadEngine: the bare mosh engine (M2 dev-bridge mode) — WASI shims only.
//  - loadClient: the composed client (engine + glue + endpoint, M5 iroh
//    mode) — WASI shims + the polymorph deltic host modules. In-browser
//    the websocket/webcrypto modules ride the native platform APIs and
//    the webrtc module uses stock RTCPeerConnection; wasi:sockets is the
//    fail-on-call browser profile (no UDP in a page).
//
// MODULE-IDENTITY: the bundle carries exactly one copy of
// @deltic/runtime/embedder, so `instanceof WitError` holds throughout.

import { Translator } from "@deltic/runtime/shim";
import { instantiate, WitError } from "@deltic/runtime/embedder";
import { wasiShims } from "@deltic/wasi-shims";
import { webcryptoImports } from "@polymorph/webcrypto-deltic";
import { websocketImports } from "@polymorph/websocket-deltic";
import { webrtcImports } from "@polymorph/webrtc-deltic";
import { socketsImports } from "@polymorph/iroh-sockets-stubs";

export { WitError };

export const ENGINE_INTERFACE = "experiment:mosh/engine";
export const CLIENT_INTERFACE = "experiment:mosh-client/client";

async function fetchBytes(url: string): Promise<Uint8Array> {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`GET ${url}: ${resp.status} ${resp.statusText}`);
  return new Uint8Array(await resp.arrayBuffer());
}

let translator: Translator | undefined;

async function translate(wasmUrl: string, translatorUrl: string) {
  if (!translator) {
    translator = await Translator.create(await fetchBytes(translatorUrl));
  }
  const componentBytes = await fetchBytes(wasmUrl);
  const { plan, adapters } = translator.translate(componentBytes);
  return { plan, componentBytes, adapters };
}

function shims(label: string, env: Record<string, string> = {}) {
  return wasiShims({ cli: { args: [label], env } });
}

/** The engine component's `experiment:mosh/engine` surface. */
// deno-lint-ignore no-explicit-any
export async function loadEngine(
  wasmUrl: string,
  translatorUrl: string,
  // deno-lint-ignore no-explicit-any
): Promise<any> {
  const artifacts = await translate(wasmUrl, translatorUrl);
  const instance = await instantiate(artifacts, { ...shims("wosh-engine") });
  const api = instance.exports[ENGINE_INTERFACE];
  if (!api) throw new Error(`component exports no ${ENGINE_INTERFACE}`);
  return api;
}

/** The composed client's `experiment:mosh-client/client` surface. */
export async function loadClient(
  wasmUrl: string,
  translatorUrl: string,
  // deno-lint-ignore no-explicit-any
): Promise<any> {
  const artifacts = await translate(wasmUrl, translatorUrl);
  const imports = {
    // WOSH_UDP=off: the browser has no UDP; the glue must not ask the
    // endpoint to bind a socket (the wasi:sockets providers here are
    // fail-on-call stubs). Paths are relay + WebRTC.
    ...shims("wosh-client", { WOSH_UDP: "off" }),
    ...webcryptoImports(),
    ...websocketImports(),
    ...webrtcImports(),
    ...socketsImports(),
  };
  const instance = await instantiate(artifacts, imports);
  const api = instance.exports[CLIENT_INTERFACE];
  if (!api) throw new Error(`component exports no ${CLIENT_INTERFACE}`);
  return api;
}
