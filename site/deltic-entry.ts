// The browser bundle entry: everything the page needs to host the wosh
// SSH client component under deltic. Bundled to site/dist/deltic.js by
// `just web-bundle` (deno bundle --platform browser); the page imports
// that bundle and nothing here is served raw.
//
// deltic is a runtime linker: it takes the component binary, translates
// it in-process, and runs it on the stock WebAssembly API. There is no
// transpile step and no generated tree -- the .wasm that the native
// gates run is byte-for-byte the .wasm the browser runs.
//
// The composed client imports three non-WASI interfaces that the iroh
// endpoint needs, and in a browser each rides a native platform API:
// webcrypto over Web Crypto, websocket over WebSocket (the relay), and
// webrtc over RTCPeerConnection (the direct-path upgrade). wasi:sockets
// is the fail-on-call browser profile -- a page has no UDP -- which is
// safe here only because the client never asks the endpoint to bind
// one (see ssh-client-core: it deliberately sets no udp-bind-addr).
//
// MODULE IDENTITY: the bundle must carry exactly one copy of
// @deltic/runtime/embedder, or `instanceof WitError` stops holding
// across module boundaries and real errors surface as unbranded
// throws. deno.json's import map is what guarantees that.

import { Translator } from "@deltic/runtime/shim";
import { instantiate, WitError } from "@deltic/runtime/embedder";
import { wasiShims } from "@deltic/wasi-shims";
import { webcryptoImports } from "@polymorph/webcrypto-deltic";
import { websocketImports } from "@polymorph/websocket-deltic";
import { webrtcImports } from "@polymorph/webrtc-deltic";
import { socketsImports } from "@polymorph/iroh-sockets-stubs";

export { WitError };

/** The interface the client component exports; see wit/terminal.wit. */
export const TERMINAL_INTERFACE = "wosh:terminal/terminal";

async function fetchBytes(url: string): Promise<Uint8Array> {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`GET ${url}: ${resp.status} ${resp.statusText}`);
  return new Uint8Array(await resp.arrayBuffer());
}

let translator: Translator | undefined;

async function translate(wasmUrl: string, translatorUrl: string) {
  // One translator serves every component; translation itself is
  // sub-millisecond warm.
  if (!translator) {
    translator = await Translator.create(await fetchBytes(translatorUrl));
  }
  const componentBytes = await fetchBytes(wasmUrl);
  const { plan, adapters } = translator.translate(componentBytes);
  return { plan, componentBytes, adapters };
}

/**
 * Instantiate the composed SSH client and hand back its
 * `wosh:terminal/terminal` surface.
 *
 * Every export is Promise-shaped under deltic, including the ones the
 * WIT declares as plain functions.
 */
// deno-lint-ignore no-explicit-any
export async function loadClient(wasmUrl: string, translatorUrl: string): Promise<any> {
  const artifacts = await translate(wasmUrl, translatorUrl);
  const imports = {
    ...wasiShims({ cli: { args: ["wosh-client"], env: {} } }),
    ...webcryptoImports(),
    ...websocketImports(),
    ...webrtcImports(),
    ...socketsImports(),
  };
  const instance = await instantiate(artifacts, imports);
  const api = instance.exports[TERMINAL_INTERFACE];
  if (!api) throw new Error(`component exports no ${TERMINAL_INTERFACE}`);
  return api;
}
