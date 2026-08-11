// The deltic host layer shared by every Deno-lane driver: translate a
// component once, instantiate it with the WASI shims (+ the polymorph
// deltic host modules for the composed client), and hand back the typed
// export surface.
//
// deltic is a runtime linker (no transpile step, no generated tree): the
// component binary is translated in-process by the pinned translator-shim
// wasm — fetch-translator.ts fetches/caches it and justfile recipes export
// its path as DELTIC_TRANSLATOR.
//
// MODULE-IDENTITY CONSTRAINT: everything here and in the polymorph host
// modules imports @deltic/runtime/embedder through the ROOT deno.json's
// import map, so there is exactly one WitError/Stream module instance and
// `instanceof` holds across every boundary.

import { Translator } from "@deltic/runtime/shim";
import type { ComponentArtifacts } from "@deltic/runtime/embedder";
import { instantiate, WitError } from "@deltic/runtime/embedder";
import { wasiShims } from "@deltic/wasi-shims";
import { webcryptoImports } from "@polymorph/webcrypto-deltic";
import { websocketImports } from "@polymorph/websocket-deltic";
import { webrtcImports } from "@polymorph/webrtc-deltic";
import { socketsImports } from "@polymorph/iroh-sockets-stubs";

export { WitError };

export const ENGINE_INTERFACE = "experiment:mosh/engine";
export const SSH_INTERFACE = "experiment:mosh/ssh";
export const CLIENT_INTERFACE = "experiment:mosh-client/client";

// --- artifacts ---------------------------------------------------------------

const artifactCache = new Map<string, ComponentArtifacts>();
let translator: Translator | undefined;

/**
 * Translate a component once per path; the plan and adapters are immutable
 * and shared across every instance made from them.
 */
export async function loadArtifacts(
  componentPath: string,
): Promise<ComponentArtifacts> {
  const cached = artifactCache.get(componentPath);
  if (cached) return cached;
  if (!translator) {
    const shim = Deno.env.get("DELTIC_TRANSLATOR");
    if (!shim) {
      throw new Error(
        "DELTIC_TRANSLATOR is unset — fetch the pinned translator shim with " +
          "host-test/fetch-translator.ts and export its path (the justfile " +
          "recipes do both).",
      );
    }
    translator = await Translator.create(await Deno.readFile(shim));
  }
  const bytes = await Deno.readFile(componentPath);
  const { plan, adapters } = translator.translate(bytes);
  const artifacts: ComponentArtifacts = { plan, componentBytes: bytes, adapters };
  artifactCache.set(componentPath, artifacts);
  return artifacts;
}

// --- instances ---------------------------------------------------------------

export interface InstanceOptions {
  /** argv[0] stand-in in `wasi:cli`; label for log lines. */
  readonly label: string;
  /** Extra guest environment. */
  readonly env?: Record<string, string>;
  /** Mirror guest stdout/stderr to the host's (WOSH_GUEST_LOGS=1). */
  readonly passthrough?: boolean;
}

export interface Instance {
  // deltic's ergonomic export surface: resource classes (PascalCase),
  // Promise-shaped camelCase methods. Typed per-driver at the use site.
  // deno-lint-ignore no-explicit-any
  readonly exports: Record<string, any>;
  stdout(): string;
  stderr(): string;
}

function baseShims(options: InstanceOptions) {
  return wasiShims({
    cli: {
      args: [options.label],
      env: { ...options.env },
      passthrough: options.passthrough ??
        Deno.env.get("WOSH_GUEST_LOGS") === "1",
    },
  });
}

/** The engine component: WASI baseline only (sync sans-I/O engine). */
export async function newEngineInstance(
  componentPath: string,
  options: InstanceOptions,
): Promise<Instance> {
  const artifacts = await loadArtifacts(componentPath);
  const shims = baseShims(options);
  const instance = await instantiate(artifacts, { ...shims });
  return wrap(instance, shims, [ENGINE_INTERFACE]);
}

/**
 * The composed client (engine + glue + endpoint): WASI baseline + the
 * polymorph deltic host modules + the fail-on-call `wasi:sockets` stubs
 * (the browser profile — relay/WebRTC paths only; no UDP socket).
 *
 * Import fragments are built FRESH per instance: the host modules'
 * resource classes carry per-instance registry identity, and sharing one
 * record across two instantiations would alias two guests onto one table.
 */
export async function newClientInstance(
  componentPath: string,
  options: InstanceOptions,
): Promise<Instance> {
  const artifacts = await loadArtifacts(componentPath);
  const shims = baseShims(options);
  const imports = {
    ...shims,
    ...webcryptoImports(),
    ...websocketImports(),
    ...webrtcImports(),
    ...socketsImports(),
  };
  const instance = await instantiate(artifacts, imports);
  return wrap(instance, shims, [CLIENT_INTERFACE]);
}

function wrap(
  // deno-lint-ignore no-explicit-any
  instance: { exports: Record<string, any> },
  shims: ReturnType<typeof wasiShims>,
  required: string[],
): Instance {
  for (const name of required) {
    if (!instance.exports[name]) {
      throw new Error(
        `export "${name}" missing; component exports: ` +
          Object.keys(instance.exports).join(", "),
      );
    }
  }
  return {
    exports: instance.exports,
    stdout: () => shims.captured.stdoutText(),
    stderr: () => shims.captured.stderrText(),
  };
}

// --- helpers -----------------------------------------------------------------

/** Reject after `ms`, so a wedged phase names itself instead of hanging. */
export function deadline<T>(
  promise: Promise<T>,
  ms: number,
  what: string,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const bomb = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`timed out after ${ms} ms: ${what}`)),
      ms,
    );
  });
  return Promise.race([promise, bomb]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  }) as Promise<T>;
}

/** Render a rejection, unwrapping the branded WIT error payload. */
export function describeError(err: unknown): string {
  if (err instanceof WitError) {
    const p = err.payload as { tag?: string; val?: unknown } | string | undefined;
    if (typeof p === "string") return `WitError: ${p}`;
    return `WitError ${p?.tag ?? "?"}${p?.val === undefined ? "" : `(${String(p.val)})`}`;
  }
  return err instanceof Error ? `${err.name}: ${err.message}` : String(err);
}
