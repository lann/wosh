// The `wosh:terminal/transfer-io` host implementation: the `source`
// and `sink` resources the SFTP engine reads from and writes to. See
// wit/terminal.wit's `transfer-io` doc comment for the split this
// mirrors -- read-at-offset for uploads (a `File` is random-access for
// free), append-only for downloads (OPFS staging, written once, in
// order).
//
// OPFS WRITE-PATH CHOICE: sync access handles (in transfer-worker.mjs),
// not `createWritable`. A `FileSystemWritableFileStream` only commits
// to the real file on `close()` -- everything written before that
// lives in a swap file that a crashed/reloaded page loses outright, so
// it cannot back a resumable sink: there is no mid-transfer point where
// `committed()` could truthfully report anything. A sync access
// handle's `flush()` is a real durability checkpoint mid-file, which is
// exactly what the contract's `committed()` needs (never overstate --
// resume corrupts the file otherwise). The one cost: sync access
// handles are Worker-only across engines (Safari included), hence the
// dedicated worker and the postMessage RPC below.
//
// `source` needs none of this: a picked `File` is already durable (it
// lives on the user's disk or wherever the picker got it from) and
// already random-access, so `read` is a plain `Blob.slice().
// arrayBuffer()` on the main thread.

/// <reference lib="dom" />

import { ComponentException } from "@polyengine/protocol";

const errArm = (what: string, e: unknown): ComponentException =>
  new ComponentException(`${what}: ${(e as Error)?.message ?? e}`);

// --- source: wraps a picked File -------------------------------------------

/** An upload's byte supply. Reads are strictly sequential per the
 * contract (wit/terminal.wit transfer-io.source) -- no read-ahead to
 * cache or cancel here. */
export class Source {
  #file: File;

  constructor(file: File) {
    this.#file = file;
  }

  async size(): Promise<bigint> {
    return BigInt(this.#file.size);
  }

  async read(offset: bigint, len: number): Promise<Uint8Array> {
    try {
      const start = Number(offset);
      const blob = this.#file.slice(start, start + len);
      return new Uint8Array(await blob.arrayBuffer());
    } catch (e) {
      throw errArm("transfer source read", e);
    }
  }
}

// --- sink: OPFS staging, via the worker's sync access handles --------------

let worker: Worker | undefined;
let injectedWorker: Worker | undefined;
let nextReqId = 0;
const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: unknown) => void }>();

/**
 * Supply the worker rather than let this module construct one.
 *
 * This module gets bundled into site/dist/polyengine.js (`just
 * web-bundle`), so `new URL("./transfer-worker.mjs", import.meta.url)`
 * here would resolve against the BUNDLE's location, not this source
 * file's -- a path that does not exist post-bundle. transfer-ui.mjs is
 * served unbundled straight from site/, so its own `import.meta.url`
 * resolves correctly; it constructs the worker and hands it in before
 * the first sink is opened.
 */
export function useTransferWorker(w: Worker): void {
  injectedWorker = w;
}

function rpcWorker(): Worker {
  if (!worker) {
    worker = injectedWorker ??
      new Worker(new URL("./transfer-worker.mjs", import.meta.url), { type: "module" });
    worker.onmessage = (ev: MessageEvent) => {
      const { reqId, ok, result, error } = ev.data;
      const p = pending.get(reqId);
      if (!p) return; // stale/unknown -- nothing to settle
      pending.delete(reqId);
      if (ok) p.resolve(result);
      else p.reject(new Error(error));
    };
  }
  return worker;
}

function call(op: string, data: Record<string, unknown> = {}): Promise<unknown> {
  const reqId = ++nextReqId;
  return new Promise((resolve, reject) => {
    pending.set(reqId, { resolve, reject });
    rpcWorker().postMessage({ reqId, op, ...data });
  });
}

/** A download's destination. `stagingId` names the OPFS file under
 * `transfers/` -- callers mint one (see `newStagingId`) and persist it
 * alongside the transfer record, so a page reload can reopen the SAME
 * file and resume from its length. */
export class Sink {
  #id: string;
  #opened: Promise<void>;

  constructor(stagingId: string, create = true) {
    this.#id = stagingId;
    this.#opened = (call("open", { id: stagingId, create }) as Promise<number>).then(() => {});
  }

  async write(data: Uint8Array): Promise<void> {
    await this.#opened;
    try {
      await call("write", { id: this.#id, bytes: data });
    } catch (e) {
      throw errArm("transfer sink write", e);
    }
  }

  async committed(): Promise<bigint> {
    await this.#opened;
    try {
      return BigInt((await call("committed", { id: this.#id })) as number);
    } catch (e) {
      throw errArm("transfer sink committed", e);
    }
  }

  async flush(): Promise<void> {
    await this.#opened;
    try {
      await call("flush", { id: this.#id });
    } catch (e) {
      throw errArm("transfer sink flush", e);
    }
  }

  /** Runs when the component drops its last handle to this resource
   * (transfer finished, cancelled, or the session/transfer resource
   * dropped) -- releases the worker's exclusive lock on the staged
   * file so the UI can read it back (getFile()) for download handoff,
   * or reopen it later to resume. */
  [Symbol.dispose]() {
    call("close", { id: this.#id }).catch(() => {});
  }
}

/** A fresh id for a staging file, unrelated to any transfer's remote
 * path (paths are bytes, not friendly filenames; the id just needs to
 * be unique on this origin). */
export function newStagingId(): string {
  return crypto.randomUUID();
}

/** The staged bytes as a `Blob`, for the download-completion handoff
 * (Blob URL + `<a download>`). Callers must ensure the `Sink` over this
 * id has already been dropped (or explicitly closed) -- OPFS refuses a
 * second accessor while the worker's sync access handle is open.
 *
 * Explicitly typed `application/octet-stream`, NOT the empty/inferred
 * type `getFile()` would otherwise hand back: verified live (repro:
 * seed a dir with `.gitconfig`, download it) that Chromium's download
 * manager sniffs an untyped blob's CONTENT independently of the `File`
 * API's own (empty, since the staging filename is an extensionless
 * UUID) `.type`, and for plain-text content this invents a `.txt`
 * extension on any name it also judges extensionless -- which a
 * leading-dot dotfile name IS, after Chromium's separate hidden-file
 * policy trims the dot (see transfer-ui.mjs's handoff comment for the
 * `.gitconfig` -> `gitconfig.txt` bug this was). An explicit
 * `application/octet-stream` type suppresses the content-sniff and
 * the invented extension; the leading-dot trim is a DIFFERENT,
 * unsuppressable policy and is handled by warning the user instead
 * (see `predictSavedName` in transfer-ui.mjs). */
export async function stagedBlob(id: string): Promise<Blob> {
  const root = await navigator.storage.getDirectory();
  const dir = await root.getDirectoryHandle("transfers", { create: true });
  const fh = await dir.getFileHandle(id);
  const raw = await fh.getFile();
  // `slice` with a type re-tags the SAME underlying bytes rather than
  // copying the whole file into an ArrayBuffer -- matters once a
  // download is bigger than "fits comfortably twice in memory".
  return raw.slice(0, raw.size, "application/octet-stream");
}

/** Explicitly release the worker's handle without waiting for resource
 * drop -- used before reading `stagedBlob` right after a transfer's
 * `outcome` reports done, since drop timing is the engine's to choose. */
export async function closeStaged(id: string): Promise<void> {
  await call("close", { id });
}

/** Remove a staged file once its handoff (or its record) is done. */
export async function removeStaged(id: string): Promise<void> {
  await call("remove", { id });
}

/** The imports-record fragment for polyengine's `instantiate`. */
export function transferIoImports(): Record<string, unknown> {
  return { "wosh:terminal/transfer-io": { Source, Sink } };
}
