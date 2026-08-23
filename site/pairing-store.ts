// The `wosh:terminal/pairing-store` host implementation: this
// browser's IROH pairing identity -- an opaque blob the component
// stores and reloads, persisted in IndexedDB alongside the SSH
// identity.
//
// Unlike identity-store (a non-extractable CryptoKey, sign-only by
// design), the blob here IS raw key material, on purpose: the iroh
// endpoint must be constructed from the pair each instantiation, and
// the pairing layer's stakes are low by design -- it gates nothing but
// the tunnel; the SSH host-key gate and real authentication are the
// boundary that matters. A stolen pairing key lets someone knock on a
// listener's door; it opens nothing. (Origin-scoped storage is the
// same trust domain either way.)
//
// The component owns the blob format; this module never looks inside.
// When IndexedDB is unavailable the store degrades to "nothing
// persists": `load` returns none and `store` is accepted into the
// void, which the component treats as pairing-fresh-each-run -- the
// pre-pairing behaviour, with a console warning.

/// <reference lib="dom" />

import { ComponentException } from "@polyengine/protocol";

const DB_NAME = "wosh";
const STORE = "identity";
const KEY = "iroh-pairing";

const req = <T>(r: IDBRequest<T>): Promise<T> =>
  new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DB_NAME, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(STORE);
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
    open.onblocked = () => reject(new Error("IndexedDB open blocked"));
  });
}

async function load(): Promise<Uint8Array | undefined> {
  let db: IDBDatabase;
  try {
    db = await openDb();
  } catch (e) {
    console.warn("wosh: IndexedDB unavailable; pairing will not survive a reload", e);
    return undefined; // degrade, never refuse
  }
  try {
    const v = await req(db.transaction(STORE).objectStore(STORE).get(KEY));
    return v instanceof Uint8Array ? v : undefined;
  } catch (e) {
    throw new ComponentException(`pairing load: ${(e as Error)?.message ?? e}`);
  } finally {
    db.close();
  }
}

async function store(blob: Uint8Array): Promise<void> {
  let db: IDBDatabase;
  try {
    db = await openDb();
  } catch (e) {
    console.warn("wosh: IndexedDB unavailable; pairing will not survive a reload", e);
    return; // accepted into the void, per the interface contract
  }
  try {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(blob, KEY);
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = tx.onerror = () => reject(tx.error);
    });
  } catch (e) {
    throw new ComponentException(`pairing store: ${(e as Error)?.message ?? e}`);
  } finally {
    db.close();
  }
}

/** The imports-record fragment for polyengine's `instantiate`. */
export function pairingStoreImports(): Record<string, unknown> {
  return { "wosh:terminal/pairing-store": { load, store } };
}
