// The `wosh:terminal/identity-store` host implementation: this
// browser's SSH identity, persisted in IndexedDB, exposed to the
// component as public bytes and signatures only.
//
// Persistence lives HERE, not in the component, structurally: the
// private half is a non-extractable WebCrypto key, and the only
// durable home for such a key is IndexedDB, which stores CryptoKey
// objects by structured clone -- the handle survives, the material
// never becomes readable. The component holds only per-instance
// capability handles, so it could not persist anything even if it
// wanted to.
//
// The surface is deliberately sign-only: the CryptoKey never leaves
// this module, so no private-key handle exists anywhere in the
// component graph. (That is a structural tidiness, not an XSS
// boundary: IndexedDB is origin-scoped, so any script in the origin
// can reach the stored handle regardless. The mitigations that would
// change that -- user-presence gating along the lines of main's
// passkey/PRF escrow -- are a different feature.) The component
// checks each signature against `public-key` on its side, so a bug
// here that signs with the wrong key fails loudly at the client.
//
// Concretely: the first use mints a non-extractable Ed25519 pair and
// stores it; every later call -- including after a page reload --
// returns the same identity, so the authorized_keys line the user
// installed keeps working. Clearing the site's data deliberately
// forgets the identity.
//
// When IndexedDB is unavailable (some private-browsing modes), the
// identity degrades to per-page-load -- exactly the pre-persistence
// behaviour -- with a console warning rather than a refusal.

/// <reference lib="dom" />

import { ComponentException } from "@deltic/runtime/embedder";

const DB_NAME = "wosh";
const STORE = "identity";
const KEY = "ssh";

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

/** Mint the identity: non-extractable private half, sign/verify split. */
async function mint(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    "Ed25519",
    /* extractable (private half; the public half is always exportable) */ false,
    ["sign", "verify"],
  ) as CryptoKeyPair;
}

/** A stored value is only trusted if it is exactly what `mint` makes. */
function usable(v: unknown): v is CryptoKeyPair {
  const pair = v as CryptoKeyPair | null;
  return (
    typeof pair === "object" && pair !== null &&
    pair.privateKey instanceof CryptoKey &&
    pair.publicKey instanceof CryptoKey &&
    pair.privateKey.algorithm.name === "Ed25519" &&
    !pair.privateKey.extractable &&
    pair.privateKey.usages.includes("sign")
  );
}

async function loadOrMint(): Promise<CryptoKeyPair> {
  const db = await openDb();
  try {
    const existing = await req(
      db.transaction(STORE).objectStore(STORE).get(KEY),
    );
    if (usable(existing)) return existing;

    // Nothing stored (or nothing usable): mint first, then settle
    // ownership in ONE readwrite transaction. IndexedDB serializes
    // readwrite transactions per store, so when two tabs race, both
    // observe the same winner: whichever committed first.
    const candidate = await mint();
    const tx = db.transaction(STORE, "readwrite");
    const store = tx.objectStore(STORE);
    const race = await req(store.get(KEY));
    let winner: CryptoKeyPair;
    if (usable(race)) {
      winner = race;
    } else {
      store.put(candidate, KEY);
      winner = candidate;
    }
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = tx.onerror = () => reject(tx.error);
    });
    return winner;
  } finally {
    db.close();
  }
}

// Resolved once per page and cached: `public-key` and `sign` must
// answer for the SAME pair even on the ephemeral fallback path, where
// a second load would mint a second key.
let pairPromise: Promise<CryptoKeyPair> | undefined;

function identityPair(): Promise<CryptoKeyPair> {
  pairPromise ??= (async () => {
    try {
      return await loadOrMint();
    } catch (e) {
      // Storage trouble is not identity trouble: fall back to the
      // pre-persistence behaviour (a fresh key per page load) and say
      // so, rather than refusing to authenticate at all.
      console.warn(
        "wosh: IndexedDB unavailable; this browser's SSH identity will not survive a reload",
        e,
      );
      return await mint();
    }
  })();
  return pairPromise;
}

/** Failures cross the WIT boundary as the `result`'s err arm. */
const errArm = (what: string, e: unknown): ComponentException =>
  new ComponentException(`${what}: ${(e as Error)?.message ?? e}`);

async function publicKey(): Promise<Uint8Array> {
  try {
    const pair = await identityPair();
    return new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  } catch (e) {
    throw errArm("ssh identity public key", e);
  }
}

async function sign(data: Uint8Array): Promise<Uint8Array> {
  try {
    const pair = await identityPair();
    return new Uint8Array(
      // The cast narrows `ArrayBufferLike` for the dom lib's
      // `BufferSource`; deltic lowers `list<u8>` as a plain
      // ArrayBuffer-backed Uint8Array.
      await crypto.subtle.sign("Ed25519", pair.privateKey, data as BufferSource),
    );
  } catch (e) {
    throw errArm("ssh identity sign", e);
  }
}

/** The imports-record fragment for deltic's `instantiate`. */
export function identityStoreImports(): Record<string, unknown> {
  return { "wosh:terminal/identity-store": { publicKey, sign } };
}
