// The `wosh:terminal/identity-store` host implementation: this
// browser's SSH identity, persisted in IndexedDB.
//
// Persistence lives HERE, not in the component, structurally: the
// private half is a non-extractable WebCrypto key, and the only
// durable home for such a key is IndexedDB, which stores CryptoKey
// objects by structured clone -- the handle survives, the material
// never becomes readable. The component holds only per-instance
// capability handles, so it could not persist anything even if it
// wanted to; it verifies what this store hands it (Ed25519,
// non-extractable, sign-only) rather than trusting it.
//
// Concretely: the first use mints a non-extractable Ed25519 pair and
// stores it; every later call -- including after a page reload --
// returns the same pair, so the authorized_keys line the user
// installed keeps working. Clearing the site's data deliberately
// forgets the identity.
//
// When IndexedDB is unavailable (some private-browsing modes), the
// identity degrades to per-page-load -- exactly the pre-persistence
// behaviour -- with a console warning rather than a refusal.

/// <reference lib="dom" />

import { ComponentException } from "@deltic/runtime/embedder";
import {
  type SignatureAlgorithm,
  SigningKey,
  VerifyingKey,
} from "@polymorph/webcrypto-deltic";

// The mint-bound algorithm record the webcrypto host module attaches
// to every signature key (its `ED25519_ALGORITHM`, which it does not
// export). Plain data: the name is what `subtle.sign` is called with,
// the lengths are the WIT-pinned Ed25519 wire widths.
const ED25519: SignatureAlgorithm = Object.freeze({
  name: "Ed25519",
  namedCurve: undefined,
  hash: undefined,
  publicLength: 32,
  signatureLength: 64,
});

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

async function identity(): Promise<[SigningKey, VerifyingKey]> {
  let pair: CryptoKeyPair;
  try {
    try {
      pair = await loadOrMint();
    } catch (e) {
      // Storage trouble is not identity trouble: fall back to the
      // pre-persistence behaviour (a fresh key per page load) and say
      // so, rather than refusing to authenticate at all.
      console.warn(
        "wosh: IndexedDB unavailable; this browser's SSH identity will not survive a reload",
        e,
      );
      pair = await mint();
    }
  } catch (e) {
    // No Ed25519 WebCrypto at all: the err arm of the WIT result.
    throw new ComponentException(
      `mint ssh identity: ${(e as Error)?.message ?? e}`,
    );
  }
  return [
    new SigningKey(pair.privateKey, ED25519),
    new VerifyingKey(pair.publicKey, ED25519),
  ];
}

/** The imports-record fragment for deltic's `instantiate`. */
export function identityStoreImports(): Record<string, unknown> {
  return { "wosh:terminal/identity-store": { identity } };
}
