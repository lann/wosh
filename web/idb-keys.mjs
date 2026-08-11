// IndexedDB CryptoKey persistence (M5, workstream D).
//
// Non-extractable WebCrypto keys survive as *use-only* handles via
// IndexedDB's structured clone — the browser stores the key material,
// script never sees it (the XSS posture from the security model). This
// is the embedder-side identity persistence that pairs with
// polymorph-iroh's `identity-from-keys` (PR #31): the CryptoKey handle
// is what the webcrypto shim wraps back into a signing handle.
//
// Browser-only module (IndexedDB, crypto.subtle); exercised headless by
// host-test/web-tests.mjs.

const DB_NAME = "wosh-keys";
const STORE = "keys";

function request(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/** Open (creating on first use) the key store. */
export async function openKeyStore() {
  const open = indexedDB.open(DB_NAME, 1);
  open.onupgradeneeded = () => {
    open.result.createObjectStore(STORE);
  };
  const db = await request(open);
  const tx = (mode) => db.transaction(STORE, mode).objectStore(STORE);
  return {
    /** Store a CryptoKey (or key pair record) under `name`. */
    put: (name, key) => request(tx("readwrite").put(key, name)),
    /** The stored value, or undefined. */
    get: (name) => request(tx("readonly").get(name)),
    del: (name) => request(tx("readwrite").delete(name)),
    list: () => request(tx("readonly").getAllKeys()),
    close: () => db.close(),
  };
}

/**
 * The client's Ed25519 identity key pair, generated non-extractable on
 * first use and persisted. Returns `{ keyPair, created }`.
 * Ed25519-in-WebCrypto is required (Chromium 137+, Firefox 130+,
 * Safari 17+); callers surface the error legibly on older engines.
 */
export async function ensureIdentity(store, name = "identity-ed25519") {
  const existing = await store.get(name);
  if (existing) return { keyPair: existing, created: false };
  const keyPair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    false, // non-extractable: use-only handle, never exfiltratable
    ["sign", "verify"],
  );
  await store.put(name, keyPair);
  return { keyPair, created: true };
}
