// The `wosh:terminal/passkey-store` host implementation: WebAuthn
// ceremonies run in-page, with the resulting identity persisted in
// this browser so the enrolled passkey survives page reloads.
//
// A SEPARATE IndexedDB database from identity-store.ts's `wosh`
// database, on purpose: two independent modules sharing one database
// would need a coordinated version bump between them, and IndexedDB
// throws at `open()` time on a version mismatch -- a module upgrading
// its own store could brick the other's. A second database is the
// cost of avoiding that coupling.
//
// See wit/terminal.wit's `passkey-store` doc comment for the full
// design rationale (why WebAuthn-shaped rather than SSH-shaped, why
// `adopt` exists, what a passkey buys over identity-store). This
// module runs the ceremonies and hands back exactly what the browser
// produced; it owns no SSH encoding.

/// <reference lib="dom" />

import { ComponentException } from "@deltic/runtime/embedder";

const DB_NAME = "wosh-passkey";
const STORE = "identity";
const KEY = "passkey";

interface StoredIdentity {
  /** Undefined until an assertion teaches it (the `adopt`-then-forgot-
   * the-rawId case is impossible in practice, but `assert` learns it
   * too when starting from an `adopt`ed record). */
  credentialId: Uint8Array | undefined;
  /** Uncompressed P-256 point, 65 bytes, `0x04 || X || Y`. */
  publicKey: Uint8Array;
  rpId: string;
}

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

/** Failures cross the WIT boundary as the `result`'s err arm. */
const errArm = (what: string, e: unknown): ComponentException =>
  new ComponentException(`${what}: ${(e as Error)?.message ?? e}`);

function usable(v: unknown): v is StoredIdentity {
  const s = v as StoredIdentity | null;
  return (
    typeof s === "object" && s !== null &&
    s.publicKey instanceof Uint8Array && s.publicKey.length === 65 &&
    typeof s.rpId === "string" &&
    (s.credentialId === undefined || s.credentialId instanceof Uint8Array)
  );
}

async function loadRecord(): Promise<StoredIdentity | undefined> {
  let db: IDBDatabase;
  try {
    db = await openDb();
  } catch (e) {
    console.warn("wosh: IndexedDB unavailable; the passkey identity will not survive a reload", e);
    return memRecord; // degrade to the per-page-load fallback below
  }
  try {
    const v = await req(db.transaction(STORE).objectStore(STORE).get(KEY));
    return usable(v) ? v : undefined;
  } finally {
    db.close();
  }
}

async function saveRecord(rec: StoredIdentity): Promise<void> {
  let db: IDBDatabase;
  try {
    db = await openDb();
  } catch (e) {
    console.warn("wosh: IndexedDB unavailable; the passkey identity will not survive a reload", e);
    memRecord = rec; // degrade, never refuse
    return;
  }
  try {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(rec, KEY);
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

async function clearRecord(): Promise<void> {
  let db: IDBDatabase;
  try {
    db = await openDb();
  } catch (e) {
    console.warn("wosh: IndexedDB unavailable; the passkey identity will not survive a reload", e);
    memRecord = undefined;
    return;
  }
  try {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).delete(KEY);
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

// Per-page-load fallback when IndexedDB is unavailable, mirroring
// identity-store.ts's degrade-not-refuse behaviour.
let memRecord: StoredIdentity | undefined;

// --- DER <-> raw ECDSA signature conversion ---------------------------------
//
// WebAuthn returns the assertion signature in ASN.1 DER (SEQUENCE of
// two INTEGERs, r and s); WebCrypto's `verify` for ECDSA wants the raw
// fixed-width r||s the P-256 order defines (64 bytes: 32 + 32). Kept
// strict rather than lenient: a malformed DER blob here means the
// authenticator (or a hostile page) produced garbage, and the right
// answer is a clear failure, not a best-effort guess at the encoding.

function derToRawEcdsaSignature(der: Uint8Array): Uint8Array {
  const fail = () => {
    throw new Error("malformed ECDSA DER signature");
  };
  let off = 0;
  if (der[off++] !== 0x30) fail(); // SEQUENCE
  let seqLen = der[off++];
  if (seqLen & 0x80) {
    const nBytes = seqLen & 0x7f;
    seqLen = 0;
    for (let i = 0; i < nBytes; i++) seqLen = (seqLen << 8) | der[off++];
  }
  if (off + seqLen !== der.length) fail();

  const readInt = (): Uint8Array => {
    if (der[off++] !== 0x02) fail(); // INTEGER
    let len = der[off++];
    if (len & 0x80) {
      const nBytes = len & 0x7f;
      len = 0;
      for (let i = 0; i < nBytes; i++) len = (len << 8) | der[off++];
    }
    const bytes = der.subarray(off, off + len);
    off += len;
    return bytes;
  };
  const r = readInt();
  const s = readInt();
  if (off !== der.length) fail();

  // Strip a leading 0x00 sign-guard byte, then left-pad to 32.
  const fit32 = (b: Uint8Array): Uint8Array => {
    let x = b;
    while (x.length > 32 && x[0] === 0) x = x.subarray(1);
    if (x.length > 32) fail();
    const out = new Uint8Array(32);
    out.set(x, 32 - x.length);
    return out;
  };
  const raw = new Uint8Array(64);
  raw.set(fit32(r), 0);
  raw.set(fit32(s), 32);
  return raw;
}

/**
 * Verify an assertion's DER signature against a stored uncompressed
 * P-256 public key, over `authenticatorData || sha256(clientDataJSON)`
 * -- exactly what the authenticator signed (WebAuthn L2 §6.5.5 -- see
 * wit/terminal.wit's `assertion` doc comment for why the byte order
 * matters). Used both to confirm an `adopt` claim and to catch a wrong
 * passkey at `assert` time, before the server ever sees the signature.
 */
async function verifyAssertion(
  publicKey: Uint8Array,
  authenticatorData: Uint8Array,
  clientDataJSON: Uint8Array,
  derSignature: Uint8Array,
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw",
    publicKey as BufferSource,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON as BufferSource));
  const signedOver = new Uint8Array(authenticatorData.length + clientDataHash.length);
  signedOver.set(authenticatorData, 0);
  signedOver.set(clientDataHash, authenticatorData.length);
  let raw: Uint8Array;
  try {
    raw = derToRawEcdsaSignature(derSignature);
  } catch {
    return false;
  }
  return await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    raw as BufferSource,
    signedOver as BufferSource,
  );
}

// --- the ceremony gate -------------------------------------------------------
//
// authenticate-passkey (terminal.wit) needs the human DURING
// authentication: the server's demand for a signature arrives while
// the page is polling status in the background, with no user gesture
// in scope. Some browsers require transient user activation before
// `credentials.get()` will even run the ceremony, so this hook lets
// the page ask for a deliberate tap first instead of the ceremony
// failing outright. Installed by boot.mjs; a no-op (proceed straight
// to the ceremony) until then.
let ceremonyGate: (() => Promise<void>) | undefined;

/** Install (or clear, with `undefined`) the pre-assertion gate. */
export function setCeremonyGate(fn: (() => Promise<void>) | undefined): void {
  ceremonyGate = fn;
}

async function maybeGate(): Promise<void> {
  const active = (navigator as unknown as { userActivation?: { isActive: boolean } }).userActivation
    ?.isActive;
  if (active === false && ceremonyGate) await ceremonyGate();
}

// --- the WIT surface ---------------------------------------------------------

interface PasskeyIdentity {
  publicKey: Uint8Array;
  relyingParty: string;
}

async function identity(): Promise<PasskeyIdentity | undefined> {
  try {
    const rec = await loadRecord();
    return rec ? { publicKey: rec.publicKey, relyingParty: rec.rpId } : undefined;
  } catch (e) {
    throw errArm("passkey identity", e);
  }
}

async function enroll(): Promise<PasskeyIdentity> {
  try {
    const rpId = location.hostname;
    const userId = crypto.getRandomValues(new Uint8Array(16));
    // The registration challenge is unused by design: nothing here
    // verifies attestation (attestation: "none"), so there is no
    // server-side ceremony state for the challenge to defend. It is
    // present only because the WebAuthn API requires one.
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { id: rpId, name: "wosh" },
        user: { id: userId, name: "wosh-browser", displayName: "wosh browser identity" },
        challenge,
        // ES256 (alg -7) ONLY: OpenSSH's webauthn signature algorithm
        // is defined for NIST P-256 and nothing else. Offering a
        // second algorithm risks the authenticator minting a
        // credential of a curve this client (and sshd's webauthn
        // support) cannot use.
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          // Resident/discoverable, required: the second-device
          // `adopt` path knows the public key from the pasted line but
          // not the credential id, so the credential must be
          // findable by the authenticator without one (an empty
          // allowCredentials list in `assert`).
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "preferred",
        },
        attestation: "none",
      },
    }) as PublicKeyCredential | null;
    if (!cred) throw new Error("no credential returned");

    const response = cred.response as AuthenticatorAttestationResponse;
    const spki = response.getPublicKey?.();
    if (!spki) {
      throw new Error(
        "authenticator did not return a public key (getPublicKey unsupported or credential not ES256)",
      );
    }
    const key = await crypto.subtle.importKey(
      "spki",
      spki,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"],
    );
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));

    const rec: StoredIdentity = {
      credentialId: new Uint8Array(cred.rawId),
      publicKey,
      rpId,
    };
    await saveRecord(rec);
    return { publicKey, relyingParty: rpId };
  } catch (e) {
    throw errArm("passkey enroll", e);
  }
}

async function adopt(candidate: PasskeyIdentity): Promise<void> {
  try {
    // A credential scoped to another domain can never be asserted
    // from here -- the authenticator signs over sha256(rpId), and the
    // browser will not run a ceremony against an rpId that is not
    // this origin's domain (or a registrable suffix of it).
    if (candidate.relyingParty !== location.hostname) {
      throw new Error(
        `passkey is scoped to "${candidate.relyingParty}", not this site ("${location.hostname}")`,
      );
    }

    // Confirm the claim before storing (terminal.wit's `adopt` doc
    // comment): run one assertion with an EMPTY allowCredentials, so
    // the platform's picker shows every resident credential for this
    // rpId and the user chooses the synced passkey. Whichever one they
    // pick must produce a signature that verifies against the
    // claimed public key, or this is the wrong passkey.
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: candidate.relyingParty,
        userVerification: "preferred",
        allowCredentials: [],
      },
    }) as PublicKeyCredential | null;
    if (!cred) throw new Error("no assertion returned");
    const response = cred.response as AuthenticatorAssertionResponse;
    const authenticatorData = new Uint8Array(response.authenticatorData);
    const clientDataJSON = new Uint8Array(response.clientDataJSON);
    const signature = new Uint8Array(response.signature);

    const ok = await verifyAssertion(candidate.publicKey, authenticatorData, clientDataJSON, signature);
    if (!ok) {
      throw new Error(
        "the passkey selected does not match the claimed public key -- a different passkey was picked",
      );
    }

    await saveRecord({
      credentialId: new Uint8Array(cred.rawId),
      publicKey: candidate.publicKey,
      rpId: candidate.relyingParty,
    });
  } catch (e) {
    throw errArm("passkey adopt", e);
  }
}

async function forget(): Promise<void> {
  try {
    // The credential itself survives in the authenticator (only its
    // owner can delete it there); this only stops OFFERING it.
    await clearRecord();
  } catch (e) {
    throw errArm("passkey forget", e);
  }
}

async function assert(challenge: Uint8Array): Promise<{
  authenticatorData: Uint8Array;
  clientDataJson: Uint8Array;
  signature: Uint8Array;
}> {
  try {
    const rec = await loadRecord();
    if (!rec) throw new Error("no passkey enrolled");

    await maybeGate();

    const cred = await navigator.credentials.get({
      publicKey: {
        // `challenge` IS the SSH signature blob, verbatim, not a hash
        // -- passed straight through; the browser does its own
        // base64url encoding of these exact bytes (terminal.wit).
        challenge: challenge as BufferSource,
        rpId: rec.rpId,
        userVerification: "preferred",
        allowCredentials: rec.credentialId
          ? [{ type: "public-key", id: rec.credentialId as BufferSource }]
          : [],
        // No extensions requested: any extension output sets a flag
        // that changes the shape of what was signed, and the
        // simplest way to keep the wire format predictable is to ask
        // for nothing.
      },
    }) as PublicKeyCredential | null;
    if (!cred) throw new Error("no assertion returned");

    const response = cred.response as AuthenticatorAssertionResponse;
    const authenticatorData = new Uint8Array(response.authenticatorData);
    // Never re-serialize clientDataJSON: sshd checks these exact bytes
    // (it reconstructs an expected prefix and hashes what was sent),
    // so this passes the browser's raw ArrayBuffer straight through.
    const clientDataJson = new Uint8Array(response.clientDataJSON);
    const signature = new Uint8Array(response.signature);

    const ok = await verifyAssertion(rec.publicKey, authenticatorData, clientDataJson, signature);
    if (!ok) {
      throw new Error(
        "the signed assertion does not match the stored passkey -- a different passkey was selected",
      );
    }

    // Learn the credential id if this record came from `adopt`
    // without ever having asserted before.
    const rawId = new Uint8Array(cred.rawId);
    if (!rec.credentialId) {
      await saveRecord({ ...rec, credentialId: rawId });
    }

    return { authenticatorData, clientDataJson, signature };
  } catch (e) {
    throw errArm("passkey assert", e);
  }
}

async function assertUnknown(challenge: Uint8Array): Promise<{
  credentialId: Uint8Array;
  relyingParty: string;
  assertion: {
    authenticatorData: Uint8Array;
    clientDataJson: Uint8Array;
    signature: Uint8Array;
  };
}> {
  try {
    // This is the ceremony that must work with NO stored record --
    // that is precisely the situation recovery exists for (an evicted
    // IndexedDB has forgotten everything `assert` relies on). So,
    // unlike `assert`: no `loadRecord()`, an EMPTY allowCredentials
    // (the platform picker offers every resident credential for this
    // rpId rather than one this client can already name), and no
    // verification against a stored public key -- there is nothing to
    // verify against yet; that is what the caller (recovery) works out
    // from two of these.
    const rpId = location.hostname;
    const cred = await navigator.credentials.get({
      publicKey: {
        // Passed through untouched, same rule as `assert`. Here it is
        // a recovery challenge rather than an SSH signature blob --
        // nothing verifies it, and what recovery reads is the
        // signature, not the message. The caller picks two DIFFERENT
        // ones on purpose; see terminal.wit's `assert-unknown`.
        challenge: challenge as BufferSource,
        rpId,
        userVerification: "preferred",
        allowCredentials: [],
        // No extensions requested, same reasoning as `assert`.
      },
    }) as PublicKeyCredential | null;
    if (!cred) throw new Error("no assertion returned");

    const response = cred.response as AuthenticatorAssertionResponse;
    const authenticatorData = new Uint8Array(response.authenticatorData);
    // Never re-serialize clientDataJSON -- same reasoning as `assert`.
    const clientDataJson = new Uint8Array(response.clientDataJSON);
    const signature = new Uint8Array(response.signature);

    return {
      credentialId: new Uint8Array(cred.rawId),
      relyingParty: rpId,
      assertion: { authenticatorData, clientDataJson, signature },
    };
  } catch (e) {
    throw errArm("passkey assert-unknown", e);
  }
}

async function remember(identity: PasskeyIdentity, credentialId: Uint8Array): Promise<void> {
  try {
    // This is `adopt` WITHOUT the confirming ceremony: the caller
    // (recovery) already proved the public key belongs to this
    // credential -- that is what two intersecting assertions bought
    // it -- so asking for a third touch here to re-establish what is
    // already known would be theatre, not safety.
    await saveRecord({
      credentialId,
      publicKey: identity.publicKey,
      rpId: identity.relyingParty,
    });
  } catch (e) {
    throw errArm("passkey remember", e);
  }
}

/** The imports-record fragment for deltic's `instantiate`. */
export function passkeyStoreImports(): Record<string, unknown> {
  return {
    "wosh:terminal/passkey-store": { identity, enroll, adopt, forget, assert, assertUnknown, remember },
  };
}
