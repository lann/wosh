// PRF wrap/unwrap of the session escrow (D4 PRF arm, M6).
//
// The WebAuthn `prf` extension evaluates a per-credential PRF during a
// get() assertion; HKDF turns the 32-byte output into a non-extractable
// AES-GCM key that seals `{key, seqFloor}`. The resulting blob is the
// `{prf: {credId, salt, iv, ct, seqFloor}}` arm shared by
// web/storage.mjs (local sessions) and proto::Escrow (proxy escrow) —
// the proxy stores and returns it, never reads it.
//
// Trust: everything OUTSIDE `ct` in a proxy-returned blob is
// attacker-controlled. The floor matters most — rolling it back makes a
// reattaching client reuse OCB nonces under a key whose traffic the
// proxy has seen (nonce reuse breaks OCB confidentiality/integrity), so
// the *sealed* seqFloor is authoritative for attach; the outer copy
// exists for client-local bookkeeping (storage.mjs bumpSeqFloor works
// without an unwrap ceremony). Unwrap returns the inner value only.
//
// Floor-jump policy (finding 13 + M6): the sealed floor can only be
// rewritten while the KEK is in memory — right after an assertion. Each
// attach therefore re-seals with `floor + FLOOR_JUMP` and re-escrows
// over the live control channel; FLOOR_JUMP (2^32) exceeds any
// plausible single-session datagram count, so a client that dies
// without a detach-time write still attaches safely next time. The
// 63-bit sequence space affords 2^31 such jumps.
//
// Ceremony calls go through CredentialsContainer.prototype — password
// managers wrap navigator.credentials and break ceremonies with
// non-WebAuthn errors (M0 finding 6); callers should surface
// interference legibly, as the probe does.

const enc = new TextEncoder();
const dec = new TextDecoder();

/** Fixed PRF eval salt (v1). Per-credential PRFs need no per-escrow
 * randomness; keeping it in the blob lets a future v2 rotate it. */
export const PRF_EVAL_SALT = enc.encode("wosh/prf-salt/v1");

/** Sealed-floor jump applied on every re-seal (see header). */
export const FLOOR_JUMP = 2 ** 32;

/** Margin over the floor for the attach-time initial sequence
 * (matches the native harness SEQ_MARGIN). */
export const SEQ_MARGIN = 10_000;

const HKDF_INFO = enc.encode("wosh/escrow-wrap/v1");

export function b64u(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export function unb64u(s) {
  const b = atob(s.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

/** Extensions for navigator.credentials.create(): request PRF. */
export function prfExtensionForCreate() {
  return { prf: {} };
}

/** Extensions for navigator.credentials.get(): evaluate the PRF. */
export function prfExtensionForGet() {
  return { prf: { eval: { first: PRF_EVAL_SALT } } };
}

/**
 * D4 sub-policy (decided M6): an authenticator without `prf` cannot
 * make a session persistent — the escrowed key would have to be
 * plaintext on the proxy, which is exactly what the PRF arm exists to
 * prevent. The `plain` schema arm stays for tests and emergencies, but
 * the client refuses to create one.
 */
export function assertPersistencePermitted(prfEnabled) {
  if (prfEnabled !== true) {
    throw new Error(
      "this authenticator does not support the WebAuthn prf extension; " +
        "refusing to persist the session (the mosh key would sit in " +
        "plaintext on the proxy)",
    );
  }
}

async function deriveKek(prfOutput) {
  const ikm = await crypto.subtle.importKey("raw", prfOutput, "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: HKDF_INFO },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Seal `{key, seqFloor}` under the PRF output; returns the tagged
 * `{prf: {...}}` escrow object (storage.mjs session `key` shape;
 * `JSON.stringify` of it is the proxy escrow blob).
 */
export async function wrapEscrow(prfOutput, { key, seqFloor }, credIdBytes) {
  if (!Number.isSafeInteger(seqFloor) || seqFloor < 0) {
    throw new Error("seqFloor must be a non-negative integer");
  }
  const kek = await deriveKek(prfOutput);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    kek,
    enc.encode(JSON.stringify({ key, seqFloor })),
  );
  return {
    prf: {
      credId: b64u(credIdBytes),
      salt: b64u(PRF_EVAL_SALT),
      iv: b64u(iv),
      ct: b64u(ct),
      seqFloor, // outer copy: client-local bookkeeping only
    },
  };
}

/**
 * Unwrap a `{prf: {...}}` escrow. Returns the SEALED `{key, seqFloor}`
 * — the outer seqFloor of a proxy-returned blob is untrusted and
 * deliberately ignored. Throws on any tampering (AES-GCM).
 */
export async function unwrapEscrow(prfOutput, escrow) {
  const arm = escrow?.prf;
  if (!arm) throw new Error("not a prf-arm escrow");
  const kek = await deriveKek(prfOutput);
  let pt;
  try {
    pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64u(arm.iv) },
      kek,
      unb64u(arm.ct),
    );
  } catch {
    throw new Error("escrow unwrap failed (wrong credential or tampered blob)");
  }
  const inner = JSON.parse(dec.decode(pt));
  if (typeof inner.key !== "string" || !Number.isSafeInteger(inner.seqFloor)) {
    throw new Error("escrow plaintext malformed");
  }
  return inner;
}
