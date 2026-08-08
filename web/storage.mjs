// Client-side persistent state (M5, workstream D).
//
// Schema v1, stored under one localStorage key as JSON:
//
//   { v: 1,
//     proxies: [{ endpointIdHex, relayUrl, direct?, name,
//                 addedAt, lastSeenAt }],
//     identityRef: null | { kind: "idb", name },
//     sessions: [{ proxyId, key, createdAt }] }
//
// A proxy's id IS its endpointIdHex (key = address, as in iroh).
// Pairing tokens are deliberately not persisted: they are first-contact
// credentials; a TOFU-accepted client reconnects on its endpoint key.
// Session `key` is a tagged variant (D4): `{ plain: { key, seqFloor } }`
// now, `{ prf: { credId, salt, iv, ct, seqFloor } }` from M6 — the
// seq-floor travels with the key because SSP replay protection and OCB
// nonce-reuse safety require every reattach to resume with a strictly
// larger datagram sequence (finding 13).
//
// Pure functions over an injected localStorage-like object; state
// values are treated as immutable (every mutator returns a new state).

export const STORAGE_KEY = "experiment-mosh/v1";

export function emptyState() {
  return { v: 1, proxies: [], identityRef: null, sessions: [] };
}

/**
 * Load state. Corrupt or absent data yields a fresh empty state; a
 * *newer* schema throws (do not silently clobber a future version).
 */
export function load(storage) {
  const raw = storage.getItem(STORAGE_KEY);
  if (!raw) return emptyState();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return emptyState();
  }
  if (!parsed || typeof parsed !== "object" || !Number.isInteger(parsed.v)) {
    return emptyState();
  }
  if (parsed.v > 1) {
    throw new Error(`stored state is schema v${parsed.v}; this client speaks v1`);
  }
  return {
    v: 1,
    proxies: Array.isArray(parsed.proxies) ? parsed.proxies : [],
    identityRef: parsed.identityRef ?? null,
    sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
  };
}

export function save(storage, state) {
  storage.setItem(STORAGE_KEY, JSON.stringify(state));
}

/**
 * Add or refresh a proxy entry (the explicit "save" acceptance).
 * Matches on endpointIdHex; a fresh entry gets addedAt, an existing one
 * keeps it and updates relay/direct/name.
 */
export function upsertProxy(state, { endpointIdHex, relayUrl, direct, name }, now = Date.now()) {
  if (!/^[0-9a-f]{64}$/.test(endpointIdHex)) {
    throw new Error("proxy endpointIdHex must be 64 lowercase hex chars");
  }
  const existing = state.proxies.find((p) => p.endpointIdHex === endpointIdHex);
  const proxy = {
    endpointIdHex,
    relayUrl,
    direct: direct ?? existing?.direct ?? null,
    name: name ?? existing?.name ?? `proxy-${endpointIdHex.slice(0, 8)}`,
    addedAt: existing?.addedAt ?? now,
    lastSeenAt: existing?.lastSeenAt ?? null,
  };
  return {
    state: {
      ...state,
      proxies: [
        ...state.proxies.filter((p) => p.endpointIdHex !== endpointIdHex),
        proxy,
      ],
    },
    proxy,
  };
}

/** Remove a proxy and any sessions bound to it. */
export function removeProxy(state, endpointIdHex) {
  return {
    ...state,
    proxies: state.proxies.filter((p) => p.endpointIdHex !== endpointIdHex),
    sessions: state.sessions.filter((s) => s.proxyId !== endpointIdHex),
  };
}

/** Mark a proxy as successfully contacted. */
export function touchProxy(state, endpointIdHex, now = Date.now()) {
  return {
    ...state,
    proxies: state.proxies.map((p) =>
      p.endpointIdHex === endpointIdHex ? { ...p, lastSeenAt: now } : p,
    ),
  };
}

/** Set the identity reference (the IndexedDB CryptoKey pointer). */
export function setIdentityRef(state, ref) {
  return { ...state, identityRef: ref };
}

/**
 * Record (or replace — v0 is one session per proxy) a persistent
 * session. `key` is the tagged variant described in the header.
 */
export function recordSession(state, { proxyId, key }, now = Date.now()) {
  assertKeyVariant(key);
  return {
    ...state,
    sessions: [
      ...state.sessions.filter((s) => s.proxyId !== proxyId),
      { proxyId, key, createdAt: now },
    ],
  };
}

export function dropSession(state, proxyId) {
  return {
    ...state,
    sessions: state.sessions.filter((s) => s.proxyId !== proxyId),
  };
}

/**
 * Raise a session's sequence floor (finding 13: bumped strictly
 * forward, with margin, on every attach). No-op if the session is
 * absent; throws if the floor would move backwards.
 */
export function bumpSeqFloor(state, proxyId, floor) {
  return {
    ...state,
    sessions: state.sessions.map((s) => {
      if (s.proxyId !== proxyId) return s;
      const arm = s.key.plain ?? s.key.prf;
      if (floor < arm.seqFloor) {
        throw new Error(`seq floor may only move forward (${arm.seqFloor} → ${floor})`);
      }
      const bumped = { ...arm, seqFloor: floor };
      return { ...s, key: s.key.plain ? { plain: bumped } : { prf: bumped } };
    }),
  };
}

function assertKeyVariant(key) {
  const arms = ["plain", "prf"].filter((a) => key && typeof key === "object" && a in key);
  if (arms.length !== 1) {
    throw new Error("session key must be exactly one of { plain, prf }");
  }
  const arm = key[arms[0]];
  if (!Number.isSafeInteger(arm.seqFloor) || arm.seqFloor < 0) {
    throw new Error("session key variant must carry a non-negative seqFloor");
  }
}
