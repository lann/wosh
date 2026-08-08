// Connection-string handling (M5, workstream D).
//
// Format v1 (per D8/M4): `1.<endpoint-id-hex>.<pairing-token>.<relay-url>`,
// dot-separated with the relay URL last so its own dots don't matter
// (split into at most 4 parts). The QR encodes
// `https://<site>/#<connstring>`; the fragment keeps the string out of
// HTTP logs. Pure module: no DOM, no storage — node-testable.

/** Parse a connection string. Throws with a user-legible message. */
export function parseConnstring(s) {
  if (typeof s !== "string") throw new Error("connection string missing");
  const trimmed = s.trim();
  if (!trimmed) throw new Error("connection string is empty");
  const parts = splitN(trimmed, ".", 4);
  if (parts.length !== 4) {
    throw new Error("malformed connection string (want 1.<id>.<token>.<relay-url>)");
  }
  const [version, idHex, token, relayUrl] = parts;
  if (version !== "1") {
    throw new Error(`unsupported connection string version ${JSON.stringify(version)}`);
  }
  if (!/^[0-9a-fA-F]{64}$/.test(idHex)) {
    throw new Error("endpoint id is not 32 bytes of hex");
  }
  if (!token) throw new Error("pairing token is empty");
  let relay;
  try {
    relay = new URL(relayUrl);
  } catch {
    throw new Error(`relay URL does not parse: ${relayUrl}`);
  }
  if (relay.protocol !== "http:" && relay.protocol !== "https:") {
    throw new Error(`relay URL must be http(s), got ${relay.protocol}`);
  }
  return {
    version: 1,
    endpointIdHex: idHex.toLowerCase(),
    token,
    relayUrl,
  };
}

/** Format the parse result back into a connection string. */
export function formatConnstring({ endpointIdHex, token, relayUrl }) {
  return `1.${endpointIdHex}.${token}.${relayUrl}`;
}

/**
 * Extract a connection string from a URL fragment (or a whole URL).
 * Accepts `#<cs>`, `<cs>`, or `https://site/path#<cs>`; percent-decodes
 * once (QR generators sometimes encode the fragment). Returns null when
 * there is nothing that looks like a connstring — callers decide
 * whether that is an error.
 */
export function connstringFromFragment(input) {
  if (typeof input !== "string") return null;
  let s = input.trim();
  const hash = s.indexOf("#");
  if (hash >= 0) {
    s = s.slice(hash + 1);
  } else if (/^https?:\/\//i.test(s)) {
    // A URL without a fragment carries no connection string; a raw
    // connstring never starts with a scheme (its relay URL is last).
    return null;
  }
  if (!s) return null;
  try {
    s = decodeURIComponent(s);
  } catch {
    // Not percent-encoded; use as-is.
  }
  return s || null;
}

/** Split into at most `n` parts (the last part keeps its separators). */
function splitN(s, sep, n) {
  const parts = [];
  let rest = s;
  while (parts.length < n - 1) {
    const i = rest.indexOf(sep);
    if (i < 0) break;
    parts.push(rest.slice(0, i));
    rest = rest.slice(i + 1);
  }
  parts.push(rest);
  return parts;
}
