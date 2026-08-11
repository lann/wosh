// Passkey ceremonies from the page (M6 browser leg, workstream E).
//
// The proxy's webauthn-rs RP speaks the standard WebAuthn JSON wire
// format (challenges and credential ids base64url-encoded);
// PublicKeyCredential.parse*FromJSON / toJSON marshal it to and from
// the buffer-shaped browser API. The PRF extension never crosses the
// wire: the page adds it to the ceremony options client-side, and the
// PRF *outputs* are stripped from responses before they reach the RP —
// they seed the KEK that seals the escrow (prf-wrap.mjs), so handing
// them to the proxy would defeat the D4 PRF arm.
//
// Ceremony calls go through CredentialsContainer.prototype — password
// managers wrap navigator.credentials and break ceremonies with
// non-WebAuthn errors (M0 finding 6).
//
// Reattach runs ONE get(): the same assertion that convinces the RP
// carries the PRF evaluation that unwraps the escrow — one user
// gesture, both outputs.

import {
  FLOOR_JUMP,
  SEQ_MARGIN,
  assertPersistencePermitted,
  prfExtensionForCreate,
  prfExtensionForGet,
  probePrfCapability,
  unwrapEscrow,
  wrapEscrow,
} from "./prf-wrap.mjs";

const enc = new TextEncoder();
const dec = new TextDecoder();

const create = (opts) => CredentialsContainer.prototype.create.call(navigator.credentials, opts);
const get = (opts) => CredentialsContainer.prototype.get.call(navigator.credentials, opts);

const parseChallenge = (bytes) => JSON.parse(dec.decode(new Uint8Array(bytes)));

/** Response wire shape, PRF outputs withheld (see header). */
const responseJson = (cred) => {
  const r = cred.toJSON();
  r.clientExtensionResults = {};
  return enc.encode(JSON.stringify(r));
};

/**
 * Register a passkey for the live session: register-start → create()
 * (PRF requested; D4 sub-policy enforced) → register-finish. Returns
 * the raw credential id.
 */
async function registerPasskey(session) {
  const ccr = parseChallenge(await session.registerStart());
  const options = PublicKeyCredential.parseCreationOptionsFromJSON(ccr.publicKey);
  options.extensions = { ...options.extensions, ...prfExtensionForCreate() };
  const cred = await create({ publicKey: options });
  // The authoritative per-credential gate (D4); the client-capability
  // probe only shades the error copy (issue #13 — on a PRF-capable
  // browser the actionable retry is "pick a different authenticator").
  assertPersistencePermitted(
    cred.getClientExtensionResults().prf?.enabled === true,
    await probePrfCapability(),
  );
  await session.registerFinish(responseJson(cred));
  return new Uint8Array(cred.rawId);
}

/**
 * Evaluate the credential's PRF with a local, self-challenged get()
 * (registration cannot evaluate; the persist path needs one output to
 * seal the first escrow).
 */
async function evalPrf(credIdBytes) {
  const assertion = await get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: "public-key", id: credIdBytes }],
      userVerification: "required",
      extensions: prfExtensionForGet(),
    },
  });
  const out = assertion.getClientExtensionResults().prf?.results?.first;
  if (!out || out.byteLength !== 32) {
    throw new Error("PRF evaluation failed (authenticator enabled prf at create but returned no output)");
  }
  return new Uint8Array(out);
}

/**
 * Make the live session persistent: registration ceremony → PRF-wrap
 * {key, seqFloor} → escrow on the proxy. Returns the `{prf:{...}}`
 * storage arm and the proxy session id (storage.mjs recordSession
 * shape).
 */
export async function persistSession(session) {
  const credId = await registerPasskey(session);
  const prfOut = await evalPrf(credId);
  const key = await session.sessionKey();
  const stats = await session.stats();
  const escrow = await wrapEscrow(prfOut, { key, seqFloor: Number(stats.currentSeq) }, credId);
  await session.makePersistent(enc.encode(JSON.stringify(escrow)));
  const sessionId = await session.sessionId();
  if (sessionId === undefined || sessionId === null) {
    throw new Error("proxy session id missing (dial-path sessions cannot persist)");
  }
  return { escrow, sessionId: Number(sessionId) };
}

/**
 * The reattach ceremony: begin → RP challenge → one get() (assertion +
 * PRF output) → finish returns the escrow → unwrap (the SEALED floor
 * is authoritative — finding 21) → attach strictly above it → re-seal
 * at floor+FLOOR_JUMP and re-escrow over the live control channel
 * (the prf-wrap floor-jump policy: the sealed floor can only move
 * while the KEK is derivable, i.e. right now). Returns the live
 * session and the fresh storage arm.
 */
export async function reattachSession(client, { relayUrl, endpointIdHex, token, sessionId }, cols, rows) {
  const flow = await client.ReattachFlow.begin(
    relayUrl,
    endpointIdHex,
    undefined,
    token,
    BigInt(sessionId),
  );
  const rcr = parseChallenge(await flow.challenge());
  const options = PublicKeyCredential.parseRequestOptionsFromJSON(rcr.publicKey);
  options.extensions = { ...options.extensions, ...prfExtensionForGet() };
  const assertion = await get({ publicKey: options });
  const prfOut = assertion.getClientExtensionResults().prf?.results?.first;
  if (!prfOut || prfOut.byteLength !== 32) {
    // Name the actual cause (issue #13): "different authenticator?"
    // was misleading on a browser that can never return PRF output.
    throw new Error(
      (await probePrfCapability()) === "yes"
        ? "no PRF output at reattach (different authenticator than the one " +
          "that persisted this session?)"
        : "no PRF output at reattach — this browser may not support the " +
          "WebAuthn prf extension (reattach from a PRF-capable browser)",
    );
  }
  const escrowBack = await flow.finish(responseJson(assertion));
  const returned = JSON.parse(dec.decode(new Uint8Array(escrowBack)));
  const inner = await unwrapEscrow(new Uint8Array(prfOut), returned);

  const session = await flow.attach(inner.key, BigInt(inner.seqFloor + SEQ_MARGIN), cols, rows);

  const newFloor = inner.seqFloor + FLOOR_JUMP;
  const escrow = await wrapEscrow(
    new Uint8Array(prfOut),
    { key: inner.key, seqFloor: newFloor },
    // The signing credential's own id — never the returned blob's
    // outer credId (everything outside `ct` is proxy-controlled).
    new Uint8Array(assertion.rawId),
  );
  await session.makePersistent(enc.encode(JSON.stringify(escrow)));
  return { session, escrow };
}
