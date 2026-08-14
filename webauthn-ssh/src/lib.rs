//! The WebAuthn-to-SSH wire mapping.
//!
//! A browser passkey can be an SSH key. OpenSSH has accepted
//! browser-made WebAuthn assertions as publickey credentials since
//! 8.4, under the signature algorithm
//! `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`. The target needs an
//! ordinary `authorized_keys` line and nothing else installed. This
//! crate is the translation layer that makes that true: it turns a
//! credential into the line, and an assertion into the signature the
//! line verifies.
//!
//! One server-configuration caveat, worth knowing before debugging
//! anything here: only OpenSSH 10.3 and later put that algorithm in
//! the default `PubkeyAcceptedAlgorithms` (upstream enabled it in
//! February 2026). Releases from 8.4 to 10.2 can verify these
//! signatures but refuse the offer before looking at one, which is a
//! server-side "no", not a wire-format bug -- sshd says so plainly at
//! `LogLevel VERBOSE`, and the fix is
//! `PubkeyAcceptedAlgorithms +webauthn-sk-ecdsa-sha2-nistp256@openssh.com`.
//!
//! It is a separate crate, and free of any component or WebAuthn
//! plumbing, for one reason: every rule enforced here is a rule the
//! SERVER enforces, several round trips away, with an error message
//! that says only "authentication failed". Wire-format mistakes are
//! therefore the expensive kind, and the cure is to make them
//! ordinary unit tests. Everything below either encodes a byte layout
//! or refuses a shape sshd would refuse.
//!
//! # The layouts
//!
//! The public key blob is a plain security-key key -- the same one
//! `ssh-keygen` would write for a hardware token (PROTOCOL.u2f):
//!
//! ```text
//! string  "sk-ecdsa-sha2-nistp256@openssh.com"
//! string  "nistp256"
//! string  Q             -- uncompressed point, 0x04 || X || Y
//! string  application
//! ```
//!
//! The signature adds the webauthn fields after the usual two:
//!
//! ```text
//! string  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
//! string  ecdsa_signature      -- mpint r, mpint s
//! byte    flags
//! uint32  counter
//! string  origin
//! string  clientData
//! string  extensions
//! ```
//!
//! # Two things that are counter-intuitive and load-bearing
//!
//! **The key and the signature have different algorithm names.** The
//! key blob says `sk-ecdsa-sha2-nistp256@openssh.com`; the userauth
//! request and the signature say
//! `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`. Both names resolve
//! to the same key type on the server, but sshd compares the name it
//! was offered against the name inside the signature, so offering the
//! key under its own name and then signing as webauthn is rejected.
//!
//! **`application` is the web origin's domain, not `ssh:`.** The
//! authenticator signs over `sha256(rp_id)`, and sshd reconstructs
//! that hash from whatever string sits in the `application` field of
//! the key. So the identity is stamped with the site that minted it:
//! a clone of the page on another domain cannot use the same line.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;

/// The key type that goes in `authorized_keys` and inside the key blob.
pub const SK_ECDSA_KEY_TYPE: &str = "sk-ecdsa-sha2-nistp256@openssh.com";

/// The signature algorithm the userauth request and the signature carry.
pub const WEBAUTHN_SK_ECDSA_ALGORITHM: &str = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";

/// The curve name inside an ECDSA key blob (RFC 5656 s10).
const NISTP256: &str = "nistp256";

/// The Ed25519 key type, for the browser's own WebCrypto identity.
pub const SSH_ED25519_KEY_TYPE: &str = "ssh-ed25519";

/// An uncompressed NIST P-256 point: `0x04 || X || Y`.
pub const P256_POINT_LEN: usize = 65;

/// A raw Ed25519 public key.
pub const ED25519_KEY_LEN: usize = 32;

/// Authenticator data is at least the RP-ID hash, the flags byte, and
/// the counter; anything after that is extension output.
const AUTH_DATA_MIN: usize = 32 + 1 + 4;

/// "User present" -- the authenticator saw a deliberate human act.
/// sshd requires it unless `authorized_keys` says `no-touch-required`.
const FLAG_USER_PRESENT: u8 = 0x01;
/// "Attested credential data present" -- a registration-shaped
/// response. sshd refuses to verify one.
const FLAG_ATTESTED_CRED_DATA: u8 = 0x40;
/// "Extension data present" -- must agree with whether any extension
/// bytes actually follow.
const FLAG_EXTENSION_DATA: u8 = 0x80;

/// The fixed head of the JSON the browser signs. sshd does not parse
/// this structure; it rebuilds this exact prefix and compares bytes,
/// which is why every byte of it is a contract.
const CLIENT_DATA_PREFIX: &str = "{\"type\":\"webauthn.get\",\"challenge\":\"";
const CLIENT_DATA_ORIGIN: &str = "\",\"origin\":\"";

/// Everything that can be wrong on the way from an assertion to a
/// signature. Each variant names a rule the server would otherwise
/// enforce silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A public key was not the length its algorithm requires.
    KeyLength { expected: usize, got: usize },
    /// A P-256 point was not in uncompressed form.
    PointNotUncompressed { first: u8 },
    /// `authenticator-data` was too short to hold the fixed fields.
    AuthenticatorDataShort { got: usize },
    /// The response carried attested credential data (a registration
    /// response, not an assertion). sshd refuses these outright.
    AttestedCredentialData,
    /// The extension-data flag disagreed with the bytes present.
    ExtensionFlagMismatch { flag_set: bool, bytes: usize },
    /// The authenticator did not record a human act.
    NoUserPresence,
    /// `clientDataJSON` did not have the shape sshd reconstructs. The
    /// most likely cause is a browser that serializes the fields in
    /// another order, or a challenge that was hashed or re-encoded on
    /// the way in.
    ClientDataShape,
    /// `clientDataJSON` was not valid UTF-8, so no origin could be read.
    ClientDataNotUtf8,
    /// The signature was not a well-formed ECDSA-Sig-Value.
    MalformedSignature(&'static str),
    /// An `authorized_keys` line could not be read back.
    MalformedLine(&'static str),
    /// Recovery was given fewer than two assertions to intersect.
    RecoveryNeedsTwo { got: usize },
    /// The assertions have no key in common. Either they came from
    /// DIFFERENT credentials -- the ordinary cause, and the one a user
    /// can act on -- or one of them does not sign the data it carries.
    RecoveryFoundNothing,
    /// The assertions did not agree on a single key. Either they came
    /// from different credentials, or -- vanishingly unlikely -- they
    /// were made over the same message and so carry the same ambiguity.
    RecoveryAmbiguous { candidates: usize },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::KeyLength { expected, got } => {
                write!(f, "public key is {got} bytes, expected {expected}")
            }
            Error::PointNotUncompressed { first } => write!(
                f,
                "public key is not an uncompressed point (leading byte 0x{first:02x}, expected 0x04)"
            ),
            Error::AuthenticatorDataShort { got } => write!(
                f,
                "authenticator data is {got} bytes, expected at least {AUTH_DATA_MIN}"
            ),
            Error::AttestedCredentialData => f.write_str(
                "the assertion carries attested credential data, which sshd refuses to verify",
            ),
            Error::ExtensionFlagMismatch { flag_set, bytes } => write!(
                f,
                "the extension-data flag is {} but {bytes} extension bytes are present",
                if *flag_set { "set" } else { "clear" }
            ),
            Error::NoUserPresence => f.write_str(
                "the authenticator did not report user presence; sshd rejects untouched signatures",
            ),
            Error::ClientDataShape => f.write_str(
                "clientDataJSON is not shaped the way sshd reconstructs it \
                 (type, then the challenge verbatim, then the origin)",
            ),
            Error::ClientDataNotUtf8 => f.write_str("clientDataJSON is not valid UTF-8"),
            Error::MalformedSignature(why) => write!(f, "malformed ECDSA signature: {why}"),
            Error::MalformedLine(why) => write!(f, "malformed authorized_keys line: {why}"),
            Error::RecoveryNeedsTwo { got } => write!(
                f,
                "recovering a public key takes at least two assertions, got {got}"
            ),
            Error::RecoveryFoundNothing => f.write_str(
                "no one key fits all these assertions -- they are from different passkeys, \
                 or one of them does not sign what it carries",
            ),
            Error::RecoveryAmbiguous { candidates } => write!(
                f,
                "the assertions do not agree on one key ({candidates} fit them all) -- \
                 they are most likely from different passkeys"
            ),
        }
    }
}

/// One WebAuthn assertion, exactly as the ceremony produced it.
#[derive(Debug, Clone, Copy)]
pub struct Assertion<'a> {
    /// `authenticatorData`: the RP-ID hash, flags, counter, and any
    /// extension output.
    pub authenticator_data: &'a [u8],
    /// `clientDataJSON`, byte for byte. Re-serializing it breaks
    /// authentication: sshd hashes exactly these bytes.
    pub client_data_json: &'a [u8],
    /// The ECDSA signature, in the ASN.1 DER form WebAuthn returns.
    pub signature: &'a [u8],
}

/// An SSH signature in the three parts the wire format is built from,
/// matching the `signature` record of `wosh:ssh-core/core`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSignature {
    pub format: String,
    pub blob: Vec<u8>,
    pub trailer: Vec<u8>,
}

// --- SSH encoding primitives -------------------------------------------

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Read a length-prefixed string, returning it and the rest.
fn take_string(input: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if input.len() < 4 {
        return Err(Error::MalformedLine("truncated length prefix"));
    }
    let (len_bytes, rest) = input.split_at(4);
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    if rest.len() < len {
        return Err(Error::MalformedLine("string runs past the end of the blob"));
    }
    Ok(rest.split_at(len))
}

// --- public keys -------------------------------------------------------

/// The `sk-ecdsa-sha2-nistp256@openssh.com` public key blob for a
/// passkey: its uncompressed P-256 point, and the relying-party id as
/// the `application`.
pub fn sk_ecdsa_key_blob(point: &[u8], application: &str) -> Result<Vec<u8>, Error> {
    if point.len() != P256_POINT_LEN {
        return Err(Error::KeyLength {
            expected: P256_POINT_LEN,
            got: point.len(),
        });
    }
    if point[0] != 0x04 {
        return Err(Error::PointNotUncompressed { first: point[0] });
    }
    let mut blob = Vec::with_capacity(4 + SK_ECDSA_KEY_TYPE.len() + 4 + NISTP256.len() + 4 + point.len() + 4 + application.len());
    put_string(&mut blob, SK_ECDSA_KEY_TYPE.as_bytes());
    put_string(&mut blob, NISTP256.as_bytes());
    put_string(&mut blob, point);
    put_string(&mut blob, application.as_bytes());
    Ok(blob)
}

/// The `ssh-ed25519` public key blob for a raw 32-byte key.
pub fn ed25519_key_blob(raw: &[u8]) -> Result<Vec<u8>, Error> {
    if raw.len() != ED25519_KEY_LEN {
        return Err(Error::KeyLength {
            expected: ED25519_KEY_LEN,
            got: raw.len(),
        });
    }
    let mut blob = Vec::with_capacity(4 + SSH_ED25519_KEY_TYPE.len() + 4 + raw.len());
    put_string(&mut blob, SSH_ED25519_KEY_TYPE.as_bytes());
    put_string(&mut blob, raw);
    Ok(blob)
}

/// An `authorized_keys` line: the key type, the base64 of the blob,
/// and a comment. This is the whole installation procedure on the
/// target -- there is nothing else to deploy.
pub fn authorized_keys_line(key_type: &str, blob: &[u8], comment: &str) -> String {
    format!("{key_type} {} {comment}", STANDARD.encode(blob))
}

/// Read a passkey `authorized_keys` line back into its point and
/// relying-party id -- the second-device path, where the credential is
/// reachable but its public half has to be carried over by hand.
pub fn parse_passkey_line(line: &str) -> Result<(Vec<u8>, String), Error> {
    let mut fields = line.split_ascii_whitespace();
    let key_type = fields
        .next()
        .ok_or(Error::MalformedLine("the line is empty"))?;
    if key_type != SK_ECDSA_KEY_TYPE {
        return Err(Error::MalformedLine(
            "not a sk-ecdsa-sha2-nistp256@openssh.com key",
        ));
    }
    let encoded = fields
        .next()
        .ok_or(Error::MalformedLine("the line has no key blob"))?;
    let blob = STANDARD
        .decode(encoded)
        .map_err(|_| Error::MalformedLine("the key blob is not valid base64"))?;

    let (name, rest) = take_string(&blob)?;
    if name != SK_ECDSA_KEY_TYPE.as_bytes() {
        return Err(Error::MalformedLine(
            "the blob's own type does not match the line's",
        ));
    }
    let (curve, rest) = take_string(rest)?;
    if curve != NISTP256.as_bytes() {
        return Err(Error::MalformedLine("the key is not on nistp256"));
    }
    let (point, rest) = take_string(rest)?;
    if point.len() != P256_POINT_LEN {
        return Err(Error::KeyLength {
            expected: P256_POINT_LEN,
            got: point.len(),
        });
    }
    if point[0] != 0x04 {
        return Err(Error::PointNotUncompressed { first: point[0] });
    }
    let (application, rest) = take_string(rest)?;
    if !rest.is_empty() {
        return Err(Error::MalformedLine("trailing bytes after the key blob"));
    }
    let application =
        String::from_utf8(application.to_vec()).map_err(|_| Error::MalformedLine("the application field is not UTF-8"))?;
    Ok((point.to_vec(), application))
}

// --- assertions --------------------------------------------------------

/// Turn one assertion into the SSH signature that answers `challenge`.
///
/// `challenge` is the signature blob the SSH core parked on -- the same
/// bytes the ceremony was given. They are re-derived here rather than
/// trusted: the browser embeds them, base64url-encoded, in the JSON it
/// signed, so comparing proves the ceremony answered THIS request and
/// not a stale one.
pub fn signature_from_assertion(
    assertion: Assertion<'_>,
    challenge: &[u8],
) -> Result<SshSignature, Error> {
    let auth_data = assertion.authenticator_data;
    if auth_data.len() < AUTH_DATA_MIN {
        return Err(Error::AuthenticatorDataShort {
            got: auth_data.len(),
        });
    }
    let flags = auth_data[32];
    let counter = &auth_data[33..AUTH_DATA_MIN];
    let extensions = &auth_data[AUTH_DATA_MIN..];

    // sshd checks all three of these itself; failing here instead
    // turns a bare "authentication failed" into a sentence.
    if flags & FLAG_ATTESTED_CRED_DATA != 0 {
        return Err(Error::AttestedCredentialData);
    }
    let ed_set = flags & FLAG_EXTENSION_DATA != 0;
    if ed_set != !extensions.is_empty() {
        return Err(Error::ExtensionFlagMismatch {
            flag_set: ed_set,
            bytes: extensions.len(),
        });
    }
    if flags & FLAG_USER_PRESENT == 0 {
        return Err(Error::NoUserPresence);
    }

    let origin = client_data_origin(assertion.client_data_json, challenge)?;
    let (r, s) = ecdsa_der_parts(assertion.signature)?;

    // The two mpints are the CONTENTS of the `ecdsa_signature` string;
    // the length prefix around them is added by the SSH core when it
    // marshals the signature. A DER INTEGER's content is already
    // minimal two's-complement big-endian, which is exactly what an
    // mpint is, so the bytes carry over untouched.
    let mut blob = Vec::with_capacity(8 + r.len() + s.len());
    put_string(&mut blob, r);
    put_string(&mut blob, s);

    let mut trailer = Vec::with_capacity(
        1 + 4 + 4 + origin.len() + 4 + assertion.client_data_json.len() + 4 + extensions.len(),
    );
    trailer.push(flags);
    trailer.extend_from_slice(counter);
    put_string(&mut trailer, origin.as_bytes());
    put_string(&mut trailer, assertion.client_data_json);
    put_string(&mut trailer, extensions);

    Ok(SshSignature {
        format: WEBAUTHN_SK_ECDSA_ALGORITHM.to_string(),
        blob,
        trailer,
    })
}

/// Check `clientDataJSON` against the prefix sshd rebuilds, and read
/// the origin out of its canonical position.
///
/// The origin is extracted from the JSON rather than supplied
/// separately on purpose: sshd puts the origin field of the signature
/// back into the reconstructed prefix and compares, so the two must
/// agree byte for byte, and taking both from one source makes that
/// impossible to get wrong.
fn client_data_origin(client_data: &[u8], challenge: &[u8]) -> Result<String, Error> {
    let mut head = String::with_capacity(CLIENT_DATA_PREFIX.len() + 4 * challenge.len() / 3 + CLIENT_DATA_ORIGIN.len());
    head.push_str(CLIENT_DATA_PREFIX);
    head.push_str(&URL_SAFE_NO_PAD.encode(challenge));
    head.push_str(CLIENT_DATA_ORIGIN);

    let rest = client_data
        .strip_prefix(head.as_bytes())
        .ok_or(Error::ClientDataShape)?;
    let end = rest
        .iter()
        .position(|&b| b == b'"')
        .ok_or(Error::ClientDataShape)?;
    // Everything after the origin -- crossOrigin, and whatever a
    // browser adds later -- is ignored, by sshd and here alike.
    String::from_utf8(rest[..end].to_vec()).map_err(|_| Error::ClientDataNotUtf8)
}

/// Split an `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
/// into its two integer contents, rejecting anything that is not
/// canonical DER. The strictness is deliberate: the values are copied
/// verbatim into mpints, and SSH's mpint encoding has exactly DER's
/// canonical form, so a lax parse here would produce a signature the
/// server rejects for a reason the client never sees.
fn ecdsa_der_parts(der: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let (body, rest) = der_take(der, 0x30, "expected a SEQUENCE")?;
    if !rest.is_empty() {
        return Err(Error::MalformedSignature("trailing bytes after the SEQUENCE"));
    }
    let (r, rest) = der_take(body, 0x02, "expected an INTEGER for r")?;
    let (s, rest) = der_take(rest, 0x02, "expected an INTEGER for s")?;
    if !rest.is_empty() {
        return Err(Error::MalformedSignature("trailing bytes after s"));
    }
    check_der_integer(r, "r")?;
    check_der_integer(s, "s")?;
    Ok((r, s))
}

/// Take one DER element of the expected tag, returning its content and
/// what follows. Only the short form and the one-byte long form are
/// accepted -- an ECDSA-P256 signature never needs more.
fn der_take<'a>(input: &'a [u8], tag: u8, why: &'static str) -> Result<(&'a [u8], &'a [u8]), Error> {
    if input.first() != Some(&tag) {
        return Err(Error::MalformedSignature(why));
    }
    let after_tag = &input[1..];
    let (len, content) = match after_tag.split_first() {
        None => return Err(Error::MalformedSignature("truncated length")),
        Some((&first, rest)) if first < 0x80 => (first as usize, rest),
        Some((&first, rest)) if first == 0x81 => match rest.split_first() {
            Some((&len, rest)) if len >= 0x80 => (len as usize, rest),
            Some(_) => {
                return Err(Error::MalformedSignature(
                    "non-minimal length encoding",
                ))
            }
            None => return Err(Error::MalformedSignature("truncated long-form length")),
        },
        Some(_) => return Err(Error::MalformedSignature("length is implausibly large")),
    };
    if content.len() < len {
        return Err(Error::MalformedSignature("element runs past the end"));
    }
    Ok(content.split_at(len))
}

fn check_der_integer(value: &[u8], which: &'static str) -> Result<(), Error> {
    match value.first() {
        None => Err(Error::MalformedSignature(if which == "r" {
            "r is empty"
        } else {
            "s is empty"
        })),
        // A high bit means a negative two's-complement value, which no
        // ECDSA scalar is.
        Some(&first) if first & 0x80 != 0 => Err(Error::MalformedSignature(if which == "r" {
            "r is negative"
        } else {
            "s is negative"
        })),
        // A leading zero is legal only to keep a value positive. The
        // one encoding this also rejects, `00` alone, is canonical DER
        // for zero -- which is not a value an ECDSA scalar can take, so
        // refusing it here costs nothing and saves a server round trip.
        Some(&0x00) if !matches!(value.get(1), Some(&b) if b & 0x80 != 0) => {
            Err(Error::MalformedSignature(if which == "r" {
                "r is zero, or has a non-canonical leading zero"
            } else {
                "s is zero, or has a non-canonical leading zero"
            }))
        }
        Some(_) => Ok(()),
    }
}

// --- recovering the public key --------------------------------------
//
// The problem this solves is narrow and specific. A WebAuthn assertion
// does not carry the credential's public key, and there is nowhere in
// the credential to keep one (the user handle is fixed at
// registration, before the key exists). So a client that loses its
// browser storage -- eviction, cleared site data, a private window --
// still HAS the passkey and can still sign with it, but has lost the
// one thing SSH must put on the wire.
//
// It is recoverable from the signatures themselves. ECDSA verification
// reconstructs a point from `r`; running that backwards yields the
// small set of public keys under which a given signature is valid --
// at most two in practice, since `r` fixes the x coordinate and only
// the sign of y is unknown. Two assertions from the same credential
// have exactly one key in common: its own.
//
// Nothing secret is involved. The inputs are signatures the server
// would have seen anyway, the output is a public key, and there is no
// value to be timing-safe about -- which is also why this leans on
// `p256` rather than open-coding the point arithmetic: the code is
// easy to get subtly wrong on rare inputs and there is no reason to.

/// Recover the credential's public key from assertions it produced,
/// as an uncompressed P-256 point (65 bytes).
///
/// Give it at least two assertions **from the same credential**, over
/// DIFFERENT messages. Different matters: an authenticator may sign
/// deterministically and may report a zero counter, so two ceremonies
/// over the same challenge can produce byte-identical signatures --
/// and identical signatures carry identical ambiguity, which no amount
/// of intersecting resolves. That case is refused, not guessed at.
///
/// Assertions from different credentials are refused the same way: the
/// intersection is empty, or (astronomically unlikely) larger than
/// one. Either way this returns an error rather than a key, so a user
/// who picks two different passkeys is told so instead of being handed
/// an identity that fails at the server.
pub fn recover_public_key(assertions: &[Assertion<'_>]) -> Result<Vec<u8>, Error> {
    if assertions.len() < 2 {
        return Err(Error::RecoveryNeedsTwo {
            got: assertions.len(),
        });
    }

    let mut common: Option<Vec<Vec<u8>>> = None;
    for assertion in assertions {
        let candidates = recover_candidates(*assertion)?;
        common = Some(match common {
            None => candidates,
            Some(prev) => prev
                .into_iter()
                .filter(|key| candidates.contains(key))
                .collect(),
        });
    }

    let mut common = common.unwrap_or_default();
    match common.len() {
        1 => Ok(common.remove(0)),
        0 => Err(Error::RecoveryFoundNothing),
        n => Err(Error::RecoveryAmbiguous { candidates: n }),
    }
}

/// Every public key under which one assertion verifies.
///
/// The recovery id is not transmitted by WebAuthn, so all four are
/// tried and each result is checked back against the signature. That
/// check is what makes the set trustworthy: a candidate is kept only
/// if the assertion genuinely verifies under it.
fn recover_candidates(assertion: Assertion<'_>) -> Result<Vec<Vec<u8>>, Error> {
    use ecdsa::RecoveryId;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    // What ECDSA signed: the authenticator data followed by the hash of
    // the client data, hashed again. Rebuilt here from the assertion's
    // own bytes, so a candidate can only survive if the signature
    // really covers the material we were handed.
    let prehash = webauthn_prehash(&assertion);

    // The DER parse is the strict one used for the wire format, so a
    // signature that could not be relayed cannot be recovered from
    // either -- one notion of well-formed, not two.
    let (r, s) = ecdsa_der_parts(assertion.signature)?;
    let signature = Signature::from_scalars(
        pad32(r).ok_or(Error::MalformedSignature("r is wider than the curve"))?,
        pad32(s).ok_or(Error::MalformedSignature("s is wider than the curve"))?,
    )
    .map_err(|_| Error::MalformedSignature("r or s is not a valid scalar"))?;

    // All four, because WebAuthn does not transmit the recovery id.
    // Two of them describe an x coordinate past the curve order, which
    // essentially never occurs and simply fails to decompress; the
    // verify-back below is what makes the surviving set trustworthy
    // rather than merely plausible.
    let mut found: Vec<Vec<u8>> = Vec::new();
    for (is_x_reduced, is_y_odd) in [(false, false), (false, true), (true, false), (true, true)] {
        let recovery_id = RecoveryId::new(is_y_odd, is_x_reduced);
        let Ok(key) = VerifyingKey::recover_from_prehash(&prehash, &signature, recovery_id) else {
            continue;
        };
        if key.verify_prehash(&prehash, &signature).is_err() {
            continue;
        }
        let point = key.to_encoded_point(false).as_bytes().to_vec();
        if !found.contains(&point) {
            found.push(point);
        }
    }
    Ok(found)
}

/// Whether an assertion was really made for `rp_id`.
///
/// The authenticator opens its signed data with `sha256(rp-id)`, and
/// that same string becomes the `application` field of the
/// `authorized_keys` line -- so a wrong one produces a line that can
/// never verify, days after anyone would connect it to this moment.
/// Comparing the hash costs nothing and catches it here.
pub fn asserted_for_rp(assertion: Assertion<'_>, rp_id: &str) -> bool {
    use sha2::{Digest, Sha256};
    assertion.authenticator_data.len() >= 32
        && assertion.authenticator_data[..32] == Sha256::digest(rp_id.as_bytes())[..]
}

/// `sha256(authenticator-data || sha256(client-data-json))` -- the
/// digest an ES256 WebAuthn signature is made over.
fn webauthn_prehash(assertion: &Assertion<'_>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let client_data_hash = Sha256::digest(assertion.client_data_json);
    let mut outer = Sha256::new();
    outer.update(assertion.authenticator_data);
    outer.update(client_data_hash);
    outer.finalize().into()
}

/// Left-pad a canonical (leading-zero-trimmed) scalar to the curve's
/// fixed 32-byte width.
fn pad32(value: &[u8]) -> Option<p256::FieldBytes> {
    let value = match value {
        // The one leading zero DER adds to keep a high value positive.
        [0x00, rest @ ..] => rest,
        other => other,
    };
    if value.len() > 32 {
        return None;
    }
    let mut out = p256::FieldBytes::default();
    out[32 - value.len()..].copy_from_slice(value);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An obviously-synthetic P-256 point: uncompressed marker then a
    /// counting pattern. Nothing here verifies a signature, so the
    /// coordinates only have to be the right shape.
    fn synthetic_point() -> Vec<u8> {
        let mut p = vec![0x04];
        p.extend((0u8..64).map(|i| i.wrapping_mul(3)));
        p
    }

    fn client_data(challenge: &[u8], origin: &str) -> Vec<u8> {
        format!(
            "{CLIENT_DATA_PREFIX}{}{CLIENT_DATA_ORIGIN}{origin}\",\"crossOrigin\":false}}",
            URL_SAFE_NO_PAD.encode(challenge)
        )
        .into_bytes()
    }

    fn auth_data(flags: u8, counter: u32, extensions: &[u8]) -> Vec<u8> {
        let mut d = vec![0xAA; 32];
        d.push(flags);
        d.extend_from_slice(&counter.to_be_bytes());
        d.extend_from_slice(extensions);
        d
    }

    /// A DER SEQUENCE of two INTEGERs, built by hand so the tests own
    /// the encoding they assert on.
    fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        for v in [r, s] {
            body.push(0x02);
            body.push(v.len() as u8);
            body.extend_from_slice(v);
        }
        let mut out = vec![0x30];
        if body.len() < 0x80 {
            out.push(body.len() as u8);
        } else {
            out.push(0x81);
            out.push(body.len() as u8);
        }
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn key_blob_has_the_four_fields_openssh_expects() {
        let point = synthetic_point();
        let blob = sk_ecdsa_key_blob(&point, "wosh.example").unwrap();

        let (name, rest) = take_string(&blob).unwrap();
        assert_eq!(name, SK_ECDSA_KEY_TYPE.as_bytes());
        let (curve, rest) = take_string(rest).unwrap();
        assert_eq!(curve, b"nistp256");
        let (q, rest) = take_string(rest).unwrap();
        assert_eq!(q, &point[..]);
        let (application, rest) = take_string(rest).unwrap();
        assert_eq!(application, b"wosh.example");
        assert!(rest.is_empty());
    }

    #[test]
    fn the_key_blob_keeps_its_own_name_not_the_webauthn_one() {
        // The distinction the server enforces: the blob is a plain
        // security-key key even though the signature that answers for
        // it is webauthn-shaped.
        let blob = sk_ecdsa_key_blob(&synthetic_point(), "wosh.example").unwrap();
        let (name, _) = take_string(&blob).unwrap();
        assert_ne!(name, WEBAUTHN_SK_ECDSA_ALGORITHM.as_bytes());
        assert_eq!(name, SK_ECDSA_KEY_TYPE.as_bytes());
    }

    #[test]
    fn a_line_round_trips_through_parsing() {
        let point = synthetic_point();
        let blob = sk_ecdsa_key_blob(&point, "wosh.example").unwrap();
        let line = authorized_keys_line(SK_ECDSA_KEY_TYPE, &blob, "wosh-passkey");
        assert!(line.starts_with("sk-ecdsa-sha2-nistp256@openssh.com "));
        assert!(line.ends_with(" wosh-passkey"));

        let (back_point, application) = parse_passkey_line(&line).unwrap();
        assert_eq!(back_point, point);
        assert_eq!(application, "wosh.example");
    }

    #[test]
    fn a_line_without_a_comment_still_parses() {
        let blob = sk_ecdsa_key_blob(&synthetic_point(), "wosh.example").unwrap();
        let line = format!("{SK_ECDSA_KEY_TYPE} {}", STANDARD.encode(&blob));
        assert!(parse_passkey_line(&line).is_ok());
    }

    #[test]
    fn an_ed25519_line_is_refused_as_a_passkey() {
        let blob = ed25519_key_blob(&[7; 32]).unwrap();
        let line = authorized_keys_line(SSH_ED25519_KEY_TYPE, &blob, "wosh-browser");
        assert!(matches!(
            parse_passkey_line(&line),
            Err(Error::MalformedLine(_))
        ));
    }

    #[test]
    fn key_blobs_refuse_the_wrong_shape() {
        assert!(matches!(
            sk_ecdsa_key_blob(&[0x04; 33], "x"),
            Err(Error::KeyLength { expected: 65, got: 33 })
        ));
        let mut compressed = synthetic_point();
        compressed[0] = 0x02;
        assert!(matches!(
            sk_ecdsa_key_blob(&compressed, "x"),
            Err(Error::PointNotUncompressed { first: 0x02 })
        ));
        assert!(matches!(
            ed25519_key_blob(&[0; 31]),
            Err(Error::KeyLength { expected: 32, got: 31 })
        ));
    }

    #[test]
    fn an_assertion_becomes_the_documented_signature_layout() {
        let challenge = b"the ssh signature blob".to_vec();
        let cd = client_data(&challenge, "https://wosh.example");
        let ad = auth_data(FLAG_USER_PRESENT | 0x04, 42, &[]);
        let sig = der(&[0x11, 0x22], &[0x33]);

        let out = signature_from_assertion(
            Assertion {
                authenticator_data: &ad,
                client_data_json: &cd,
                signature: &sig,
            },
            &challenge,
        )
        .unwrap();

        assert_eq!(out.format, WEBAUTHN_SK_ECDSA_ALGORITHM);

        // blob: mpint r, mpint s
        let (r, rest) = take_string(&out.blob).unwrap();
        assert_eq!(r, &[0x11, 0x22]);
        let (s, rest) = take_string(rest).unwrap();
        assert_eq!(s, &[0x33]);
        assert!(rest.is_empty());

        // trailer: flags, counter, origin, clientData, extensions
        assert_eq!(out.trailer[0], FLAG_USER_PRESENT | 0x04);
        assert_eq!(&out.trailer[1..5], &42u32.to_be_bytes());
        let (origin, rest) = take_string(&out.trailer[5..]).unwrap();
        assert_eq!(origin, b"https://wosh.example");
        let (client_data, rest) = take_string(rest).unwrap();
        assert_eq!(client_data, &cd[..]);
        let (extensions, rest) = take_string(rest).unwrap();
        assert!(extensions.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn extension_bytes_ride_along_when_the_flag_says_so() {
        let challenge = b"c".to_vec();
        let cd = client_data(&challenge, "https://wosh.example");
        let ad = auth_data(FLAG_USER_PRESENT | FLAG_EXTENSION_DATA, 1, &[0xA0, 0x01]);
        let out = signature_from_assertion(
            Assertion {
                authenticator_data: &ad,
                client_data_json: &cd,
                signature: &der(&[1], &[2]),
            },
            &challenge,
        )
        .unwrap();
        let (_, rest) = take_string(&out.trailer[5..]).unwrap();
        let (_, rest) = take_string(rest).unwrap();
        let (extensions, _) = take_string(rest).unwrap();
        assert_eq!(extensions, &[0xA0, 0x01]);
    }

    #[test]
    fn a_challenge_that_is_not_the_one_we_asked_for_is_refused() {
        // The property this defends: the ceremony answered THIS
        // request. A stale or substituted assertion fails here rather
        // than at the server.
        let cd = client_data(b"some other challenge", "https://wosh.example");
        let ad = auth_data(FLAG_USER_PRESENT, 1, &[]);
        assert_eq!(
            signature_from_assertion(
                Assertion {
                    authenticator_data: &ad,
                    client_data_json: &cd,
                    signature: &der(&[1], &[2]),
                },
                b"the challenge we sent",
            ),
            Err(Error::ClientDataShape)
        );
    }

    #[test]
    fn a_hashed_challenge_is_refused() {
        // sshd base64urls the RAW signature blob; a client that hashed
        // it first would fail remotely with no explanation.
        let challenge = b"the ssh signature blob".to_vec();
        let cd = client_data(&[0xAB; 32], "https://wosh.example");
        let ad = auth_data(FLAG_USER_PRESENT, 1, &[]);
        assert_eq!(
            signature_from_assertion(
                Assertion {
                    authenticator_data: &ad,
                    client_data_json: &cd,
                    signature: &der(&[1], &[2]),
                },
                &challenge,
            ),
            Err(Error::ClientDataShape)
        );
    }

    #[test]
    fn a_padded_challenge_encoding_is_refused() {
        // OpenSSH strips base64 padding when it rebuilds the prefix,
        // so a padded encoding cannot match.
        let challenge = b"ab".to_vec(); // encodes with padding under STANDARD
        let padded = format!(
            "{CLIENT_DATA_PREFIX}{}{CLIENT_DATA_ORIGIN}https://wosh.example\"}}",
            STANDARD.encode(&challenge)
        );
        let ad = auth_data(FLAG_USER_PRESENT, 1, &[]);
        assert_eq!(
            signature_from_assertion(
                Assertion {
                    authenticator_data: &ad,
                    client_data_json: padded.as_bytes(),
                    signature: &der(&[1], &[2]),
                },
                &challenge,
            ),
            Err(Error::ClientDataShape)
        );
    }

    #[test]
    fn reordered_client_data_fields_are_refused() {
        // sshd compares a reconstructed prefix, so field order is part
        // of the wire format even though JSON says otherwise.
        let challenge = b"c".to_vec();
        let reordered = format!(
            "{{\"origin\":\"https://wosh.example\",\"type\":\"webauthn.get\",\"challenge\":\"{}\"}}",
            URL_SAFE_NO_PAD.encode(&challenge)
        );
        let ad = auth_data(FLAG_USER_PRESENT, 1, &[]);
        assert_eq!(
            signature_from_assertion(
                Assertion {
                    authenticator_data: &ad,
                    client_data_json: reordered.as_bytes(),
                    signature: &der(&[1], &[2]),
                },
                &challenge,
            ),
            Err(Error::ClientDataShape)
        );
    }

    #[test]
    fn authenticator_flags_are_checked_the_way_sshd_checks_them() {
        let challenge = b"c".to_vec();
        let cd = client_data(&challenge, "https://wosh.example");
        let sig = der(&[1], &[2]);
        let attempt = |ad: Vec<u8>| {
            signature_from_assertion(
                Assertion {
                    authenticator_data: &ad,
                    client_data_json: &cd,
                    signature: &sig,
                },
                &challenge,
            )
        };

        assert_eq!(
            attempt(auth_data(FLAG_USER_PRESENT | FLAG_ATTESTED_CRED_DATA, 1, &[])),
            Err(Error::AttestedCredentialData)
        );
        assert_eq!(
            attempt(auth_data(FLAG_USER_PRESENT | FLAG_EXTENSION_DATA, 1, &[])),
            Err(Error::ExtensionFlagMismatch { flag_set: true, bytes: 0 })
        );
        assert_eq!(
            attempt(auth_data(FLAG_USER_PRESENT, 1, &[0xA0])),
            Err(Error::ExtensionFlagMismatch { flag_set: false, bytes: 1 })
        );
        assert_eq!(attempt(auth_data(0x04, 1, &[])), Err(Error::NoUserPresence));
        assert_eq!(
            attempt(vec![0; 36]),
            Err(Error::AuthenticatorDataShort { got: 36 })
        );
    }

    #[test]
    fn der_integers_carry_over_as_mpints_unchanged() {
        // A DER INTEGER's content is canonical minimal
        // two's-complement big-endian, which is exactly an mpint's --
        // including the leading zero that keeps a high-bit value
        // positive.
        let challenge = b"c".to_vec();
        let cd = client_data(&challenge, "https://o");
        let high_bit = [0x00, 0xF0, 0x0D];
        let out = signature_from_assertion(
            Assertion {
                authenticator_data: &auth_data(FLAG_USER_PRESENT, 1, &[]),
                client_data_json: &cd,
                signature: &der(&high_bit, &[0x7F]),
            },
            &challenge,
        )
        .unwrap();
        let (r, rest) = take_string(&out.blob).unwrap();
        assert_eq!(r, &high_bit);
        let (s, _) = take_string(rest).unwrap();
        assert_eq!(s, &[0x7F]);
    }

    #[test]
    fn malformed_der_is_refused() {
        let challenge = b"c".to_vec();
        let cd = client_data(&challenge, "https://o");
        let attempt = |sig: Vec<u8>| {
            signature_from_assertion(
                Assertion {
                    authenticator_data: &auth_data(FLAG_USER_PRESENT, 1, &[]),
                    client_data_json: &cd,
                    signature: &sig,
                },
                &challenge,
            )
        };

        assert!(matches!(attempt(vec![]), Err(Error::MalformedSignature(_))));
        // not a SEQUENCE
        assert!(matches!(attempt(vec![0x31, 0x00]), Err(Error::MalformedSignature(_))));
        // negative r
        assert!(matches!(attempt(der(&[0x80, 0x01], &[1])), Err(Error::MalformedSignature(_))));
        // non-canonical leading zero on s
        assert!(matches!(attempt(der(&[1], &[0x00, 0x01])), Err(Error::MalformedSignature(_))));
        // empty r
        assert!(matches!(attempt(der(&[], &[1])), Err(Error::MalformedSignature(_))));
        // trailing junk
        let mut trailing = der(&[1], &[2]);
        trailing.push(0x00);
        assert!(matches!(attempt(trailing), Err(Error::MalformedSignature(_))));
    }

    // --- recovery ---------------------------------------------------
    //
    // These sign with a real P-256 key so the assertions are genuine:
    // recovery has to reproduce the key that made them, not a key that
    // merely satisfies the shape.

    /// A soft authenticator's assertion over `challenge`, signed by
    /// `key` -- the same bytes a browser hands back.
    fn signed_assertion(
        key: &p256::ecdsa::SigningKey,
        challenge: &[u8],
        counter: u32,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::{Digest, Sha256};

        let cd = client_data(challenge, "https://wosh.example");
        let ad = auth_data(FLAG_USER_PRESENT, counter, &[]);
        let mut outer = Sha256::new();
        outer.update(&ad);
        outer.update(Sha256::digest(&cd));
        let prehash: [u8; 32] = outer.finalize().into();
        let (sig, _): (p256::ecdsa::Signature, _) = key.sign_prehash(&prehash).unwrap();
        (ad, cd, sig.to_der().as_bytes().to_vec())
    }

    fn assertion_of(parts: &(Vec<u8>, Vec<u8>, Vec<u8>)) -> Assertion<'_> {
        Assertion {
            authenticator_data: &parts.0,
            client_data_json: &parts.1,
            signature: &parts.2,
        }
    }

    #[test]
    fn two_assertions_recover_the_key_that_made_them() {
        // The property the whole recovery path rests on: a client that
        // still holds the passkey but has lost its browser storage can
        // work the public half back out, byte for byte.
        let key = p256::ecdsa::SigningKey::from_slice(&[
            0x4c, 0x0b, 0x1f, 0x2a, 0x93, 0x77, 0x18, 0x05, 0xd1, 0x66, 0x3e, 0x41, 0x8a, 0x2c,
            0x55, 0x90, 0x6b, 0x38, 0xe7, 0x12, 0x44, 0xa9, 0x0c, 0x5f, 0x73, 0x1d, 0x62, 0xb8,
            0x0e, 0x94, 0x37, 0x21,
        ])
        .unwrap();
        let expected = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let a = signed_assertion(&key, b"wosh-passkey-recovery-1", 1);
        let b = signed_assertion(&key, b"wosh-passkey-recovery-2", 2);
        let recovered =
            recover_public_key(&[assertion_of(&a), assertion_of(&b)]).unwrap();

        assert_eq!(recovered, expected);
        assert_eq!(recovered.len(), P256_POINT_LEN);
        // And it is directly usable: the line it produces is the line
        // enrolment would have produced.
        assert_eq!(
            sk_ecdsa_key_blob(&recovered, "wosh.example").unwrap(),
            sk_ecdsa_key_blob(&expected, "wosh.example").unwrap()
        );
    }

    #[test]
    fn one_assertion_is_not_enough_to_be_sure() {
        // One signature narrows the key to a couple of candidates but
        // does not pick between them, so the API refuses to guess.
        let key = p256::ecdsa::SigningKey::from_slice(&[3u8; 32]).unwrap();
        let a = signed_assertion(&key, b"only-one", 1);
        assert_eq!(
            recover_public_key(&[assertion_of(&a)]),
            Err(Error::RecoveryNeedsTwo { got: 1 })
        );
        // ...and the ambiguity is real: a single assertion genuinely
        // fits more than one key.
        assert!(recover_candidates(assertion_of(&a)).unwrap().len() > 1);
    }

    #[test]
    fn assertions_from_different_passkeys_do_not_agree() {
        // What a user sees when they pick the wrong credential at the
        // second prompt: a refusal, not an identity that fails later
        // at the server.
        let one = p256::ecdsa::SigningKey::from_slice(&[5u8; 32]).unwrap();
        let two = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let a = signed_assertion(&one, b"wosh-passkey-recovery-1", 1);
        let b = signed_assertion(&two, b"wosh-passkey-recovery-2", 1);
        assert_eq!(
            recover_public_key(&[assertion_of(&a), assertion_of(&b)]),
            Err(Error::RecoveryFoundNothing)
        );
    }

    #[test]
    fn repeating_one_assertion_resolves_nothing() {
        // The reason the two ceremonies must use different challenges:
        // an authenticator that signs deterministically and reports a
        // zero counter would otherwise return the same bytes twice,
        // and the same bytes carry the same ambiguity. Refused rather
        // than resolved by coin toss.
        let key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let a = signed_assertion(&key, b"same", 0);
        assert!(matches!(
            recover_public_key(&[assertion_of(&a), assertion_of(&a)]),
            Err(Error::RecoveryAmbiguous { .. })
        ));
    }

    #[test]
    fn a_tampered_assertion_recovers_nothing_in_common() {
        // Recovery rebuilds what was signed from the assertion's own
        // bytes, so material that does not match its signature cannot
        // smuggle a key through.
        let key = p256::ecdsa::SigningKey::from_slice(&[11u8; 32]).unwrap();
        let a = signed_assertion(&key, b"wosh-passkey-recovery-1", 1);
        let mut b = signed_assertion(&key, b"wosh-passkey-recovery-2", 2);
        b.1.push(b' '); // one byte of clientData, after signing
        assert_eq!(
            recover_public_key(&[assertion_of(&a), assertion_of(&b)]),
            Err(Error::RecoveryFoundNothing)
        );
    }

    #[test]
    fn recovery_refuses_the_same_malformed_signatures_the_wire_does() {
        let key = p256::ecdsa::SigningKey::from_slice(&[13u8; 32]).unwrap();
        let mut a = signed_assertion(&key, b"wosh-passkey-recovery-1", 1);
        a.2 = vec![0x30, 0x00]; // an empty SEQUENCE
        let b = signed_assertion(&key, b"wosh-passkey-recovery-2", 2);
        assert!(matches!(
            recover_public_key(&[assertion_of(&a), assertion_of(&b)]),
            Err(Error::MalformedSignature(_))
        ));
    }

    #[test]
    fn an_origin_with_a_port_survives_extraction() {
        // The browser gate runs on http://localhost:<port>; sshd only
        // requires that the origin contain no quote character.
        let challenge = b"c".to_vec();
        let cd = client_data(&challenge, "http://localhost:3352");
        let out = signature_from_assertion(
            Assertion {
                authenticator_data: &auth_data(FLAG_USER_PRESENT, 1, &[]),
                client_data_json: &cd,
                signature: &der(&[1], &[2]),
            },
            &challenge,
        )
        .unwrap();
        let (origin, _) = take_string(&out.trailer[5..]).unwrap();
        assert_eq!(origin, b"http://localhost:3352");
    }
}
