//! The wosh pairing connection string.
//!
//! Encodes exactly what a peer needs to dial the listener over iroh:
//! its Ed25519 endpoint-id (the iroh pubkey / address), the relay URL
//! it's reachable through, and an optional random pairing token. The
//! whole thing is one binary blob, base64url-encoded (no padding) so
//! it drops directly into a URL fragment (`#<connstring>`) with no
//! percent-encoding and no delimiter-collision risk (relay URLs
//! contain dots and slashes; keeping the format binary rather than
//! delimiter-separated sidesteps that entirely).
//!
//! Wire layout (before base64url):
//!
//! ```text
//! byte 0:     version (2 is what encode() emits; 1 still decodes)
//! bytes 1..:  the version's payload
//! ```
//!
//! Version 2 payload is [postcard](https://postcard.jamesmunns.com/)
//! (the stable wire format of postcard 1.x) for this shape:
//!
//! ```text
//! struct  { pubkey: [u8; 32], relay: Relay, token: Option<[u8; 16]> }
//! enum Relay { Url(String), WellKnown(u32) }
//! ```
//!
//! which byte-wise means: 32 raw pubkey bytes (fixed-size arrays get
//! no length prefix), then the relay enum (varint discriminant 0 +
//! varint length + UTF-8 for `Url`, or discriminant 1 + varint index
//! for `WellKnown`), then `0x00` or `0x01 || 16 token bytes`.
//!
//! Two properties are load-bearing for the other decoders of this
//! format (the Go client's hand-rolled parser, and the site's
//! `endpointIdOf` in boot.mjs, which reads only the prefix):
//!
//! - `pubkey` is the FIRST field, so `version || pubkey` sits at the
//!   same fixed offsets in every version;
//! - `WellKnown` indexes [`WELL_KNOWN_RELAYS`], whose entries are
//!   append-only and never reused (see its doc comment).
//!
//! The specialization is transparent: [`ConnString`] carries a plain
//! `relay_url` string, `encode` matches it against the table, and
//! `decode` resolves an index back to the URL. Callers never see the
//! enum.
//!
//! Version 1 (still decoded, no longer emitted) was fully manual:
//!
//! ```text
//! byte 0:       version (1)
//! bytes 1..33:  endpoint-id (32-byte raw Ed25519 public key)
//! byte 33:      flags (bit 0 = has_token)
//! bytes 34..50: token (16 random bytes), present iff flag bit 0 set
//! remaining:    relay URL, UTF-8, to the end of the blob
//! ```

use serde::{Deserialize, Serialize};

/// The version `encode` emits.
///
/// The payload is byte-identical to version 2's: the bump marks a
/// change in what the TOKEN MEANS, not in how the blob is laid out. In
/// 1 and 2 the token was a bearer secret the client sent; from 3 it is
/// a key the client proves knowledge of and never transmits (see
/// [`pairing_proof`]). A listener cannot tell those apart from the
/// bytes on the pairing frame, so the version says it instead: an
/// older client meeting a version-3 link refuses it by version, which
/// is legible, rather than sending a bearer token to a listener that
/// will only answer "bad pairing token".
pub const VERSION: u8 = 3;

/// Emitted until the pairing proof landed; still decoded, and still
/// usable -- the secret it carries is the same one, and only the way
/// it is proven changed.
pub const VERSION_2: u8 = 2;

/// The original fixed-layout version; decoded for compatibility with
/// already-printed QR codes and links.
pub const VERSION_1: u8 = 1;

/// Raw Ed25519 public key length.
pub const PUBKEY_LEN: usize = 32;

/// Pairing token length, when present.
pub const TOKEN_LEN: usize = 16;

/// Length of a [`pairing_proof`].
pub const PROOF_LEN: usize = 32;

const FLAG_HAS_TOKEN: u8 = 0x01; // v1 only

/// The public iroh relays, by well-known index.
///
/// **Append-only. An index, once assigned, is NEVER reused or
/// reordered** — a connstring is a durable artifact (printed QR codes,
/// bookmarked links), so index `n` must mean the same relay to every
/// decoder forever. A relay that is retired keeps its slot (decoding
/// it keeps returning the historical URL; whether dialing it still
/// works is the relay operator's business, not this format's). New
/// public relays go at the END of the table.
///
/// The Go client (`client-go/export_wosh_terminal_terminal/iroh.go`)
/// carries a copy of this table; the two must stay in sync — its
/// entries, like these, are append-only.
///
/// Matching is exact (the encoder does no URL canonicalization);
/// entries are spelled without the trailing FQDN dot because that is
/// how this project spells relay URLs everywhere (rustls-based
/// websocket hosts reject a trailing dot in the TLS server name).
///
/// Source: iroh's baked-in production relays (`iroh::defaults::prod`).
pub const WELL_KNOWN_RELAYS: &[&str] = &[
    "https://use1-1.relay.n0.iroh.link", // 0: NA East
    "https://usw1-1.relay.n0.iroh.link", // 1: NA West
    "https://euc1-1.relay.n0.iroh.link", // 2: EU Central
    "https://aps1-1.relay.n0.iroh.link", // 3: AP South
];

/// A decoded (or about-to-be-encoded) connection string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnString {
    /// The listener's iroh endpoint-id: a raw 32-byte Ed25519 public key.
    pub pubkey: [u8; PUBKEY_LEN],
    /// The relay URL both sides use to find each other.
    pub relay_url: String,
    /// The pairing token, if the listener was started with one.
    pub token: Option<[u8; TOKEN_LEN]>,
}

/// The pairing token as a human passes it around: 26 characters of
/// base32 with visual error correction (`data_encoding`'s
/// `BASE32_NOPAD_VISUAL`).
///
/// This is the form the listener prints and a person retypes -- into
/// `--token`, or into the browser's re-pair field when a saved
/// connection has lost its enrollment. Hex was 32 characters and had
/// no notion of the mistakes people actually make reading a code off a
/// terminal, so the alphabet here corrects the classic confusions on
/// the way in: `0`/`O`, `1`/`l`/`I`, `8`/`B`. It is NOT the wire
/// encoding -- inside a connection string the token is 16 raw bytes
/// (see `WireV2`), and nothing about this affects the protocol.
pub fn token_encode(token: &[u8; TOKEN_LEN]) -> String {
    data_encoding::BASE32_NOPAD_VISUAL.encode(token)
}

/// The inverse, tolerant of how a person types: separators they add
/// while reading it out (spaces, `-`, `:`) are dropped, and case is
/// accepted either way.
///
/// One subtlety, and it is why the case fold is not a blanket
/// `to_uppercase`: the visual table maps LOWERCASE `l` to `I`, while
/// UPPERCASE `L` is a symbol in its own right (value 11). So `l` is
/// resolved first and the rest folded after, or a typed `l` would
/// silently become a different byte.
pub fn token_decode(s: &str) -> Result<[u8; TOKEN_LEN], String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != ':')
        .map(|c| if c == 'l' { 'I' } else { c.to_ascii_uppercase() })
        .collect();
    let bytes = data_encoding::BASE32_NOPAD_VISUAL
        .decode(cleaned.as_bytes())
        .map_err(|e| format!("not a pairing token: {e}"))?;
    if bytes.len() != TOKEN_LEN {
        return Err(format!(
            "a pairing token is {} characters ({TOKEN_LEN} bytes); that decoded to {}",
            token_encode(&[0u8; TOKEN_LEN]).len(),
            bytes.len()
        ));
    }
    let mut t = [0u8; TOKEN_LEN];
    t.copy_from_slice(&bytes);
    Ok(t)
}

/// The v2 wire shape. Private on purpose: the relay specialization is
/// an encoding detail, resolved to a plain URL on the way in and out.
#[derive(Serialize, Deserialize)]
struct WireV2 {
    pubkey: [u8; PUBKEY_LEN],
    relay: RelayRepr,
    token: Option<[u8; TOKEN_LEN]>,
}

#[derive(Serialize, Deserialize)]
enum RelayRepr {
    /// Any relay, spelled out. Postcard discriminant 0.
    Url(String),
    /// An index into [`WELL_KNOWN_RELAYS`] (varint on the wire).
    /// Postcard discriminant 1.
    WellKnown(u32),
}

/// Everything that can go wrong decoding a connection string. Payloads
/// are diagnostics for logs/UI, not a machine-readable contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Not valid base64url.
    Base64,
    /// Too short to hold even the fixed-size fields for its own flags.
    Truncated,
    /// The leading version byte isn't one this build understands.
    UnsupportedVersion(u8),
    /// The payload doesn't parse as its version's wire shape.
    Malformed,
    /// The relay URL's bytes are not valid UTF-8.
    RelayUrlNotUtf8,
    /// The relay URL was empty (a connstring is useless without one).
    EmptyRelayUrl,
    /// A well-known relay index this build's table doesn't have --
    /// produced by a newer encoder. The fix is updating this decoder,
    /// not guessing.
    UnknownWellKnownRelay(u32),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::Base64 => write!(f, "not valid base64url"),
            DecodeError::Truncated => write!(f, "truncated connection string"),
            DecodeError::UnsupportedVersion(v) => {
                write!(f, "unsupported connection string version {v}")
            }
            DecodeError::Malformed => write!(f, "malformed connection string payload"),
            DecodeError::RelayUrlNotUtf8 => write!(f, "relay URL is not valid UTF-8"),
            DecodeError::EmptyRelayUrl => write!(f, "connection string carries no relay URL"),
            DecodeError::UnknownWellKnownRelay(i) => write!(
                f,
                "well-known relay index {i} is newer than this build's table"
            ),
        }
    }
}

impl ConnString {
    /// Encode as the base64url string that goes after `#` in the QR
    /// link (and is pasted/typed manually as a fallback). Emits
    /// version 3; a relay URL found in [`WELL_KNOWN_RELAYS`] rides as
    /// its index (transparently -- `decode` hands back the URL).
    pub fn encode(&self) -> String {
        use base64::Engine as _;

        let relay = match WELL_KNOWN_RELAYS.iter().position(|r| *r == self.relay_url) {
            Some(i) => RelayRepr::WellKnown(i as u32),
            None => RelayRepr::Url(self.relay_url.clone()),
        };
        let wire = WireV2 { pubkey: self.pubkey, relay, token: self.token };

        let mut buf = Vec::with_capacity(1 + PUBKEY_LEN + 2 + TOKEN_LEN + self.relay_url.len());
        buf.push(VERSION);
        buf.extend_from_slice(
            &postcard::to_allocvec(&wire).expect("postcard encoding of a plain struct"),
        );

        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    }

    /// Decode a connection string (the raw base64url blob -- the
    /// caller strips any leading `#` from a URL fragment first).
    /// Accepts versions 1, 2 and 3.
    pub fn decode(s: &str) -> Result<Self, DecodeError> {
        use base64::Engine as _;

        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.trim())
            .map_err(|_| DecodeError::Base64)?;

        match bytes.split_first() {
            None => Err(DecodeError::Truncated),
            // 3 and 2 share a payload; the version distinguishes how
            // the token is used, which is the caller's business.
            Some((&VERSION, payload)) | Some((&VERSION_2, payload)) => Self::decode_v2(payload),
            Some((&VERSION_1, payload)) => Self::decode_v1(payload),
            Some((&other, _)) => Err(DecodeError::UnsupportedVersion(other)),
        }
    }

    fn decode_v2(payload: &[u8]) -> Result<Self, DecodeError> {
        // take_from_bytes + an explicit rest check: trailing bytes are
        // a malformed blob, not padding to shrug off.
        let (wire, rest): (WireV2, &[u8]) =
            postcard::take_from_bytes(payload).map_err(|_| DecodeError::Malformed)?;
        if !rest.is_empty() {
            return Err(DecodeError::Malformed);
        }
        let relay_url = match wire.relay {
            RelayRepr::Url(url) => url,
            RelayRepr::WellKnown(i) => WELL_KNOWN_RELAYS
                .get(i as usize)
                .ok_or(DecodeError::UnknownWellKnownRelay(i))?
                .to_string(),
        };
        if relay_url.is_empty() {
            return Err(DecodeError::EmptyRelayUrl);
        }
        Ok(ConnString { pubkey: wire.pubkey, relay_url, token: wire.token })
    }

    fn decode_v1(payload: &[u8]) -> Result<Self, DecodeError> {
        // pubkey(32) + flags(1) is the minimum possible.
        if payload.len() < PUBKEY_LEN + 1 {
            return Err(DecodeError::Truncated);
        }
        let mut pubkey = [0u8; PUBKEY_LEN];
        pubkey.copy_from_slice(&payload[..PUBKEY_LEN]);

        let flags = payload[PUBKEY_LEN];
        let mut offset = PUBKEY_LEN + 1;

        let token = if flags & FLAG_HAS_TOKEN != 0 {
            if payload.len() < offset + TOKEN_LEN {
                return Err(DecodeError::Truncated);
            }
            let mut token = [0u8; TOKEN_LEN];
            token.copy_from_slice(&payload[offset..offset + TOKEN_LEN]);
            offset += TOKEN_LEN;
            Some(token)
        } else {
            None
        };

        let relay_url = String::from_utf8(payload[offset..].to_vec())
            .map_err(|_| DecodeError::RelayUrlNotUtf8)?;
        if relay_url.is_empty() {
            return Err(DecodeError::EmptyRelayUrl);
        }

        Ok(ConnString { pubkey, relay_url, token })
    }
}

/// Domain separation for [`pairing_proof`]: this key is used for
/// exactly one thing, and says so in every input it hashes.
const PROOF_DOMAIN: &[u8] = b"wosh pairing proof v1";

/// Prove knowledge of the pairing token without sending it, bound to
/// the connection it is presented on.
///
/// Version 1 and 2 connection strings made the token a bearer secret:
/// the client wrote it on the wire and the listener compared bytes.
/// Anything that saw a pairing frame learned the token, and could pair
/// any device of its own from then on -- the token outlives the
/// connection it was seen on, and outlives rotation for every device
/// already enrolled.
///
/// A proof does not. It is an HMAC over the two endpoint identities
/// and the ALPN, keyed by the token: the listener recomputes it from
/// the identity iroh authenticated during the handshake
/// (`connection.peer()`), so a captured proof is worthless to anyone
/// who cannot also produce that peer's signature -- which is to say,
/// to anyone who is not that device already. The token itself never
/// appears on the wire.
///
/// What this does NOT defend against, and is not meant to: a leaked
/// connection string. The token is printed in a QR code and handed
/// around on purpose, and whoever holds it can compute proofs of their
/// own. Rotation (and enrollment surviving it) is that story, not this
/// one.
///
/// Both identities are fixed-width and the ALPN is length-prefixed, so
/// no two different contexts can hash the same bytes.
pub fn pairing_proof(
    token: &[u8; TOKEN_LEN],
    listener_id: &[u8; PUBKEY_LEN],
    client_id: &[u8; PUBKEY_LEN],
    alpn: &[u8],
) -> [u8; PROOF_LEN] {
    use hmac::Mac as _;

    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(token)
        .expect("HMAC accepts a key of any length");
    mac.update(PROOF_DOMAIN);
    mac.update(listener_id);
    mac.update(client_id);
    mac.update(&(alpn.len() as u32).to_le_bytes());
    mac.update(alpn);

    let mut proof = [0u8; PROOF_LEN];
    proof.copy_from_slice(&mac.finalize().into_bytes());
    proof
}

/// Compare a presented pairing proof against the expected one without
/// leaking, in the time it takes, how much of it was right.
///
/// A byte-by-byte `==` stops at the first difference, so its duration
/// reports the length of the matching prefix -- which is what turns
/// forging a 32-byte value into forging 32 one-byte values in turn.
/// The comparison runs on bytes a peer chose, so it is done in
/// constant time; that the channel looks narrow in today's deployment
/// is an argument about the deployment, not about the comparison.
///
/// The LENGTH is not secret -- a proof is always `PROOF_LEN` bytes --
/// so a length mismatch may (and does) return early.
pub fn proof_eq(presented: &[u8], expected: &[u8; PROOF_LEN]) -> bool {
    use subtle::ConstantTimeEq as _;
    presented.ct_eq(&expected[..]).into()
}

#[cfg(test)]
mod tests {
    /// Pinned output of `pairing_proof` for the synthetic inputs below.
    const PROOF_GOLDEN: &str = "deb21acb79418ed5d9afb9994d8f4f0c4087b350bd5bb243079deed9d3a90520";
    use super::*;
    use base64::Engine as _;

    // Synthetic throughout: a token of all 7s and identities of 1s and
    // 2s, so nothing here resembles key material anyone could mistake
    // for real.
    fn sample_proof_inputs() -> ([u8; TOKEN_LEN], [u8; PUBKEY_LEN], [u8; PUBKEY_LEN]) {
        ([7u8; TOKEN_LEN], [1u8; PUBKEY_LEN], [2u8; PUBKEY_LEN])
    }

    #[test]
    fn proof_eq_accepts_only_the_whole_proof() {
        let expected = [9u8; PROOF_LEN];
        assert!(proof_eq(&expected, &expected));

        // Wrong in one byte, at either end: where it differs must not
        // change the answer (nor, though this cannot assert it, the
        // time it takes to say so).
        let mut first_off = expected;
        first_off[0] ^= 1;
        assert!(!proof_eq(&first_off, &expected));
        let mut last_off = expected;
        last_off[PROOF_LEN - 1] ^= 1;
        assert!(!proof_eq(&last_off, &expected));

        // Lengths the wire can present: the frame's length is the
        // peer's to choose.
        assert!(!proof_eq(&[], &expected));
        assert!(!proof_eq(&expected[..PROOF_LEN - 1], &expected));
        let mut longer = expected.to_vec();
        longer.push(0);
        assert!(!proof_eq(&longer, &expected));
    }

    #[test]
    fn pairing_proof_binds_every_part_of_its_context() {
        let (token, listener, client) = sample_proof_inputs();
        let base = pairing_proof(&token, &listener, &client, b"wosh/2");

        // Change any one input and the proof must change: a proof that
        // ignored the client identity would be replayable by anyone
        // holding a recording of it, which is the whole point of it.
        let mut other_token = token;
        other_token[0] ^= 1;
        assert_ne!(base, pairing_proof(&other_token, &listener, &client, b"wosh/2"));

        let mut other_listener = listener;
        other_listener[0] ^= 1;
        assert_ne!(base, pairing_proof(&token, &other_listener, &client, b"wosh/2"));

        let mut other_client = client;
        other_client[0] ^= 1;
        assert_ne!(base, pairing_proof(&token, &listener, &other_client, b"wosh/2"));

        assert_ne!(base, pairing_proof(&token, &listener, &client, b"wosh/1"));

        // The two identities are not interchangeable: swapping them
        // must not produce the same proof (it would, if they were
        // concatenated without their fixed widths mattering).
        assert_ne!(base, pairing_proof(&token, &client, &listener, b"wosh/2"));

        // And the ALPN is length-prefixed, so no two different ALPNs
        // can run together into the same bytes.
        assert_ne!(
            pairing_proof(&token, &listener, &client, b"ab"),
            pairing_proof(&token, &listener, &client, b"a"),
        );
    }

    #[test]
    fn pairing_proof_is_stable() {
        // The proof is a WIRE value: both ends compute it
        // independently, so a change to the context encoding that
        // nobody noticed would break pairing in the field rather than
        // here. Pinned against synthetic inputs (see above).
        let (token, listener, client) = sample_proof_inputs();
        let proof = pairing_proof(&token, &listener, &client, b"wosh/2");
        let hex: String = proof.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, PROOF_GOLDEN);
    }

    fn sample_pubkey() -> [u8; PUBKEY_LEN] {
        let mut k = [0u8; PUBKEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    fn decode_b64(s: &str) -> Vec<u8> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()
    }

    #[test]
    fn round_trips_without_token() {
        let cs = ConnString {
            pubkey: sample_pubkey(),
            relay_url: "https://relay.example.com".into(),
            token: None,
        };
        let encoded = cs.encode();
        // No delimiter characters that would need percent-encoding in
        // a URL fragment.
        assert!(encoded.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        let decoded = ConnString::decode(&encoded).unwrap();
        assert_eq!(cs, decoded);
    }

    #[test]
    fn round_trips_with_token() {
        let cs = ConnString {
            pubkey: sample_pubkey(),
            relay_url: "http://127.0.0.1:3340".into(),
            token: Some([7u8; TOKEN_LEN]),
        };
        let decoded = ConnString::decode(&cs.encode()).unwrap();
        assert_eq!(cs, decoded);
    }

    #[test]
    fn a_token_round_trips_through_its_human_encoding() {
        let token = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let text = token_encode(&token);
        // 16 bytes of base32 with no padding is 26 characters -- six
        // fewer than hex, and the point of the change.
        assert_eq!(text.len(), 26, "{text}");
        assert!(text.chars().all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)), "{text}");
        assert_eq!(token_decode(&text), Ok(token));
    }

    #[test]
    fn the_confusable_characters_are_corrected() {
        let token = [0u8; TOKEN_LEN]; // encodes as all 'A's -- no confusables
        let text = token_encode(&token);
        // Take a token whose text HAS the confusable symbols, then type
        // it the way a person would get it wrong.
        let real = [
            0x7f, 0xff, 0x0e, 0x88, 0x21, 0x00, 0x44, 0x99, 0x2a, 0xbc, 0xde, 0xf0, 0x13, 0x57,
            0x9b, 0xdf,
        ];
        let good = token_encode(&real);
        let typed = good
            .replace('O', "0")
            .replace('I', "1")
            .replace('B', "8");
        assert_eq!(token_decode(&typed), Ok(real), "typed {typed} for {good}");
        // ...and a lowercase `l` means `I`, while an uppercase `L` does
        // not (it is symbol 11): the reason the fold is not blanket.
        assert_eq!(token_decode(&good.replace('I', "l")), Ok(real));
        let _ = text;
    }

    #[test]
    fn separators_are_forgiven_but_length_is_not() {
        let token = [9u8; TOKEN_LEN];
        let text = token_encode(&token);
        let spaced = format!("{} {} {}", &text[..8], &text[8..16], &text[16..]);
        assert_eq!(token_decode(&spaced), Ok(token));
        assert_eq!(token_decode(&text.replace("", "-")), Ok(token));
        assert!(token_decode(&text[..20]).is_err(), "a short token must not decode");
        assert!(token_decode("").is_err());
        assert!(token_decode("not a token at all!!").is_err());
    }

    /// The one place this encoding bites, pinned rather than
    /// discovered later: `l` and `L` are NOT the same symbol.
    ///
    /// The visual table reads lowercase `l` as `I` (the misreading it
    /// exists to correct), while uppercase `L` is symbol 11 in its own
    /// right. So lowercase input round-trips only for tokens whose
    /// text contains no `L` -- blanket-lowercasing one that does
    /// changes it. The listener prints uppercase and the browser's
    /// field asks for uppercase; this test is here so nobody "fixes"
    /// the fold without knowing what it costs.
    #[test]
    fn lowercase_l_means_i_and_uppercase_l_does_not() {
        // A token whose encoding contains an 'L'.
        let mut with_l = None;
        for n in 0u8..64 {
            let t = [n; TOKEN_LEN];
            if token_encode(&t).contains('L') {
                with_l = Some(t);
                break;
            }
        }
        let token = with_l.expect("some byte pattern encodes with an L");
        let text = token_encode(&token);
        assert_eq!(token_decode(&text), Ok(token), "as printed");
        assert_ne!(
            token_decode(&text.to_lowercase()),
            Ok(token),
            "lowercasing an L must NOT silently survive: {text}"
        );

        // A token WITHOUT an 'L' is case-insensitive, which is what
        // makes the caveat narrow rather than general.
        let plain = [9u8; TOKEN_LEN];
        assert!(!token_encode(&plain).contains('L'));
        assert_eq!(token_decode(&token_encode(&plain).to_lowercase()), Ok(plain));

        // And the misreading the table is FOR still works.
        assert_eq!(token_decode(&text.replace('I', "l")), Ok(token));
    }

    #[test]
    fn round_trips_every_well_known_relay() {
        for (i, url) in WELL_KNOWN_RELAYS.iter().enumerate() {
            let cs = ConnString {
                pubkey: sample_pubkey(),
                relay_url: url.to_string(),
                token: Some([i as u8; TOKEN_LEN]),
            };
            let decoded = ConnString::decode(&cs.encode()).unwrap();
            assert_eq!(cs, decoded, "well-known index {i}");
        }
    }

    #[test]
    fn well_known_relays_ride_as_indices() {
        let cs = ConnString {
            pubkey: sample_pubkey(),
            relay_url: WELL_KNOWN_RELAYS[0].into(),
            token: None,
        };
        let bytes = decode_b64(&cs.encode());
        // version || pubkey || enum-discriminant(1) || varint-index(0)
        // || option-none(0): the URL itself must NOT be spelled out.
        assert_eq!(bytes.len(), 1 + PUBKEY_LEN + 3);
        assert!(!bytes.windows(4).any(|w| w == b"iroh"));
    }

    /// Golden bytes for the v2 wire shape, pinned by hand so a change
    /// in postcard's (stable, spec'd) encoding -- or in our struct
    /// declaration order -- fails HERE rather than surfacing as the Go
    /// decoder and this crate silently disagreeing.
    #[test]
    fn v2_golden_bytes() {
        let cs = ConnString {
            pubkey: sample_pubkey(),
            relay_url: WELL_KNOWN_RELAYS[2].into(),
            token: Some([9u8; TOKEN_LEN]),
        };
        let mut expected = vec![VERSION];
        expected.extend_from_slice(&sample_pubkey());
        expected.push(1); // RelayRepr discriminant: WellKnown
        expected.push(2); // varint index 2
        expected.push(1); // Option: Some
        expected.extend_from_slice(&[9u8; TOKEN_LEN]);
        assert_eq!(decode_b64(&cs.encode()), expected);

        let cs = ConnString {
            pubkey: sample_pubkey(),
            relay_url: "https://x".into(),
            token: None,
        };
        let mut expected = vec![VERSION];
        expected.extend_from_slice(&sample_pubkey());
        expected.push(0); // RelayRepr discriminant: Url
        expected.push(9); // varint string length
        expected.extend_from_slice(b"https://x");
        expected.push(0); // Option: None
        assert_eq!(decode_b64(&cs.encode()), expected);
    }

    /// The version||pubkey prefix is shared by every version at the
    /// same offsets -- boot.mjs's endpointIdOf() reads exactly that
    /// prefix, and refuses versions it does not know, so this is the
    /// one thing a version bump must not move.
    #[test]
    fn pubkey_prefix_is_stable_across_versions() {
        let cs = ConnString {
            pubkey: sample_pubkey(),
            relay_url: "https://relay.example.com".into(),
            token: Some([3u8; TOKEN_LEN]),
        };
        let v2 = decode_b64(&cs.encode());
        assert_eq!(v2[0], VERSION);
        assert_eq!(&v2[1..1 + PUBKEY_LEN], &sample_pubkey());
    }

    /// The BROWSER's encoder, decoded by the real thing.
    ///
    /// site/boot.mjs hand-rolls this format (it has no Rust, and the
    /// page must be able to rebuild a connstring for a saved card --
    /// tokenless for an ordinary tap, TOKENED for the re-pair sheet).
    /// A silent disagreement there is not a parse error the user ever
    /// sees: it is a pairing that simply never succeeds. So the JS
    /// output is pinned here as a literal.
    ///
    /// The literal was produced by running boot.mjs's
    /// `tokenedConnstring()` under node with pubkey = 00 01 .. 1f
    /// (`sample_pubkey`) and token = 01 02 .. 10; regenerate it the
    /// same way if the encoder ever changes.
    #[test]
    fn decodes_the_browsers_tokened_connstring() {
        const FROM_BOOT_MJS: &str = "AwABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fABVodHRwOi8vMTI3LjAuMC4xOjMzNDABAQIDBAUGBwgJCgsMDQ4PEA";
        let cs = ConnString::decode(FROM_BOOT_MJS).expect("boot.mjs's tokened connstring must decode");
        assert_eq!(cs.pubkey, sample_pubkey());
        assert_eq!(cs.relay_url, "http://127.0.0.1:3340");
        let mut token = [0u8; TOKEN_LEN];
        for (i, b) in token.iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        assert_eq!(cs.token, Some(token));
    }

    /// A v2 blob still decodes, and means the same connection: the
    /// version bump marks how the token is PROVEN (bearer before,
    /// `pairing_proof` from 3), and the secret it carries is
    /// unchanged, so an already-printed QR keeps working against a
    /// listener that has moved on.
    #[test]
    fn decodes_v2_as_the_same_connection() {
        let cs = ConnString {
            pubkey: sample_pubkey(),
            relay_url: "https://relay.example.com".into(),
            token: Some([3u8; TOKEN_LEN]),
        };
        let mut v3 = decode_b64(&cs.encode());
        assert_eq!(v3[0], VERSION);
        // Same payload, older version byte: that is the whole
        // difference between the two.
        v3[0] = VERSION_2;
        let as_v2 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&v3);
        assert_eq!(ConnString::decode(&as_v2).unwrap(), cs);
    }

    /// A v1 blob (as every already-printed QR code is) still decodes.
    #[test]
    fn decodes_v1() {
        let encode_v1 = |cs: &ConnString| {
            let mut buf = vec![VERSION_1];
            buf.extend_from_slice(&cs.pubkey);
            buf.push(if cs.token.is_some() { FLAG_HAS_TOKEN } else { 0 });
            if let Some(t) = &cs.token {
                buf.extend_from_slice(t);
            }
            buf.extend_from_slice(cs.relay_url.as_bytes());
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
        };
        for token in [None, Some([7u8; TOKEN_LEN])] {
            let cs = ConnString {
                pubkey: sample_pubkey(),
                relay_url: "https://use1-1.relay.n0.iroh.link".into(),
                token,
            };
            assert_eq!(ConnString::decode(&encode_v1(&cs)).unwrap(), cs);
        }
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(ConnString::decode("not base64url!!"), Err(DecodeError::Base64));
        assert_eq!(ConnString::decode(""), Err(DecodeError::Truncated));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut buf = vec![99u8]; // bogus version
        buf.extend_from_slice(&[0u8; PUBKEY_LEN]);
        buf.push(0);
        buf.extend_from_slice(b"https://x");
        let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
        assert_eq!(ConnString::decode(&s), Err(DecodeError::UnsupportedVersion(99)));
    }

    #[test]
    fn rejects_unknown_well_known_index() {
        let mut buf = vec![VERSION];
        buf.extend_from_slice(&sample_pubkey());
        buf.push(1); // WellKnown
        buf.push(63); // an index far past the table
        buf.push(0); // no token
        let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
        assert_eq!(ConnString::decode(&s), Err(DecodeError::UnknownWellKnownRelay(63)));
    }

    #[test]
    fn rejects_malformed_v2() {
        // Truncated mid-struct.
        let mut buf = vec![VERSION];
        buf.extend_from_slice(&sample_pubkey()[..10]);
        let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
        assert_eq!(ConnString::decode(&s), Err(DecodeError::Malformed));

        // Trailing junk after a complete struct.
        let cs = ConnString {
            pubkey: sample_pubkey(),
            relay_url: WELL_KNOWN_RELAYS[0].into(),
            token: None,
        };
        let mut bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(cs.encode())
            .unwrap();
        bytes.push(0xAA);
        let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        assert_eq!(ConnString::decode(&s), Err(DecodeError::Malformed));
    }

    #[test]
    fn rejects_empty_relay_url() {
        let mut buf = vec![VERSION];
        buf.extend_from_slice(&sample_pubkey());
        buf.push(0); // Url
        buf.push(0); // length 0
        buf.push(0); // no token
        let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
        assert_eq!(ConnString::decode(&s), Err(DecodeError::EmptyRelayUrl));
    }
}
