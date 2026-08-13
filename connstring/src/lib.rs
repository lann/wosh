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
pub const VERSION: u8 = 2;

/// The original fixed-layout version; decoded for compatibility with
/// already-printed QR codes and links.
pub const VERSION_1: u8 = 1;

/// Raw Ed25519 public key length.
pub const PUBKEY_LEN: usize = 32;

/// Pairing token length, when present.
pub const TOKEN_LEN: usize = 16;

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
    /// version 2; a relay URL found in [`WELL_KNOWN_RELAYS`] rides as
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
    /// Accepts versions 1 and 2.
    pub fn decode(s: &str) -> Result<Self, DecodeError> {
        use base64::Engine as _;

        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.trim())
            .map_err(|_| DecodeError::Base64)?;

        match bytes.split_first() {
            None => Err(DecodeError::Truncated),
            Some((&VERSION, payload)) => Self::decode_v2(payload),
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

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

    /// The version||pubkey prefix is shared by v1 and v2 at the same
    /// offsets -- boot.mjs's endpointIdOf() reads exactly that prefix.
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
