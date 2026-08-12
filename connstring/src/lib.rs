//! The wosh pairing connection string.
//!
//! Encodes exactly what a peer needs to dial the listener over iroh:
//! its Ed25519 endpoint-id (the iroh pubkey / address), the relay URL
//! it's reachable through, and an optional random pairing token. The
//! whole thing is one binary blob, base64url-encoded (no padding) so
//! it drops directly into a URL fragment (`#<connstring>`) with no
//! percent-encoding and no delimiter-collision risk (relay URLs
//! contain dots and slashes; keeping the format binary-length-prefixed
//! rather than delimiter-separated sidesteps that entirely).
//!
//! Wire layout (before base64url):
//!
//! ```text
//! byte 0:       version (currently 1)
//! bytes 1..33:  endpoint-id (32-byte raw Ed25519 public key)
//! byte 33:      flags (bit 0 = has_token)
//! bytes 34..50: token (16 random bytes), present iff flag bit 0 is set
//! remaining:    relay URL, UTF-8, to the end of the blob
//! ```

/// The current (only) wire format version.
pub const VERSION: u8 = 1;

/// Raw Ed25519 public key length.
pub const PUBKEY_LEN: usize = 32;

/// Pairing token length, when present.
pub const TOKEN_LEN: usize = 16;

const FLAG_HAS_TOKEN: u8 = 0x01;

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
    /// The relay URL's bytes are not valid UTF-8.
    RelayUrlNotUtf8,
    /// The relay URL was empty (a connstring is useless without one).
    EmptyRelayUrl,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::Base64 => write!(f, "not valid base64url"),
            DecodeError::Truncated => write!(f, "truncated connection string"),
            DecodeError::UnsupportedVersion(v) => {
                write!(f, "unsupported connection string version {v}")
            }
            DecodeError::RelayUrlNotUtf8 => write!(f, "relay URL is not valid UTF-8"),
            DecodeError::EmptyRelayUrl => write!(f, "connection string carries no relay URL"),
        }
    }
}

impl ConnString {
    /// Encode as the base64url string that goes after `#` in the QR
    /// link (and is pasted/typed manually as a fallback).
    pub fn encode(&self) -> String {
        use base64::Engine as _;

        let mut buf = Vec::with_capacity(1 + PUBKEY_LEN + 1 + TOKEN_LEN + self.relay_url.len());
        buf.push(VERSION);
        buf.extend_from_slice(&self.pubkey);
        let flags = if self.token.is_some() { FLAG_HAS_TOKEN } else { 0 };
        buf.push(flags);
        if let Some(token) = &self.token {
            buf.extend_from_slice(token);
        }
        buf.extend_from_slice(self.relay_url.as_bytes());

        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    }

    /// Decode a connection string (the raw base64url blob -- the
    /// caller strips any leading `#` from a URL fragment first).
    pub fn decode(s: &str) -> Result<Self, DecodeError> {
        use base64::Engine as _;

        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.trim())
            .map_err(|_| DecodeError::Base64)?;

        // version(1) + pubkey(32) + flags(1) is the minimum possible.
        if bytes.len() < 1 + PUBKEY_LEN + 1 {
            return Err(DecodeError::Truncated);
        }
        let version = bytes[0];
        if version != VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }

        let mut pubkey = [0u8; PUBKEY_LEN];
        pubkey.copy_from_slice(&bytes[1..1 + PUBKEY_LEN]);

        let flags = bytes[1 + PUBKEY_LEN];
        let mut offset = 1 + PUBKEY_LEN + 1;

        let token = if flags & FLAG_HAS_TOKEN != 0 {
            if bytes.len() < offset + TOKEN_LEN {
                return Err(DecodeError::Truncated);
            }
            let mut token = [0u8; TOKEN_LEN];
            token.copy_from_slice(&bytes[offset..offset + TOKEN_LEN]);
            offset += TOKEN_LEN;
            Some(token)
        } else {
            None
        };

        if offset > bytes.len() {
            return Err(DecodeError::Truncated);
        }
        let relay_url =
            String::from_utf8(bytes[offset..].to_vec()).map_err(|_| DecodeError::RelayUrlNotUtf8)?;
        if relay_url.is_empty() {
            return Err(DecodeError::EmptyRelayUrl);
        }

        Ok(ConnString { pubkey, relay_url, token })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pubkey() -> [u8; PUBKEY_LEN] {
        let mut k = [0u8; PUBKEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
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
            relay_url: "https://use1-1.relay.n0.iroh.link".into(),
            token: Some([7u8; TOKEN_LEN]),
        };
        let encoded = cs.encode();
        let decoded = ConnString::decode(&encoded).unwrap();
        assert_eq!(cs, decoded);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(ConnString::decode("not base64url!!"), Err(DecodeError::Base64));
        assert_eq!(ConnString::decode(""), Err(DecodeError::Truncated));
    }

    #[test]
    fn rejects_wrong_version() {
        use base64::Engine as _;
        let mut buf = vec![99u8]; // bogus version
        buf.extend_from_slice(&[0u8; PUBKEY_LEN]);
        buf.push(0);
        buf.extend_from_slice(b"https://x");
        let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
        assert_eq!(ConnString::decode(&s), Err(DecodeError::UnsupportedVersion(99)));
    }
}
