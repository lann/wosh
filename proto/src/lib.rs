//! Shared wire protocol between the proxy and the client-core glue.
//!
//! Two layers, both versioned by the connection ALPN
//! (`experiment-mosh/0`):
//!
//! - **Control channel**: the first client-opened bidirectional stream;
//!   length-prefixed (u32 LE) CBOR messages, [`Client`] and [`Proxy`]
//!   directions.
//! - **Datagram tunnel framing**: every QUIC datagram carries a 1-byte
//!   header so oversized mosh datagrams (stock C mosh-server emits up
//!   to ~1252 B; the iroh ceiling is 1162 B — finding 9) can be split
//!   across two datagrams and reassembled at the far end. Loss of
//!   either half drops the whole datagram — mosh's SSP retransmission
//!   owns recovery, the tunnel stays lossy-by-contract.

use serde::{Deserialize, Serialize};

/// Control protocol version inside the ALPN'd connection.
pub const CONTROL_VERSION: u16 = 0;

/// Client → proxy control messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Client {
    /// First message on the control stream. Unknown peers without a
    /// valid `pairing_token` are disconnected without ceremony.
    Hello { version: u16, pairing_token: String },
    /// Create a mosh session (`mosh-server -i 127.0.0.1`) and attach
    /// to it. v0: one session per connection.
    NewSession { cols: u16, rows: u16 },
    /// Begin passkey registration for the attached session (M6).
    /// Proxy answers with `RegisterChallenge`.
    RegisterStart,
    /// The authenticator's response to `RegisterChallenge`
    /// (webauthn-rs `RegisterPublicKeyCredential` JSON).
    RegisterFinish { response: Vec<u8> },
    /// Escrow the (client-wrapped, opaque) session blob and mark the
    /// session persistent: it survives detach and future reattaches
    /// are assertion-gated. Requires a registered passkey.
    MakePersistent { escrow: Vec<u8> },
    /// Attach to a persistent session instead of creating one.
    /// Proxy answers with `AuthChallenge`; the tunnel opens only
    /// after a verified `AuthFinish`.
    Reattach { session_id: u64 },
    /// The authenticator's assertion for `AuthChallenge`
    /// (webauthn-rs `PublicKeyCredential` JSON).
    AuthFinish { assertion: Vec<u8> },
    /// Route the connection's datagram tunnel to a client-managed
    /// mosh-server on the proxy host's loopback (M7: the client
    /// started it itself over the forwarded ssh stream and owns the
    /// key; the proxy never sees it). Proxy answers `ForwardOk`.
    ForwardDatagrams { port: u16 },
}

/// Proxy → client control messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Proxy {
    /// Hello accepted (peer already known, or operator approved the
    /// TOFU prompt). Sent only after any prompt resolves.
    HelloAck { version: u16 },
    /// The mosh session is live; `key` is the MOSH CONNECT key. All
    /// connection datagrams now tunnel to this session.
    SessionReady { session_id: u64, key: String },
    /// WebAuthn creation options (webauthn-rs
    /// `CreationChallengeResponse` JSON).
    RegisterChallenge { challenge: Vec<u8> },
    /// Registration verified and stored.
    RegisterOk,
    /// Escrow stored; the session is persistent from now on.
    PersistOk,
    /// WebAuthn request options (webauthn-rs
    /// `RequestChallengeResponse` JSON) for a `Reattach`.
    AuthChallenge { challenge: Vec<u8> },
    /// Assertion verified: the escrow blob comes back and the
    /// datagram tunnel now targets the persistent session.
    ReattachReady { session_id: u64, escrow: Vec<u8> },
    /// The datagram tunnel now targets the client-managed loopback
    /// port (M7). The session id exists for passkey binding, exactly
    /// like a proxy-spawned session's.
    ForwardOk { session_id: u64 },
    /// Terminal failure; the connection closes after this.
    Error { message: String },
}

/// First byte of every client-opened bidirectional stream AFTER the
/// control stream, naming what the stream is for. (The control stream
/// is unambiguous: it is the first one.)
pub mod stream_tag {
    /// Forward this stream to the ssh port on the proxy host's
    /// loopback (M7 inner ssh).
    pub const SSH_FORWARD: u8 = 0x01;
}

/// Encode one control message with the u32-LE length prefix.
pub fn encode<T: Serialize>(msg: &T) -> Vec<u8> {
    let mut body = Vec::new();
    ciborium::into_writer(msg, &mut body).expect("cbor encode");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Incremental decoder over a reassembly buffer: returns one decoded
/// message per call when a complete frame is buffered.
pub fn decode<T: for<'de> Deserialize<'de>>(buf: &mut Vec<u8>) -> Result<Option<T>, String> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > 1 << 20 {
        return Err(format!("control frame too large: {len}"));
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let msg = ciborium::from_reader(&buf[4..4 + len]).map_err(|e| format!("cbor: {e}"))?;
    buf.drain(..4 + len);
    Ok(Some(msg))
}

// --- escrow blob ---------------------------------------------------------

/// The escrowed session blob (M6). Opaque bytes to the proxy — it
/// stores and returns them, never parses. Between client-side parties
/// (web/storage.mjs, the native harness) the format is this tagged
/// variant as JSON, byte-compatible with the storage schema's session
/// `key` field (D4): `{"plain":{...}}` or `{"prf":{...}}`. Every arm
/// carries `seqFloor` (finding 13): reattach must resume the datagram
/// sequence strictly above it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Escrow {
    Plain {
        key: String,
        #[serde(rename = "seqFloor")]
        seq_floor: u64,
    },
    Prf {
        #[serde(rename = "credId")]
        cred_id: String,
        salt: String,
        iv: String,
        ct: String,
        #[serde(rename = "seqFloor")]
        seq_floor: u64,
    },
}

impl Escrow {
    pub fn seq_floor(&self) -> u64 {
        match self {
            Escrow::Plain { seq_floor, .. } | Escrow::Prf { seq_floor, .. } => *seq_floor,
        }
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("escrow encode")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("escrow: {e}"))
    }
}

// --- datagram tunnel framing -------------------------------------------

/// Header byte: the datagram payload follows in full.
pub const FRAME_WHOLE: u8 = 0x00;
/// Header bytes: first / second half of a split datagram; byte 1 is a
/// wrapping id matching the halves.
pub const FRAME_FRAG_FIRST: u8 = 0x01;
pub const FRAME_FRAG_SECOND: u8 = 0x02;

/// Split `payload` into tunnel datagrams that each fit `max_size`
/// (the connection's `max-datagram-size`). v0 supports two fragments —
/// enough for any real mosh datagram (< 2 × (1162 − 2)).
pub fn frame(payload: &[u8], max_size: usize, next_id: &mut u8) -> Result<Vec<Vec<u8>>, String> {
    if payload.len() + 1 <= max_size {
        let mut d = Vec::with_capacity(1 + payload.len());
        d.push(FRAME_WHOLE);
        d.extend_from_slice(payload);
        return Ok(vec![d]);
    }
    let chunk = max_size - 2; // header + id
    if payload.len() > 2 * chunk {
        return Err(format!(
            "datagram {}B exceeds the 2-fragment tunnel limit ({}B)",
            payload.len(),
            2 * chunk
        ));
    }
    let id = *next_id;
    *next_id = next_id.wrapping_add(1);
    let (a, b) = payload.split_at(chunk);
    let mut first = Vec::with_capacity(2 + a.len());
    first.push(FRAME_FRAG_FIRST);
    first.push(id);
    first.extend_from_slice(a);
    let mut second = Vec::with_capacity(2 + b.len());
    second.push(FRAME_FRAG_SECOND);
    second.push(id);
    second.extend_from_slice(b);
    Ok(vec![first, second])
}

/// Reassembler for the receive side. Holds at most one pending first
/// half — datagrams are unordered but fragments of one datagram are
/// sent back-to-back, and mosh retransmits whole state anyway.
#[derive(Default)]
pub struct Defragmenter {
    pending: Option<(u8, Vec<u8>)>,
}

impl Defragmenter {
    /// Feed one tunnel datagram; returns the reassembled payload when
    /// complete. Malformed or unmatched fragments are dropped (lossy
    /// transport semantics).
    pub fn push(&mut self, datagram: &[u8]) -> Option<Vec<u8>> {
        match datagram.split_first() {
            Some((&FRAME_WHOLE, rest)) => Some(rest.to_vec()),
            Some((&FRAME_FRAG_FIRST, rest)) => {
                let (&id, body) = rest.split_first()?;
                self.pending = Some((id, body.to_vec()));
                None
            }
            Some((&FRAME_FRAG_SECOND, rest)) => {
                let (&id, body) = rest.split_first()?;
                let (pending_id, mut payload) = self.pending.take()?;
                if pending_id != id {
                    return None;
                }
                payload.extend_from_slice(body);
                Some(payload)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_round_trip() {
        let mut id = 0;
        let frames = frame(b"hello", 1162, &mut id).unwrap();
        assert_eq!(frames.len(), 1);
        let mut d = Defragmenter::default();
        assert_eq!(d.push(&frames[0]).unwrap(), b"hello");
    }

    #[test]
    fn split_round_trip() {
        let payload: Vec<u8> = (0..1252u16).map(|i| i as u8).collect();
        let mut id = 7;
        let frames = frame(&payload, 1162, &mut id).unwrap();
        assert_eq!(frames.len(), 2);
        assert!(frames.iter().all(|f| f.len() <= 1162));
        let mut d = Defragmenter::default();
        assert!(d.push(&frames[0]).is_none());
        assert_eq!(d.push(&frames[1]).unwrap(), payload);
    }

    #[test]
    fn lost_first_half_drops() {
        let payload = vec![0u8; 1500];
        let mut id = 0;
        let frames = frame(&payload, 1162, &mut id).unwrap();
        let mut d = Defragmenter::default();
        assert!(d.push(&frames[1]).is_none()); // second half alone: dropped
    }

    #[test]
    fn control_round_trip() {
        let msg = Client::Hello {
            version: CONTROL_VERSION,
            pairing_token: "abc123".into(),
        };
        let mut buf = encode(&msg);
        buf.extend_from_slice(&encode(&Client::NewSession { cols: 80, rows: 24 }));
        let m1: Client = decode(&mut buf).unwrap().unwrap();
        assert!(matches!(m1, Client::Hello { .. }));
        let m2: Client = decode(&mut buf).unwrap().unwrap();
        assert!(matches!(m2, Client::NewSession { cols: 80, rows: 24 }));
        assert!(decode::<Client>(&mut buf).unwrap().is_none());
    }

    #[test]
    fn ceremony_round_trip() {
        let mut buf = encode(&Client::Reattach { session_id: 7 });
        buf.extend_from_slice(&encode(&Client::AuthFinish {
            assertion: b"{}".to_vec(),
        }));
        assert!(matches!(
            decode::<Client>(&mut buf).unwrap().unwrap(),
            Client::Reattach { session_id: 7 }
        ));
        assert!(matches!(
            decode::<Client>(&mut buf).unwrap().unwrap(),
            Client::AuthFinish { .. }
        ));

        let mut buf = encode(&Proxy::ReattachReady {
            session_id: 7,
            escrow: b"blob".to_vec(),
        });
        assert!(matches!(
            decode::<Proxy>(&mut buf).unwrap().unwrap(),
            Proxy::ReattachReady { session_id: 7, .. }
        ));
    }

    #[test]
    fn escrow_json_matches_storage_schema() {
        // Byte-compatibility with web/storage.mjs `{plain:{key,seqFloor}}`.
        let escrow = Escrow::Plain {
            key: "K".into(),
            seq_floor: 5,
        };
        assert_eq!(escrow.to_json(), br#"{"plain":{"key":"K","seqFloor":5}}"#);
        assert_eq!(Escrow::from_json(&escrow.to_json()).unwrap(), escrow);
        assert_eq!(escrow.seq_floor(), 5);

        let prf: Escrow = Escrow::from_json(
            br#"{"prf":{"credId":"c","salt":"s","iv":"i","ct":"t","seqFloor":9}}"#,
        )
        .unwrap();
        assert_eq!(prf.seq_floor(), 9);
    }
}
