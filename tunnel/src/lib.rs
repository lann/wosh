//! The wosh tunnel protocol, version 2: resumable sessions.
//!
//! Protocol v1 (ALPN `wosh/1`) is a raw byte pipe: a `[len:u8][token]`
//! pairing frame, then SSH bytes verbatim. A transport death -- relay
//! restart, network roam, laptop sleep -- kills the session, because
//! neither side can know which bytes the other actually received.
//!
//! Version 2 (ALPN `wosh/2`) makes the byte streams RESUMABLE while
//! keeping the tunnel content-agnostic (it still never looks inside
//! the SSH bytes). Three ideas, no more:
//!
//! 1. **Frames.** Each direction is a sequence of typed frames --
//!    `[type:u8][len:u32 LE][payload]` -- carrying data, cumulative
//!    acknowledgements, and the hello/reply handshake.
//! 2. **Cumulative offsets.** Each side counts the session bytes it
//!    has sent and received (u64, from session start, DATA payload
//!    bytes only). ACK frames carry the receive counter; the sender
//!    keeps a bounded replay buffer of unacknowledged bytes and trims
//!    it on every ACK.
//! 3. **Resume = offset exchange.** A reconnecting client sends
//!    `Hello{resume: Some(Resume{session_id, received})}`; the
//!    listener replies `Resumed{received}` with its own counter. Each
//!    side trims its replay buffer to the peer's counter and retransmits
//!    the tail. DATA frames carry no sequence numbers -- the handshake
//!    alone realigns the streams, exactly like a TCP retransmit.
//!
//! The SSH stack never notices: on the client the sans-I/O core is
//! simply not fed a wire-broken while a resume is in flight; on the
//! listener the sshd TCP leg stays open while the session is parked
//! awaiting its client (bounded by the listener's grace timer).
//!
//! Session identity and authority: `session_id` is 16 random bytes
//! minted by the listener. A resume is honored only when it arrives
//! from the SAME iroh endpoint id that created the session (the dial
//! is authenticated against that id by iroh itself) AND names a known
//! session id. The pairing token in `Hello.token` follows the
//! enrollment rules regardless (a stale token from an enrolled device
//! is fine; see the listener's pairing docs).
//!
//! Buffer discipline: replay buffers are capped ([`REPLAY_CAP`]). If a
//! side would exceed the cap (the peer stopped acking), the oldest
//! unacked bytes are gone and the session is NOT resumable past them:
//! implementations mark it dead rather than resume with a gap --
//! a corrupted SSH stream fails opaquely later; a refused resume fails
//! legibly now.

use serde::{Deserialize, Serialize};

/// ALPN for this protocol version.
pub const ALPN_V2: &[u8] = b"wosh/2";
/// ALPN for the legacy raw pipe (still accepted by the listener).
pub const ALPN_V1: &[u8] = b"wosh/1";

/// Replay-buffer cap per direction. Beyond this much unacknowledged
/// data the session stops being resumable (see module docs).
pub const REPLAY_CAP: usize = 4 * 1024 * 1024;

/// Send an ACK at least once per this many received bytes (senders may
/// also ack on a timer; receivers must tolerate any cadence).
pub const ACK_EVERY_BYTES: u64 = 128 * 1024;

/// Frame types on the wire.
pub const FT_DATA: u8 = 0;
pub const FT_ACK: u8 = 1;
pub const FT_HELLO: u8 = 2;
pub const FT_REPLY: u8 = 3;

/// Frame header size: type byte + u32 LE length.
pub const HEADER_LEN: usize = 5;

/// The client's first frame on a fresh connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// The pairing token from the connstring (empty when the
    /// connstring carries none). Judged by the listener's enrollment
    /// rules, exactly like v1's pairing frame.
    pub token: Vec<u8>,
    /// Present when resuming an existing session.
    pub resume: Option<Resume>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resume {
    /// The id `HelloReply::New` handed out at session creation.
    pub session_id: [u8; 16],
    /// Cumulative session bytes this client has RECEIVED; the listener
    /// trims its replay buffer to this and retransmits from here.
    pub received: u64,
}

/// The listener's answer to a `Hello`.
///
/// Ordering guarantee: the listener sends its `Reply` as the FIRST
/// frame on a fresh connection, before any retransmitted `Data`. The
/// client is written to tolerate pipelined data anyway; new decoders
/// should be too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HelloReply {
    /// A fresh session. Keep the id: it is the resume capability.
    New { session_id: [u8; 16] },
    /// Resumed: `received` is the listener's cumulative receive
    /// counter; the client trims its replay buffer to it and
    /// retransmits from there.
    Resumed { received: u64 },
    /// Not happening (unknown session, wrong endpoint, expired grace,
    /// replay gap, bad token). The reason is for humans.
    Refused { reason: String },
}

/// A decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Data(Vec<u8>),
    Ack(u64),
    Hello(Hello),
    Reply(HelloReply),
}

/// Encode a frame header + payload into `out`.
fn put_frame(out: &mut Vec<u8>, ty: u8, payload: &[u8]) {
    out.push(ty);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
}

pub fn encode_data(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    put_frame(&mut out, FT_DATA, payload);
    out
}

pub fn encode_ack(received: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + 8);
    put_frame(&mut out, FT_ACK, &received.to_le_bytes());
    out
}

pub fn encode_hello(h: &Hello) -> Vec<u8> {
    let body = postcard::to_allocvec(h).expect("postcard encode of a plain struct");
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    put_frame(&mut out, FT_HELLO, &body);
    out
}

pub fn encode_reply(r: &HelloReply) -> Vec<u8> {
    let body = postcard::to_allocvec(r).expect("postcard encode of a plain enum");
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    put_frame(&mut out, FT_REPLY, &body);
    out
}

/// Incremental frame decoder: feed it chunks as they arrive, take
/// complete frames out. Malformed input (unknown type, oversized
/// frame, bad postcard body) is an error -- the connection is the unit
/// of failure, there is no resync.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

/// Frames above this are nonsense for this protocol (SSH chunks are
/// tens of KiB); treat as corruption rather than buffering unboundedly.
pub const MAX_FRAME: usize = 1024 * 1024;

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append newly-arrived bytes.
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Take the next complete frame, if one is buffered.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, String> {
        if self.buf.len() < HEADER_LEN {
            return Ok(None);
        }
        let ty = self.buf[0];
        let len = u32::from_le_bytes(self.buf[1..5].try_into().unwrap()) as usize;
        if len > MAX_FRAME {
            return Err(format!("frame of {len} bytes: corrupt stream"));
        }
        if self.buf.len() < HEADER_LEN + len {
            return Ok(None);
        }
        let payload = self.buf[HEADER_LEN..HEADER_LEN + len].to_vec();
        self.buf.drain(..HEADER_LEN + len);
        let frame = match ty {
            FT_DATA => Frame::Data(payload),
            FT_ACK => {
                let bytes: [u8; 8] =
                    payload.as_slice().try_into().map_err(|_| "ACK payload not 8 bytes")?;
                Frame::Ack(u64::from_le_bytes(bytes))
            }
            FT_HELLO => Frame::Hello(
                postcard::from_bytes(&payload).map_err(|e| format!("hello: {e}"))?,
            ),
            FT_REPLY => Frame::Reply(
                postcard::from_bytes(&payload).map_err(|e| format!("reply: {e}"))?,
            ),
            other => return Err(format!("unknown frame type {other}")),
        };
        Ok(Some(frame))
    }
}

/// One direction's replay bookkeeping: the bytes sent but not yet
/// acknowledged, and the counters both the ACK sender and the resume
/// handshake speak in.
#[derive(Debug, Default)]
pub struct Replay {
    /// Cumulative bytes ever handed to `sent`.
    pub sent_total: u64,
    /// The peer's last acknowledged cumulative count.
    pub acked: u64,
    /// Unacknowledged bytes, oldest first: covers `acked..sent_total`.
    buf: std::collections::VecDeque<u8>,
    /// Set once the buffer would have exceeded [`REPLAY_CAP`]: the
    /// session can no longer be resumed past the gap.
    pub overflowed: bool,
}

impl Replay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record bytes as sent (call alongside actually writing them).
    pub fn sent(&mut self, payload: &[u8]) {
        self.sent_total += payload.len() as u64;
        self.buf.extend(payload);
        if self.buf.len() > REPLAY_CAP {
            // Drop oldest and remember that resume is now impossible
            // past this point; resumability checks consult `overflowed`.
            let excess = self.buf.len() - REPLAY_CAP;
            self.buf.drain(..excess);
            self.overflowed = true;
        }
    }

    /// The peer acknowledged `received` cumulative bytes.
    pub fn ack(&mut self, received: u64) {
        if received <= self.acked || received > self.sent_total {
            return; // stale or nonsense; acks are cumulative
        }
        let drop = (received - self.acked) as usize;
        // The buffer can be shorter than the ack span only after an
        // overflow already invalidated resume; drain what is there.
        let drop = drop.min(self.buf.len());
        self.buf.drain(..drop);
        self.acked = received;
    }

    /// The replay tail from the peer's `received` count, for
    /// retransmission after a resume -- or None when the peer's count
    /// is outside what the buffer still covers (gap: refuse the
    /// resume).
    ///
    /// Call this BEFORE `ack(received)`: the ack trims exactly the
    /// bytes the tail would read.
    pub fn tail_from(&self, received: u64) -> Option<Vec<u8>> {
        if received > self.sent_total {
            return None; // the peer claims bytes we never sent
        }
        let missing = (self.sent_total - received) as usize;
        if missing > self.buf.len() {
            return None; // trimmed past it (overflow or stale ack state)
        }
        let start = self.buf.len() - missing;
        Some(self.buf.iter().skip(start).copied().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_across_chunk_boundaries() {
        let hello = Hello { token: vec![7; 16], resume: None };
        let mut wire = encode_hello(&hello);
        wire.extend_from_slice(&encode_data(b"abc"));
        wire.extend_from_slice(&encode_ack(42));
        wire.extend_from_slice(&encode_reply(&HelloReply::Resumed { received: 9 }));

        // Feed one byte at a time: reassembly must not care.
        let mut dec = Decoder::new();
        let mut frames = Vec::new();
        for b in wire {
            dec.feed(&[b]);
            while let Some(f) = dec.next_frame().unwrap() {
                frames.push(f);
            }
        }
        assert_eq!(
            frames,
            vec![
                Frame::Hello(hello),
                Frame::Data(b"abc".to_vec()),
                Frame::Ack(42),
                Frame::Reply(HelloReply::Resumed { received: 9 }),
            ]
        );
    }

    /// The wire bytes are a contract (two independently-built ends);
    /// pin them so codec drift fails here, not as an interop mystery.
    #[test]
    fn golden_bytes() {
        assert_eq!(encode_data(b"hi"), vec![0, 2, 0, 0, 0, b'h', b'i']);
        assert_eq!(encode_ack(1), vec![1, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        // Hello{token: [9,9], resume: Some{id=[1;16], received=5}}:
        // postcard = len-prefixed token, option tag, 16 raw id bytes,
        // varint received.
        let h = Hello { token: vec![9, 9], resume: Some(Resume { session_id: [1; 16], received: 5 }) };
        let mut want = vec![FT_HELLO];
        let body: Vec<u8> = [
            vec![2, 9, 9], // token: varint len + bytes
            vec![1],       // Some
            vec![1; 16],   // session id (fixed array: raw)
            vec![5],       // received: varint
        ]
        .concat();
        want.extend_from_slice(&(body.len() as u32).to_le_bytes());
        want.extend_from_slice(&body);
        assert_eq!(encode_hello(&h), want);
    }

    #[test]
    fn replay_bookkeeping() {
        let mut r = Replay::new();
        r.sent(b"hello ");
        r.sent(b"world");
        assert_eq!(r.sent_total, 11);
        assert_eq!(r.tail_from(0).unwrap(), b"hello world");
        assert_eq!(r.tail_from(6).unwrap(), b"world");
        assert_eq!(r.tail_from(11).unwrap(), b"");
        assert!(r.tail_from(12).is_none()); // beyond what was sent

        r.ack(6);
        assert_eq!(r.acked, 6);
        assert!(r.tail_from(3).is_none()); // trimmed: gap
        assert_eq!(r.tail_from(6).unwrap(), b"world");

        // Stale and nonsense acks are ignored.
        r.ack(3);
        r.ack(99);
        assert_eq!(r.acked, 6);
    }

    #[test]
    fn replay_overflow_invalidates_resume() {
        let mut r = Replay::new();
        let chunk = vec![0u8; REPLAY_CAP / 4];
        for _ in 0..5 {
            r.sent(&chunk); // 25% over cap
        }
        assert!(r.overflowed);
        assert!(r.tail_from(0).is_none()); // the oldest bytes are gone
        // The recent tail is still replayable.
        let recent = r.sent_total - (REPLAY_CAP as u64) / 2;
        assert!(r.tail_from(recent).is_some());
    }

    #[test]
    fn decoder_rejects_garbage() {
        let mut dec = Decoder::new();
        dec.feed(&[9, 1, 0, 0, 0, 0]); // unknown type
        assert!(dec.next_frame().is_err());

        let mut dec = Decoder::new();
        dec.feed(&[FT_DATA, 255, 255, 255, 255]); // 4 GiB frame
        assert!(dec.next_frame().is_err());

        let mut dec = Decoder::new();
        dec.feed(&[FT_ACK, 3, 0, 0, 0, 1, 2, 3]); // ACK payload not 8 bytes
        assert!(dec.next_frame().is_err());
    }
}
