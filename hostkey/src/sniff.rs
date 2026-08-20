//! The passive observer: an SSH transport-framing state machine fed
//! copies of the SERVER->CLIENT bytes.
//!
//! Two properties matter more than anything it extracts. It never
//! touches the proxied stream (it only ever sees copies), and it can
//! be wrong without consequence: every ambiguity resolves to "give
//! up, silently". A listener that mis-parses a handshake must degrade
//! to the dumb pipe it was before this crate existed, not to a broken
//! one.
//!
//! Framing per RFC 4253: identification lines (CRLF-terminated, the
//! server MAY send arbitrary lines before the one starting `SSH-`),
//! then binary packets `uint32 packet_length || byte padding_length
//! || payload || padding`. Before NEWKEYS there is no encryption and
//! no MAC, so that framing is readable verbatim -- which is the whole
//! reason this works.

use ssh_key::PublicKey;

/// Stop scanning after this much. A stream that has not shown us a
/// host key within half a megabyte of cleartext is not going to: it
/// is either not SSH, or it desynced in a way our sanity checks
/// missed, and either way we would rather stop looking than keep
/// buffering someone's bulk traffic.
pub const MAX_SCAN: usize = 512 * 1024;

/// The largest packet we will believe. RFC 4253 requires 35000 to be
/// supported; anything past 256 KiB in a CLEARTEXT handshake packet
/// means we are reading something that is not a packet header.
const MAX_PACKET: u32 = 256 * 1024;

/// SSH_MSG_NEWKEYS: the last cleartext packet. After this the wire is
/// encrypted and there is nothing left for us to see.
const MSG_NEWKEYS: u8 = 21;

#[derive(Debug, PartialEq, Eq)]
enum State {
    /// Consuming identification lines, up to and including the
    /// `SSH-...` one.
    Ident,
    /// Reading binary packets.
    Packets,
    /// Finished, either with a key or without one. Nothing more is
    /// buffered and `feed` becomes a no-op.
    Done,
}

/// Watches one connection's server->client direction for the host key.
pub struct Sniffer {
    state: State,
    buf: Vec<u8>,
    seen: usize,
    key: Option<PublicKey>,
}

impl Default for Sniffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Sniffer {
    pub fn new() -> Self {
        Sniffer {
            state: State::Ident,
            buf: Vec::new(),
            seen: 0,
            key: None,
        }
    }

    /// The host key, once one has been observed. `None` until then,
    /// and forever if the scan gave up.
    pub fn key(&self) -> Option<&PublicKey> {
        self.key.as_ref()
    }

    /// True once this sniffer will never produce anything further --
    /// key found, NEWKEYS seen, desync, or the scan cap. The caller
    /// can stop copying bytes to it.
    pub fn finished(&self) -> bool {
        self.state == State::Done
    }

    /// Feed a copy of the next server->client chunk. Chunk boundaries
    /// are arbitrary (they are TCP reads, not packets), so everything
    /// buffers across calls.
    ///
    /// Returns the key if THIS call is the one that found it, so a
    /// caller can act exactly once without polling.
    pub fn feed(&mut self, chunk: &[u8]) -> Option<&PublicKey> {
        if self.state == State::Done {
            return None;
        }
        self.seen += chunk.len();
        self.buf.extend_from_slice(chunk);
        let found = self.drive();
        // The cap counts bytes INSPECTED, not bytes buffered: a
        // handshake spread over a thousand one-byte reads is normal,
        // a half-megabyte one is not.
        if !found && self.seen > MAX_SCAN {
            self.give_up();
        }
        if found {
            self.key.as_ref()
        } else {
            None
        }
    }

    /// Stop for good, releasing the buffer. Always silent: every
    /// reason to be here (not SSH, desync, cap) is one the operator
    /// can do nothing about, and a proxy that narrates its own failed
    /// guesses about traffic is worse than one that does not guess.
    fn give_up(&mut self) {
        self.state = State::Done;
        self.buf = Vec::new();
        self.buf.shrink_to_fit();
    }

    /// Consume as much of the buffer as is currently complete.
    /// Returns true when a key was found.
    fn drive(&mut self) -> bool {
        loop {
            match self.state {
                State::Done => return false,
                State::Ident => match consume_ident(&self.buf) {
                    IdentStep::Need => return false,
                    IdentStep::Bad => {
                        self.give_up();
                        return false;
                    }
                    IdentStep::Consumed(n, done) => {
                        self.buf.drain(..n);
                        if done {
                            self.state = State::Packets;
                        }
                    }
                },
                State::Packets => match next_packet(&self.buf) {
                    PacketStep::Need => return false,
                    PacketStep::Bad => {
                        self.give_up();
                        return false;
                    }
                    PacketStep::Packet { total, payload } => {
                        let payload = payload.to_vec();
                        self.buf.drain(..total);
                        match payload.first().copied() {
                            // NEWKEYS ends the cleartext phase. If we
                            // have not found a key by now we never
                            // will on this connection.
                            Some(MSG_NEWKEYS) => {
                                self.give_up();
                                return false;
                            }
                            Some(msg) => {
                                if let Some(k) = host_key_in(msg, &payload[1..]) {
                                    self.key = Some(k);
                                    self.give_up();
                                    return true;
                                }
                            }
                            None => {
                                // A zero-length payload is not legal
                                // framing; treat it as desync.
                                self.give_up();
                                return false;
                            }
                        }
                    }
                },
            }
        }
    }
}

enum IdentStep {
    /// Not a whole line yet.
    Need,
    /// `n` bytes consumed; `true` when that was the `SSH-` line and
    /// binary packets follow.
    Consumed(usize, bool),
    Bad,
}

/// Consume ONE identification line if a complete one is buffered.
///
/// RFC 4253 §4.2 lets a server send arbitrary lines before its
/// identification string, so lines are skipped until one starts with
/// `SSH-`. A line here means CRLF-terminated -- the spec is explicit,
/// and being strict costs us nothing (an LF-only peer just gets no
/// fingerprint printed, never a broken proxy).
fn consume_ident(buf: &[u8]) -> IdentStep {
    // 255 bytes including CRLF is the RFC's limit; a "line" longer
    // than that is a stream that is not speaking SSH at us.
    let horizon = buf.len().min(255);
    let Some(lf) = buf[..horizon].iter().position(|&b| b == b'\n') else {
        return if buf.len() >= 255 {
            IdentStep::Bad
        } else {
            IdentStep::Need
        };
    };
    if lf == 0 || buf[lf - 1] != b'\r' {
        return IdentStep::Bad;
    }
    let line = &buf[..lf - 1];
    IdentStep::Consumed(lf + 1, line.starts_with(b"SSH-"))
}

enum PacketStep<'a> {
    Need,
    Packet { total: usize, payload: &'a [u8] },
    Bad,
}

/// Split one cleartext binary packet off the front of `buf`.
///
/// Every field is sanity-checked, because the alternative to noticing
/// a desync is inventing packet boundaries out of encrypted noise and
/// then handing whatever falls out to a key parser.
fn next_packet(buf: &[u8]) -> PacketStep<'_> {
    if buf.len() < 5 {
        return PacketStep::Need;
    }
    let packet_length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let padding_length = buf[4] as u32;
    // §6: padding is at least 4 bytes, and packet_length counts
    // padding_length + payload + padding, so it must exceed
    // padding_length + 1 for any payload at all to exist.
    if padding_length < 4 || packet_length <= padding_length + 1 || packet_length > MAX_PACKET {
        return PacketStep::Bad;
    }
    let total = 4 + packet_length as usize;
    if buf.len() < total {
        return PacketStep::Need;
    }
    let payload_len = (packet_length - padding_length - 1) as usize;
    PacketStep::Packet {
        total,
        payload: &buf[5..5 + payload_len],
    }
}

/// Does this server message carry `string K_S` right after the
/// message byte -- and is it really a key?
///
/// Messages 30/31/33 are the kex-specific range where a host key can
/// appear, but which of them actually does depends on the kex that
/// was negotiated: 31 is KEX_ECDH_REPLY (host key) under
/// curve25519/ecdh but KEX_DH_GEX_GROUP (an mpint prime) under group
/// exchange, where the key instead rides 33 (KEX_DH_GEX_REPLY); 30 is
/// KEXRSA_PUBKEY under RSA kex.
///
/// Rather than tracking the negotiation, we VALIDATE BY PARSE: read
/// the leading `string` and accept it only if `PublicKey::from_bytes`
/// takes it. A group-exchange prime is not a well-formed public-key
/// blob, so this self-selects -- and it fails closed, since the only
/// thing we can do with an unparseable candidate is ignore it.
fn host_key_in(msg: u8, rest: &[u8]) -> Option<PublicKey> {
    if !matches!(msg, 30 | 31 | 33) {
        return None;
    }
    if rest.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    // checked_add, not `4 + len`: usize is 32 bits on wasm32, `len` is
    // whatever the far end put on the wire, and a wrapping add here
    // would turn a crafted packet into a panic on any debug build.
    let blob = rest.get(4..len.checked_add(4)?)?;
    PublicKey::from_bytes(blob).ok()
}
