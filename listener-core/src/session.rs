//! The v2 (ALPN `wosh/2`) listener half: framed, resumable sessions.
//!
//! The protocol itself is `wosh-tunnel` (see `tunnel/src/lib.rs` --
//! frames, cumulative offsets, resume = offset exchange). What lives
//! here is the *state machine* that makes a session outlive the
//! transport that carries it, in a single-threaded `spawn_local`
//! world with one hard constraint: **an in-flight stream read must
//! never be cancelled.** polymorph-iroh's `recv.read()` and
//! wasi-sockets' `rx.read()` are host calls; dropping their futures
//! mid-flight is not a supported operation, so nothing here is
//! structured as "select two reads and drop the loser".
//!
//! That constraint dictates the whole shape. A session is a set of
//! LONG-LIVED tasks that own the sshd TCP leg, plus one task per
//! client ATTACHMENT that owns that attachment's iroh streams:
//!
//! ```text
//!   [A] tcp_reader  sshd -> Replay::sent -> outq        (pauses while parked)
//!   [B] client_writer  outq -> the current attachment's send stream
//!   [C] tcp_writer  inq -> sshd
//!   [D] client_reader (one per attachment) frames -> inq / acks
//! ```
//!
//! Nothing crosses a task boundary except through the session's
//! `RefCell` state, and no borrow of it is ever held across an await.
//! Tasks are never cancelled: a superseded attachment's pump notices
//! at its next await RETURN (generation counter mismatch) and retires
//! itself. A silently-dead client's read may not return until iroh's
//! idle timeout -- that is precisely why the new attachment cannot
//! wait for the old one to let go of anything, and why the sshd leg
//! is owned by the session rather than by an attachment.
//!
//! Backpressure while parked: [A] simply STOPS reading the sshd
//! socket. Bytes queue in the kernel and sshd blocks, which is the
//! correct backpressure. The `Replay` buffer holds only bytes already
//! handed to a client, never a parked session's backlog.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::rc::Rc;
use std::task::{Poll, Waker};

use wit_bindgen::StreamResult;
use wosh_tunnel::{
    encode_ack, encode_data, encode_pong, encode_reply, Decoder, Frame, Hello, HelloReply, Replay,
    Resume,
    ACK_EVERY_BYTES,
};

use crate::bindings::polymorph::iroh::endpoint::{Connection, RecvStream, SendStream};
use crate::bindings::wasi::clocks::monotonic_clock;
use crate::bindings::wasi::sockets::types::{IpAddressFamily, TcpSocket};
use crate::bindings::wit_stream;
use crate::encode_hex;

/// Chunk size for both directions' reads and for slicing a replay
/// tail into DATA frames. SSH records are far smaller; this is just
/// the syscall granularity.
const CHUNK: usize = 16 * 1024;

/// How many ended sessions to remember, so that a resume arriving
/// after the fact gets a legible reason instead of "unknown".
const TOMBSTONES: usize = 64;

/// Short, log-safe form of a session id. Session ids ARE the resume
/// capability (16 random bytes, see the tunnel module docs), so logs
/// get a prefix only -- never the whole thing.
fn id8(id: &[u8; 16]) -> String {
    encode_hex(&id[..4])
}

// ---------------------------------------------------------------- state

struct SessionState {
    /// listener -> client bookkeeping (what we may have to retransmit).
    replay: Replay,
    /// Cumulative client -> listener DATA bytes we have received.
    received: u64,
    /// The `received` value we last put on the wire as an ACK.
    acked_out: u64,
    /// Framed bytes bound for the client, in order.
    outq: VecDeque<Vec<u8>>,
    /// DATA payloads bound for sshd, in order.
    inq: VecDeque<Vec<u8>>,
    /// The current attachment's writer. `None` while parked, and also
    /// while [B] has it borrowed for an in-flight write -- [B] is the
    /// only taker, and it puts it back or drops it by generation.
    send: Option<SendStream>,
    /// The current attachment's connection, kept separately from
    /// `send` precisely so a supersede can close the old connection
    /// even while [B] holds the old send stream.
    conn: Option<Rc<Connection>>,
    attached: bool,
    /// Bumped on every attach and every park: a pump whose captured
    /// generation no longer matches has been superseded and exits.
    generation: u64,
    /// Bumped on every park; the grace timer only kills the session
    /// if the park it was started for is still the current one.
    park_epoch: u64,
    /// The sshd leg is gone: flush what is queued, FIN, retire.
    dead: bool,
    wakers: Vec<Waker>,
}

impl SessionState {
    fn wake(&mut self) {
        for w in self.wakers.drain(..) {
            w.wake();
        }
    }
}

pub struct Session {
    /// The iroh endpoint id (hex) that created this session. A resume
    /// is honored only from this id -- iroh authenticated the dial
    /// against it, so it is the session's authority.
    creator: String,
    state: RefCell<SessionState>,
}

/// All live sessions plus a short memory of dead ones.
pub struct Registry {
    live: RefCell<HashMap<[u8; 16], Rc<Session>>>,
    gone: RefCell<VecDeque<([u8; 16], &'static str)>>,
}

impl Registry {
    pub fn new() -> Rc<Self> {
        Rc::new(Self { live: RefCell::new(HashMap::new()), gone: RefCell::new(VecDeque::new()) })
    }

    fn bury(&self, id: [u8; 16], reason: &'static str) {
        self.live.borrow_mut().remove(&id);
        let mut gone = self.gone.borrow_mut();
        gone.push_back((id, reason));
        while gone.len() > TOMBSTONES {
            gone.pop_front();
        }
    }

    fn epitaph(&self, id: &[u8; 16]) -> &'static str {
        self.gone
            .borrow()
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, r)| *r)
            .unwrap_or("unknown session")
    }
}

// ------------------------------------------------------- await helpers
//
// Every one of these is a `poll_fn` over the session state that
// registers the waker and returns Pending; every mutation of the
// state calls `wake()`. Over-broad wakeups (all waiters, every
// change) are deliberate: correctness by construction beats a
// per-condition waker list in a state machine this small.

async fn wait_attached_or_dead(sess: &Rc<Session>) -> bool {
    std::future::poll_fn(|cx| {
        let mut st = sess.state.borrow_mut();
        if st.dead {
            return Poll::Ready(false);
        }
        if st.attached {
            return Poll::Ready(true);
        }
        st.wakers.push(cx.waker().clone());
        Poll::Pending
    })
    .await
}

/// Next chunk for sshd, or `None` once the session is dead and the
/// queue is drained.
async fn next_inbound(sess: &Rc<Session>) -> Option<Vec<u8>> {
    std::future::poll_fn(|cx| {
        let mut st = sess.state.borrow_mut();
        if let Some(b) = st.inq.pop_front() {
            return Poll::Ready(Some(b));
        }
        if st.dead {
            return Poll::Ready(None);
        }
        st.wakers.push(cx.waker().clone());
        Poll::Pending
    })
    .await
}

enum WriteJob {
    /// Write these bytes on this attachment (captured generation).
    Send(Vec<u8>, u64, SendStream),
    /// Nothing left and the session ended: FIN the client's stream.
    Finish(SendStream),
    /// No attachment will ever want these bytes.
    Exit,
}

async fn next_write_job(sess: &Rc<Session>) -> WriteJob {
    std::future::poll_fn(|cx| {
        let mut st = sess.state.borrow_mut();
        if st.attached {
            if let Some(send) = st.send.take() {
                if let Some(b) = st.outq.pop_front() {
                    let gen = st.generation;
                    return Poll::Ready(WriteJob::Send(b, gen, send));
                }
                if st.dead {
                    // Drained: FIN, and stop being "attached" so a
                    // late resume cannot try to reuse this stream.
                    st.attached = false;
                    st.conn.take();
                    return Poll::Ready(WriteJob::Finish(send));
                }
                st.send = Some(send);
            }
        } else if st.dead {
            return Poll::Ready(WriteJob::Exit);
        }
        st.wakers.push(cx.waker().clone());
        Poll::Pending
    })
    .await
}

// ------------------------------------------------- session transitions

/// Attach a client's streams to a session, superseding any current
/// attachment. Returns the new generation. `tail` (a replay
/// retransmission) is queued after clearing anything the previous
/// attachment left unwritten -- everything in `outq` is either DATA
/// already accounted for in `replay` (and therefore inside `tail`) or
/// an ACK, which the next cadence regenerates.
fn attach(sess: &Rc<Session>, send: SendStream, conn: Rc<Connection>, tail: Vec<u8>) -> u64 {
    let mut st = sess.state.borrow_mut();
    // The NEW attachment wins: a silently-dead client looks alive
    // until something forces its connection to fault, so close the
    // old one here. Its pump [D] is very likely parked in a read that
    // we must not cancel; closing makes that read RETURN, which is
    // how it learns to retire.
    if let Some(old) = st.conn.take() {
        old.close(0, "superseded by a newer attachment");
    }
    st.outq.clear();
    for c in tail.chunks(CHUNK) {
        st.outq.push_back(encode_data(c));
    }
    st.send = Some(send);
    st.conn = Some(conn);
    st.attached = true;
    st.generation += 1;
    st.acked_out = st.received;
    st.wake();
    st.generation
}

/// The client attachment died but the session may live: park it (or,
/// with `--resume-grace 0`, don't -- that is v1 behavior).
fn park(sess: &Rc<Session>, reg: &Rc<Registry>, id: [u8; 16], grace: u64, peer: &str) {
    {
        let st = sess.state.borrow();
        if st.dead {
            return;
        }
    }
    if grace == 0 {
        end_session(sess, reg, id, "session ended");
        eprintln!("[{peer}] session {} closed (--resume-grace 0: no parking)", id8(&id));
        return;
    }
    let epoch = {
        let mut st = sess.state.borrow_mut();
        if let Some(c) = st.conn.take() {
            c.close(0, "attachment ended");
        }
        // Release the dead attachment's write half NOW, not at the next
        // attach. The stream is unusable the moment its connection dies,
        // and a resource held across that death is a live hazard: its
        // eventual drop fires a reset by CONNECTION HANDLE, and handles
        // are slab slots the endpoint reuses -- held long enough (until
        // a resume attaches, exactly this path), the reset lands on the
        // REUSED slot, i.e. on the fresh connection it just attached.
        // Dropped here, the slot still belongs to the dead connection
        // and the reset is a no-op.
        st.send.take();
        st.attached = false;
        st.generation += 1;
        st.park_epoch += 1;
        st.wake();
        st.park_epoch
    };
    eprintln!("[{peer}] parked session {} (grace {grace}s)", id8(&id));

    // The grace timer is a task, not a deadline checked on the next
    // tick: a parked session has no ticks (that is the whole point of
    // parking), so nothing else would ever come along to expire it.
    let sess = sess.clone();
    let reg = reg.clone();
    let peer = peer.to_string();
    wit_bindgen::spawn_local(async move {
        monotonic_clock::wait_for(grace.saturating_mul(1_000_000_000)).await;
        let expired = {
            let st = sess.state.borrow();
            !st.dead && !st.attached && st.park_epoch == epoch
        };
        if expired {
            end_session(&sess, &reg, id, "session ended");
            eprintln!("[{peer}] session {} expired (unclaimed for {grace}s)", id8(&id));
        }
    });
}

/// The session is over: unregister it and let every task retire. [B]
/// flushes whatever is queued and FINs the client's stream first, so
/// a still-attached client sees the tail of the SSH stream and then a
/// clean end -- exactly what v1's FIN cascade gives it.
fn end_session(sess: &Rc<Session>, reg: &Rc<Registry>, id: [u8; 16], reason: &'static str) {
    reg.bury(id, reason);
    let mut st = sess.state.borrow_mut();
    st.dead = true;
    st.wake();
}

// ------------------------------------------------------------- the pumps

/// [A] sshd -> client. Records into the replay buffer and queues
/// frames; PAUSES entirely while the session is parked.
async fn pump_tcp_to_client(
    sess: Rc<Session>,
    reg: Rc<Registry>,
    id: [u8; 16],
    mut rx: wit_bindgen::StreamReader<u8>,
) {
    loop {
        if !wait_attached_or_dead(&sess).await {
            break; // dead: [B] handles the flush + FIN
        }
        let (result, buf) = rx.read(Vec::with_capacity(CHUNK)).await;
        if !buf.is_empty() {
            let mut st = sess.state.borrow_mut();
            // Record BEFORE queueing: `sent_total` must cover every
            // byte a resume tail might have to cover, including bytes
            // that never reach the wire because the attachment died.
            st.replay.sent(&buf);
            for c in buf.chunks(CHUNK) {
                st.outq.push_back(encode_data(c));
            }
            st.wake();
        }
        match result {
            StreamResult::Complete(_) => {}
            // sshd hung up: the session cannot be resumed into
            // anything, so it ends here rather than parking.
            StreamResult::Dropped | StreamResult::Cancelled => {
                end_session(&sess, &reg, id, "session ended");
                break;
            }
        }
    }
}

/// [B] outq -> the current attachment.
async fn pump_client_writer(sess: Rc<Session>, reg: Rc<Registry>, id: [u8; 16], grace: u64, peer: String) {
    loop {
        match next_write_job(&sess).await {
            WriteJob::Send(bytes, gen, send) => {
                let wrote = send.write(bytes).await;
                let mut st = sess.state.borrow_mut();
                if st.generation != gen || !st.attached {
                    drop(st);
                    drop(send); // superseded mid-write: abandon it
                    continue;
                }
                if wrote.is_ok() {
                    st.send = Some(send);
                } else {
                    drop(st);
                    drop(send);
                    // The write side noticed the client is gone
                    // before the read side did; same verdict.
                    park(&sess, &reg, id, grace, &peer);
                }
            }
            WriteJob::Finish(send) => {
                let _ = send.finish();
                break;
            }
            WriteJob::Exit => break,
        }
    }
}

/// [C] inq -> sshd.
async fn pump_client_to_tcp(
    sess: Rc<Session>,
    reg: Rc<Registry>,
    id: [u8; 16],
    mut tx: wit_bindgen::StreamWriter<u8>,
) {
    while let Some(chunk) = next_inbound(&sess).await {
        if !tx.write_all(chunk).await.is_empty() {
            end_session(&sess, &reg, id, "session ended");
            break;
        }
    }
    drop(tx); // FIN -> sshd closes its side
}

/// [D] one client attachment's read side. Runs inline in the
/// connection task, so the connection resource lives exactly as long
/// as this loop.
#[allow(clippy::too_many_arguments)]
async fn pump_client_reader(
    sess: Rc<Session>,
    reg: Rc<Registry>,
    id: [u8; 16],
    recv: RecvStream,
    mut dec: Decoder,
    generation: u64,
    grace: u64,
    peer: String,
    pings: bool,
) -> Result<String, String> {
    let mut to_sshd = 0u64;
    loop {
        // Frames buffered by the handshake read come first.
        loop {
            let frame = match dec.next_frame() {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => {
                    park(&sess, &reg, id, grace, &peer);
                    return Err(format!("session {}: malformed frame: {e}", id8(&id)));
                }
            };
            let violation = {
                let mut st = sess.state.borrow_mut();
                frame.apply(&mut st, &mut to_sshd, pings)
            };
            if let Some(e) = violation {
                park(&sess, &reg, id, grace, &peer);
                return Err(format!("session {}: {e}", id8(&id)));
            }
        }

        match recv.read(CHUNK as u32).await {
            Ok(Some(chunk)) => {
                if sess.state.borrow().generation != generation {
                    return Ok(format!("session {}: attachment superseded", id8(&id)));
                }
                dec.feed(&chunk);
            }
            Ok(None) | Err(_) => {
                if sess.state.borrow().generation != generation {
                    return Ok(format!("session {}: attachment superseded", id8(&id)));
                }
                let dead = sess.state.borrow().dead;
                if dead {
                    // Session already over; this is the clean FIN
                    // cascade after [B] finished the stream.
                    return Ok(format!("session {} ended ({to_sshd}B -> target)", id8(&id)));
                }
                park(&sess, &reg, id, grace, &peer);
                return Ok(format!("session {} detached ({to_sshd}B -> target)", id8(&id)));
            }
        }
    }
}

/// Applying one decoded frame to the session state. Returns `Some`
/// with a human reason when the frame is a protocol violation.
trait ApplyFrame {
    fn apply(self, st: &mut SessionState, to_sshd: &mut u64, pings: bool) -> Option<String>;
}

impl ApplyFrame for Frame {
    fn apply(self, st: &mut SessionState, to_sshd: &mut u64, pings: bool) -> Option<String> {
        match self {
            Frame::Data(payload) => {
                st.received += payload.len() as u64;
                *to_sshd += payload.len() as u64;
                st.inq.push_back(payload);
                // Cumulative ACK cadence: at least one per
                // ACK_EVERY_BYTES received (the peer tolerates any
                // cadence; this one bounds its replay buffer).
                if st.received - st.acked_out >= ACK_EVERY_BYTES {
                    st.acked_out = st.received;
                    let ack = encode_ack(st.received);
                    st.outq.push_back(ack);
                }
                st.wake();
                None
            }
            Frame::Ack(n) => {
                st.replay.ack(n);
                None
            }
            // A second HELLO, or a REPLY (which only the listener
            // ever sends): the peer is not speaking this protocol.
            Frame::Hello(_) => Some("a second HELLO mid-session".into()),
            Frame::Reply(_) => Some("a REPLY from the client".into()),
            // Liveness (wosh/3 only, see tunnel/src/lib.rs "Liveness
            // rules"): a PONG answers a PING this listener never
            // sends, so it is only ever a stray reply and is safe to
            // drop. A PING is answered right back with a PONG of the
            // same payload; that PONG rides outq and pump [B] exactly
            // like an ACK does -- it never touches `received` /
            // `acked_out` and is never recorded in `st.replay`, since
            // liveness frames don't occupy the DATA byte stream.
            Frame::Ping(p) => {
                if pings {
                    st.outq.push_back(encode_pong(p));
                    st.wake();
                    None
                } else {
                    Some("a PING on a wosh/2 connection".into())
                }
            }
            Frame::Pong(_) => {
                if pings {
                    None
                } else {
                    Some("a PONG on a wosh/2 connection".into())
                }
            }
        }
    }
}

// ------------------------------------------------------ the sshd TCP leg

struct TcpLeg {
    tx: wit_bindgen::StreamWriter<u8>,
    rx: wit_bindgen::StreamReader<u8>,
}

/// Open the sshd leg. The WARNING wording is the v1 one verbatim:
/// "the target isn't there" is the single most likely operator error
/// and this log line is the only place the real cause surfaces.
async fn connect_target(target: SocketAddr) -> Result<TcpLeg, String> {
    let family = match target {
        SocketAddr::V4(_) => IpAddressFamily::Ipv4,
        SocketAddr::V6(_) => IpAddressFamily::Ipv6,
    };
    let sock = TcpSocket::create(family).map_err(|e| format!("tcp create: {e:?}"))?;
    sock.connect(crate::tcp::to_wasi(target)).await.map_err(|e| {
        format!(
            "WARNING: could not reach the target {target}: {e:?} -- is the \
             service running? (--target sets it; this connection was dropped)"
        )
    })?;
    let sock = Rc::new(sock);

    let (tx, tx_reader) = wit_stream::new();
    // Drive the socket's send call from its own task: it is an async
    // import, so it only makes progress while something polls it, and
    // it has to outlive every attachment.
    let sock_send = sock.clone();
    wit_bindgen::spawn_local(async move {
        let _ = sock_send.send(tx_reader).await;
    });
    let (rx, rx_done) = sock.receive();
    // Same for the receive-completion future -- and it is what keeps
    // the socket resource itself alive: once both pumps have dropped
    // their stream halves, the socket drops and the leg closes.
    wit_bindgen::spawn_local(async move {
        let _ = rx_done.await;
        drop(sock);
    });
    Ok(TcpLeg { tx, rx })
}

// ------------------------------------------------------------ the entry

/// Serve one `wosh/2` connection: handshake, then attach it to a new
/// or existing session and pump until this ATTACHMENT (not the
/// session) ends.
#[allow(clippy::too_many_arguments)]
pub async fn serve_v2(
    conn: Rc<Connection>,
    reg: Rc<Registry>,
    target: SocketAddr,
    token: Option<[u8; wosh_connstring::TOKEN_LEN]>,
    paired: &RefCell<std::collections::HashSet<String>>,
    grace: u64,
) -> Result<String, String> {
    let peer = encode_hex(&conn.peer());
    // CONTRACT: tunnel/src/lib.rs "Version 3" / "Liveness rules" --
    // wosh/3 is v2 plus PING/PONG; ALPN is the only thing that tells
    // us which state machine to run, so it's read once here and
    // threaded down to frame application.
    let pings = conn.alpn() == wosh_tunnel::ALPN_V3;
    let (send, recv) = conn.accept_bi().await.map_err(|e| format!("accept-bi: {e:?}"))?;

    let mut dec = Decoder::new();
    let hello = read_hello(&recv, &mut dec).await?;

    // Enrollment: EXACTLY v1's rules (see serve_connection). The only
    // difference is that a v2 refusal is spoken out loud -- the
    // client can render it -- where v1 drops silently.
    if let Some(want) = token {
        let enrolled = paired.borrow().contains(&peer);
        if !enrolled {
            if hello.token.len() == want.len() && hello.token == want {
                paired.borrow_mut().insert(peer.clone());
                crate::pairing::persist(&peer);
                eprintln!("[{peer}] paired (valid token; this device now reconnects across token rotations)");
            } else {
                refuse(&send, "bad pairing token").await;
                return Err("refused: bad pairing token (and not a paired device)".into());
            }
        }
    }

    match hello.resume {
        None => start_session(conn, reg, target, send, recv, dec, grace, peer, pings).await,
        Some(r) => resume_session(conn, reg, send, recv, dec, r, grace, peer, pings).await,
    }
}

/// The first frame MUST be a HELLO; anything else is a client that is
/// not speaking this protocol, and the connection is the unit of
/// failure (there is no resync -- see the Decoder docs).
async fn read_hello(recv: &RecvStream, dec: &mut Decoder) -> Result<Hello, String> {
    loop {
        match dec.next_frame() {
            Ok(Some(Frame::Hello(h))) => return Ok(h),
            Ok(Some(other)) => {
                return Err(format!("refused: first frame was {other:?}, expected HELLO"))
            }
            Ok(None) => {}
            Err(e) => return Err(format!("refused: {e}")),
        }
        match recv.read(CHUNK as u32).await {
            Ok(Some(chunk)) => dec.feed(&chunk),
            Ok(None) => return Err("connection closed before HELLO".into()),
            Err(e) => return Err(format!("read: {e:?}")),
        }
    }
}

/// Speak a refusal, then linger briefly. The point of v2 refusals is
/// that the client can RENDER the reason (v1 just drops); returning
/// immediately would drop the last `Rc<Connection>` and could reset
/// the connection before the reply is delivered. One second is a
/// bounded wait -- a peer that never reads costs us nothing more.
async fn refuse(send: &SendStream, reason: &str) {
    let _ = send.write(encode_reply(&HelloReply::Refused { reason: reason.to_string() })).await;
    let _ = send.finish();
    monotonic_clock::wait_for(1_000_000_000).await;
}

#[allow(clippy::too_many_arguments)]
async fn start_session(
    conn: Rc<Connection>,
    reg: Rc<Registry>,
    target: SocketAddr,
    send: SendStream,
    recv: RecvStream,
    dec: Decoder,
    grace: u64,
    peer: String,
    pings: bool,
) -> Result<String, String> {
    let mut id = [0u8; 16];
    // The session id is a capability: the ONLY thing besides the
    // authenticated endpoint id that authorizes a resume.
    getrandom::getrandom(&mut id).map_err(|e| format!("randomness unavailable: {e}"))?;

    let leg = match connect_target(target).await {
        Ok(v) => v,
        Err(e) => {
            refuse(&send, "target unreachable").await;
            return Err(e);
        }
    };

    let sess = Rc::new(Session {
        creator: peer.clone(),
        state: RefCell::new(SessionState {
            replay: Replay::new(),
            received: 0,
            acked_out: 0,
            outq: VecDeque::new(),
            inq: VecDeque::new(),
            send: None,
            conn: None,
            attached: false,
            generation: 0,
            park_epoch: 0,
            dead: false,
            wakers: Vec::new(),
        }),
    });
    reg.live.borrow_mut().insert(id, sess.clone());

    send.write(encode_reply(&HelloReply::New { session_id: id }))
        .await
        .map_err(|e| format!("hello reply: {e:?}"))?;

    // Our own handle on the connection resource: the session state
    // drops its copy on supersede or FIN, and dropping the resource
    // out from under this task's in-flight read is not allowed.
    let hold = conn.clone();
    let generation = attach(&sess, send, conn, Vec::new());
    spawn_session_tasks(&sess, &reg, id, leg, grace, &peer);
    eprintln!("[{peer}] session {} opened (target {target})", id8(&id));
    let out = pump_client_reader(sess, reg, id, recv, dec, generation, grace, peer, pings).await;
    drop(hold);
    out
}

#[allow(clippy::too_many_arguments)]
async fn resume_session(
    conn: Rc<Connection>,
    reg: Rc<Registry>,
    send: SendStream,
    recv: RecvStream,
    dec: Decoder,
    r: Resume,
    grace: u64,
    peer: String,
    pings: bool,
) -> Result<String, String> {
    let id = r.session_id;
    let sess = reg.live.borrow().get(&id).cloned();
    let Some(sess) = sess else {
        let reason = reg.epitaph(&id);
        refuse(&send, reason).await;
        return Err(format!("refused resume of {}: {reason}", id8(&id)));
    };
    // Authority: same endpoint id that created it. iroh authenticated
    // the dial against that id, so this is not a bearer check on top
    // of the session id -- it is the second, unforgeable half.
    if sess.creator != peer {
        refuse(&send, "not your session").await;
        return Err(format!("refused resume of {}: wrong endpoint id", id8(&id)));
    }
    // A dead-but-not-yet-buried session (its tasks are finishing) is
    // not resumable either.
    if sess.state.borrow().dead {
        refuse(&send, "session ended").await;
        return Err(format!("refused resume of {}: session ended", id8(&id)));
    }

    let tail = sess.state.borrow().replay.tail_from(r.received);
    let Some(tail) = tail else {
        // An unbridgeable gap: the bytes the client is missing are no
        // longer buffered. Resuming would silently corrupt the SSH
        // stream (it would fail opaquely later); refusing fails
        // legibly now -- and the session can never be resumed, so it
        // ends here.
        refuse(&send, "resume gap: the session moved on").await;
        end_session(&sess, &reg, id, "resume gap: the session moved on");
        return Err(format!("refused resume of {}: replay gap", id8(&id)));
    };
    let received = sess.state.borrow().received;

    send.write(encode_reply(&HelloReply::Resumed { received }))
        .await
        .map_err(|e| format!("hello reply: {e:?}"))?;

    let replayed = tail.len();
    let hold = conn.clone(); // see start_session
    let generation = attach(&sess, send, conn, tail);
    eprintln!("[{peer}] resumed session {} (replayed {replayed} bytes)", id8(&id));
    let out = pump_client_reader(sess, reg, id, recv, dec, generation, grace, peer, pings).await;
    drop(hold);
    out
}

fn spawn_session_tasks(
    sess: &Rc<Session>,
    reg: &Rc<Registry>,
    id: [u8; 16],
    leg: TcpLeg,
    grace: u64,
    peer: &str,
) {
    let TcpLeg { tx, rx } = leg;
    wit_bindgen::spawn_local(pump_tcp_to_client(sess.clone(), reg.clone(), id, rx));
    wit_bindgen::spawn_local(pump_client_to_tcp(sess.clone(), reg.clone(), id, tx));
    wit_bindgen::spawn_local(pump_client_writer(
        sess.clone(),
        reg.clone(),
        id,
        grace,
        peer.to_string(),
    ));
}
