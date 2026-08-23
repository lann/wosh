//! `wosh-client`: the browser SSH client's I/O half (Rust component,
//! wac-composed with the sans-I/O Go `wosh:ssh-core` component and the
//! polymorph-iroh endpoint). It parses the connection string, dials the
//! listener over iroh, pumps bytes between that connection and the SSH
//! core, relays signature requests to the host's `identity-store`, and
//! exports the stable `wosh:terminal/terminal` interface the website
//! drives via polyengine.
//!
//! Division of labour (see wit/terminal.wit and wit/deps/wosh-ssh-core):
//! the core owns the SSH protocol and holds NO keys and does NO I/O;
//! this component owns the wire, the connection string and the identity
//! relay; the private key lives behind the host's `identity-store` and
//! no handle to it exists anywhere in the component graph.
//!
//! Concurrency shape (deliberate, and the reason this file is
//! structured the way it is):
//!
//! * **The reader task is never cancelled.** It owns `recv` and sits
//!   in `recv.read().await` forever. Component-model async imports in
//!   this ecosystem are not safe to drop mid-flight -- polymorph-iroh
//!   and wosh both keep an explicit "no-cancel discipline" -- so
//!   there is deliberately no `select!` racing the read against
//!   anything else. An earlier draft did exactly that and would have
//!   cancelled an in-flight read on *every keystroke*.
//! * **The writer task is the only writer of `send`.** Concurrent
//!   `write` calls on one QUIC stream could interleave and corrupt
//!   the ssh byte stream (polymorph-iroh refuses them outright with
//!   `error.in-use`). Everything that produces outbound bytes pushes
//!   them onto `outbox` and notifies the writer instead. The single
//!   exception is the pairing frame, written before the writer task
//!   exists.
//! * **A `RefCell` borrow is never held across an `.await`.** That
//!   hazard is real here: polymorph-iroh's own endpoint has a
//!   documented guest-side panic of exactly this shape. Every await
//!   site below copies what it needs out of the cell first.
//! * **No timers on the ssh path.** The core's ssh path is timer-free
//!   and every state change is caused by a call this component makes,
//!   so the protocol itself needs no clock -- and the exported
//!   interface carries no keepalive: wit-bindgen tracks the tasks
//!   spawned below. The one deliberate exception is the liveness
//!   prober ([`keepalive_task`], v3 connections only), which is
//!   clock-driven because the thing it detects has no other cause to
//!   hang an event off: a silently black-holed path produces no read
//!   error, no write error, and no frame. The only other detector is
//!   QUIC's idle timeout underneath us -- fixed at 30s, not
//!   configurable from here, and invisible until it fires.
//!
//! Transport versions (see `wosh-tunnel`'s module docs -- that crate is
//! THE protocol):
//!
//! * **v3** (`ALPN_V3`) is v2 plus liveness frames: this client probes
//!   with PING when the link has gone quiet and treats an unanswered
//!   probe as a verdict, turning up to 30s of typing into a void into
//!   a few seconds followed by a resume.
//! * **v2** (`ALPN_V2`) is a framed, resumable tunnel with no liveness
//!   frames: a transport death no longer kills the session; the resume
//!   machine ([`resume_loop`]) redials, replays the unacknowledged
//!   tail, and the SSH core is never told anything happened.
//! * **v1** (`ALPN_V1`) is the legacy raw pipe, kept as a one-shot dial
//!   fallback so a freshly-deployed page still reaches a listener that
//!   has not been updated. In legacy mode this component behaves
//!   exactly as it did before resume existed: `[len][proof]` pairing
//!   frame, raw bytes, transport death = `wire-broken`.
//!
//! Two pieces of state make the resume machine tractable:
//!
//! * **The connection generation** (`Inner::generation`). Reader and
//!   writer tasks are spawned per connection and carry the generation
//!   they were born under. They are never cancelled (see above); when a
//!   resume installs a new connection it bumps the generation, and the
//!   superseded tasks -- whose in-flight read/write returns an error on
//!   the closed connection -- notice the mismatch and exit quietly.
//! * **The replay buffer** (`Inner::replay`). Outbound DATA payloads are
//!   recorded there before they are written and trimmed by the peer's
//!   ACKs; a resume retransmits its tail. It is capped
//!   (`wosh_tunnel::REPLAY_CAP`), so it bounds what a resume can bridge:
//!   an overflow means the gap is unrecoverable and the session must
//!   die legibly rather than resume corrupt.

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "wosh-client",
        generate_all,
    });
}

mod pairing;
mod passkey;
mod transfer;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::Future;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use bindings::exports::wosh::terminal::terminal::{
    CloseKind as WitCloseKind, DirEntry, Guest, GuestSession, LinkState, Prompt, PromptBatch,
    ProbeResult, Status, Transfer,
};
use bindings::polymorph::iroh::endpoint::{Connection, Endpoint, EndpointOptions, RecvStream, SendStream};
use bindings::polymorph::iroh::identity::Identity;
use bindings::polymorph::iroh::types::{EndpointAddr, TransportAddr};
use bindings::wosh::ssh_core::core::{
    PublicKey as CoreKey, Session as CoreSession, SignRequest as CoreSignRequest,
    Signature as CoreSignature, Status as CoreStatus,
};
use bindings::wosh::terminal::identity_store;
use bindings::wosh::terminal::transfer_io::{Sink, Source};

use wosh_connstring::ConnString;
use wosh_tunnel::{
    Decoder, Frame, Hello, HelloReply, Replay, Resume, ACK_EVERY_BYTES, ALPN_V1, ALPN_V2, ALPN_V3,
};

/// Read size for the reader task. Sized to comfortably hold a
/// full-size ssh packet; the core reassembles regardless.
const READ_CHUNK: u32 = 16 * 1024;

/// The most SSH bytes this client puts in ONE tunnel DATA frame.
///
/// `wosh_tunnel::MAX_FRAME` (1 MiB) is a hard ceiling, not a hint: the
/// peer's `Decoder` treats a longer frame as a corrupt stream and fails
/// the connection, and because the offending bytes are already in the
/// replay buffer, every resume retransmits the same oversized frame and
/// is refused again -- a session that cannot die and cannot recover.
/// (Observed: a 1,050,004-byte frame, then seventy-one identical resume
/// attempts.)
///
/// Nothing upstream bounds a single write. The core hands over
/// everything it has produced since the last `drain`, which is whatever
/// the ssh stack buffered -- a file transfer's worth, a monster paste's
/// worth. So the bound lives HERE, at the point where bytes become
/// frames, and it covers the resume tail as well: that path never
/// touches the outbox, so a bound applied when queueing would miss it
/// entirely, and a replay tail is exactly the thing most likely to be
/// large.
///
/// 256 KiB leaves the ceiling a factor of four of headroom while
/// keeping the per-frame overhead (five bytes) irrelevant.
const MAX_WIRE_CHUNK: usize = 256 * 1024;

/// Backoff for the resume machine: 500ms doubling to a 15s cap, giving
/// up once 600s of TRYING have been spent. Long enough to ride out a
/// relay restart plus both sides re-registering -- and, at this size,
/// long enough to ride out the kind of outage a phone in a lift or a
/// laptop between networks actually has.
/// Sleeping is real (`wasi:clocks/monotonic-clock`, imported
/// for exactly this): between attempts every other task in the
/// component keeps running.
///
/// Why so long. The budget matches the listener's default
/// `--resume-grace` (600s) -- by convention, not by negotiation:
/// nothing on the wire tells us the peer's grace, so the two numbers
/// are kept equal on purpose and a listener configured shorter simply
/// refuses the resume, which we hear about immediately. And that is
/// the point: every DEFINITIVE answer still fails fast. A refusal, a
/// replay gap and a replay overflow all end the session the moment
/// they are known, because they are answers. The long window is spent
/// only on UNREACHABILITY -- nobody home, no route -- where giving up
/// early buys nothing at all: a fresh dial would be just as
/// unreachable, and the listener is holding the session parked the
/// whole time. Ending early there just throws away a live session that
/// was about to come back.
///
/// Trying, not elapsing. A backgrounded phone suspends this component
/// mid-loop, and a hidden tab has its timers throttled to a fraction
/// of what they asked for; wall-clock time would then be spent without
/// a single attempt being made, and the budget would be gone before
/// the page came back -- for a session the listener still holds
/// parked. So each pass adds what it MEANT to take: the sleep it asked
/// for, plus the attempt itself capped, because an attempt that
/// appears to have taken minutes was suspended, not slow.
const RESUME_BACKOFF_START_MS: u64 = 500;
const RESUME_BACKOFF_CAP_MS: u64 = 15_000;
const RESUME_WINDOW_MS: u64 = 600_000;
/// The most a single attempt can charge the budget. A dial that runs
/// past this was not dialing, it was suspended.
const RESUME_ATTEMPT_CAP_MS: u64 = 20_000;

/// Probe the peer after this much inbound silence. Any frame counts as
/// inbound (wosh-tunnel liveness rules), so a busy link never probes.
const PING_AFTER_IDLE_MS: u64 = 10_000;
/// An outstanding ping older than this is a verdict: the link is dead.
/// A live peer answers a PING as fast as it can write one frame.
const PING_VERDICT_MS: u64 = 5_000;
/// How often the prober wakes to check those two numbers.
const KEEPALIVE_TICK_MS: u64 = 1_000;
/// A DATA write while the link has been silent this long piggybacks a
/// ping. Typing is the moment the user is watching: a keystroke into a
/// black hole should earn a verdict in five-to-seven seconds, not the
/// thirty QUIC's idle timeout would take.
const INTERACTIVE_PROBE_MS: u64 = 2_000;

/// How often `probe`'s poll loop ticks the core while waiting for a
/// `probe-poll` answer. Same cadence as the keepalive prober -- there
/// is nothing special about this number beyond "frequent enough that
/// a fast command returns promptly, coarse enough not to spin".
const PROBE_POLL_TICK_MS: u64 = 100;
/// How long `probe` waits for an answer before giving up. This is the
/// component's own bound, not the core's -- core.wit's probe surface
/// is deliberately timer-free (see `wit/deps/wosh-ssh-core/core.wit`)
/// -- so somebody has to own a deadline, and per the core's own doc
/// comment that is the embedder. An abandoned probe stays in flight
/// in the core past this deadline (module doc, `probe` in
/// terminal.wit), which is why the next `probe` call may legitimately
/// refuse until the stuck one finally answers.
const PROBE_DEADLINE_MS: u64 = 15_000;

/// The tunnel dialect this session settled on at connect. Fixed for
/// the session's lifetime -- a resume redials the SAME ALPN -- which
/// is why it lives on `State` rather than in the mutable `Inner`.
#[derive(Clone, Copy, PartialEq)]
enum Proto {
    /// Framed, resumable, with PING/PONG liveness.
    V3,
    /// Framed and resumable, no liveness frames.
    V2,
    /// The legacy raw pipe: no framing, no resume.
    V1,
}

impl Proto {
    /// Tunnel frames rather than raw ssh bytes.
    fn framed(self) -> bool {
        self != Proto::V1
    }

    /// The ALPN this session dials and redials with.
    fn alpn(self) -> &'static [u8] {
        match self {
            Proto::V3 => ALPN_V3,
            Proto::V2 => ALPN_V2,
            Proto::V1 => ALPN_V1,
        }
    }
}

/// Why a session ended. Component-internal mirror of terminal.wit's
/// `close-kind`; see that file for what each one means to a page.
///
/// `Ended` is never stored here: it is the one kind nothing latches,
/// because it is not a wire event -- it is read off the core's own
/// `closed` status by the export. The variant is kept so this stays a
/// full mirror of the WIT type rather than a subset that would have to
/// grow one later.
#[derive(Clone, Copy)]
#[allow(dead_code)]
enum CloseKind {
    Ended,
    Failed,
    Lost,
}


async fn sleep_ms(ms: u64) {
    bindings::wasi::clocks::monotonic_clock::wait_for(ms * 1_000_000).await;
}

fn now_ms() -> u64 {
    bindings::wasi::clocks::monotonic_clock::now() / 1_000_000
}

fn err<E: std::fmt::Debug>(what: &str) -> impl FnOnce(E) -> String + '_ {
    move |e| format!("{what}: {e:?}")
}

/// A sticky, single-consumer wake signal. `notify()` before `wait()`
/// is captured (the flag persists), so there is no missed-wakeup race
/// between "the reader queued new bytes" and "the writer parked".
#[derive(Default)]
struct Signal {
    dirty: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}

impl Signal {
    fn notify(&self) {
        self.dirty.set(true);
        // The take happens in its OWN statement, and the distinction
        // matters: an `if let` scrutinee's temporaries live to the end
        // of the whole `if let` (Rust 2021), so writing
        // `if let Some(w) = self.waker.borrow_mut().take()` holds the
        // RefMut WHILE `wake()` runs. With inter-task wakeup, `wake()`
        // may synchronously poll the woken task; if that task re-arms
        // by taking `waker.borrow_mut()` on this very Signal, that is
        // a double borrow -- a panic, i.e. a trap, and a trap poisons
        // the component instance. A LATENT hazard, closed on
        // principle: it was hypothesized as the flood-poison cause and
        // falsified by rebuild (the observed poison is the Go
        // runtime's clock read inside cabi_realloc during the
        // may-leave-false copy window; see app.mjs serializeSession).
        let w = self.waker.borrow_mut().take();
        if let Some(w) = w {
            w.wake();
        }
    }

    fn wait(&self) -> impl Future<Output = ()> + '_ {
        std::future::poll_fn(move |cx: &mut Context<'_>| {
            if self.dirty.take() {
                Poll::Ready(())
            } else {
                *self.waker.borrow_mut() = Some(cx.waker().clone());
                Poll::Pending
            }
        })
    }
}

/// Shared session state. The iroh `send` half is deliberately NOT
/// here -- it belongs solely to the writer task.
struct Inner {
    core: CoreSession,
    /// The CURRENT connection; replaced by a successful resume.
    conn: Rc<Connection>,
    /// Bumped every time a new connection is installed. Reader/writer
    /// tasks born under an older generation exit quietly (module
    /// header).
    generation: u64,
    /// Bytes the core produced, awaiting the writer task.
    outbox: VecDeque<Vec<u8>>,
    /// The reader task observed the connection end (EOF or error).
    link_down: bool,
    /// A signature relay is already in flight; without this flag two
    /// tasks noticing `signing` would both fetch `pending-signature`
    /// and the second `provide-signature` would fail.
    signing: bool,
    detached: bool,

    // --- tunnel v2 bookkeeping (all inert in legacy mode) ----------
    /// The resume capability the listener minted (`HelloReply::New`).
    /// A capability: never logged in full, hex prefix at most.
    session_id: [u8; 16],
    /// Outbound replay: DATA payloads recorded before they are written,
    /// trimmed by the peer's ACKs.
    replay: Replay,
    /// Cumulative DATA payload bytes RECEIVED this session. This is the
    /// number ACK frames and `Resume.received` speak in.
    received: u64,
    /// The last value an ACK frame carried, so the reader can schedule
    /// one per `ACK_EVERY_BYTES`.
    acked_to_peer: u64,
    /// The reader asked the writer to emit an ACK (single-writer
    /// invariant: only the writer task ever touches `send`).
    ack_due: bool,
    /// A resume is in flight; exactly one task runs the loop.
    resuming: bool,
    /// The page told us it is going away (`suspend`). While this is
    /// set, nothing redials: a phone that has been backgrounded cannot
    /// reach the network, and trying only wakes its radio and spends a
    /// budget measured for a page that can see the result.
    suspended: bool,
    /// The transport went while suspended (or a resume stood down for
    /// it). The session is neither attached nor dead: it waits for
    /// `wake`, which is the only thing that starts it moving again.
    stalled: bool,

    // --- tunnel v3 liveness (all inert below v3) -------------------
    /// When the last frame of ANY kind arrived. The liveness rules
    /// make every frame evidence, not just PONG.
    last_inbound_ms: u64,
    /// When the writer actually PUT a ping on the wire -- not when one
    /// was requested; the verdict clock must not start before the
    /// probe exists. Cleared by any inbound frame.
    ping_outstanding: Option<u64>,
    /// Someone asked for a ping. Like `ack_due`: only the writer task
    /// ever touches `send`.
    ping_due: bool,
    /// Ping payloads awaiting their echo. The protocol says answer
    /// EVERY ping, so this is a queue rather than a flag.
    pong_due: VecDeque<u64>,
    /// Payload source for the pings we send. Opaque to the peer.
    ping_counter: u64,
    /// The session reached `ready` at least once. The difference
    /// between a session that FAILED and one that was LOST.
    was_ready: bool,
    /// Set by `declare_dead`; the machine-readable half of the closed
    /// status (terminal.wit's `close-kind`).
    close_kind: Option<CloseKind>,
}

impl Inner {
    /// Queue whatever the core has produced. Sync throughout -- no
    /// `.await`, so callers may hold the borrow.
    fn take_core_output(&mut self) -> bool {
        let bytes = self.core.drain();
        if bytes.is_empty() {
            false
        } else {
            self.outbox.push_back(bytes);
            true
        }
    }

    /// A task born under `generation` has been superseded by a resume
    /// (or the session is gone): it must retire without touching
    /// anything.
    fn stale(&self, generation: u64) -> bool {
        self.generation != generation
    }
}

/// Everything the spawned tasks and the exported methods share.
struct State {
    inner: RefCell<Inner>,
    /// The dialect settled at connect. Immutable for the session: a
    /// resume redials the same ALPN, so nothing here can change it.
    proto: Proto,
    /// Owned for the session's lifetime, NOT because anything here
    /// calls them again -- except that with resume, the endpoint IS
    /// called again, to redial. Dropping a polymorph-iroh resource
    /// handle releases it host-side, and dropping the endpoint closes
    /// every connection it carries. The previous Go client never hit
    /// this -- Go's GC releases handles lazily, so its leaked endpoint
    /// stayed alive by accident. In Rust the drop is deterministic, so
    /// the ownership must be too. (Observed, not theoretical: the first
    /// integration run died with the listener logging `accept-bi:
    /// Error::Closed` the moment `connect` returned.)
    ///
    /// `Rc` inside a `RefCell`, and not a plain `Endpoint`, because the
    /// endpoint SHARES FATE WITH ITS RELAY websocket: after a relay
    /// restart, every `connect` on the old endpoint fails `Closed`,
    /// forever (observed live in the resume drill). The resume loop
    /// therefore REBINDS a fresh endpoint from the same pairing
    /// identity and swaps it in here; callers clone the `Rc` out and
    /// never hold the borrow across the connect await.
    endpoint: RefCell<Rc<Endpoint>>,
    /// The same pairing identity for every redial AND rebind within a
    /// session: the listener authorizes a resume against the endpoint
    /// id that created the session (wosh-tunnel module docs), so a
    /// fresh identity would be silently unresumable.
    identity: Identity,
    /// The relay this session dials through; rebinding needs it.
    relay_url: String,
    /// Where to redial. Same address as the original dial.
    addr: EndpointAddr,
    /// The v2 pairing proof, replayed in every `Hello` (resume sends
    /// one too). Not the token: see the proof's construction in
    /// `connect`. Empty in open mode. Held even on a v1 dial, where it
    /// is never sent -- v1 has no second Hello, and resume is v2-only.
    pairing: Vec<u8>,
    /// The session's SFTP connection, opened lazily by the first file
    /// operation and kept for every later one (terminal.wit's
    /// `list-dir`). `None` before the first operation and again after
    /// the channel dies; see `transfer::ensure_open`, which is the only
    /// thing that installs one.
    sftp: RefCell<Option<transfer::Sftp>>,
    /// One task is opening that channel right now. Without this, two
    /// concurrent first operations would each open a channel and one
    /// would be orphaned on the server.
    sftp_opening: Cell<bool>,
    /// The in-flight allowance every transfer on this session shares.
    ///
    /// Session-scoped rather than per-transfer because the thing it
    /// protects is: `replay` above is one buffer for the whole session,
    /// and overflowing it makes the session unresumable. A page may
    /// start any number of transfers at once (one per dropped file), so
    /// an allowance handed out per transfer would multiply by a number
    /// nothing bounds. See `transfer::REPLAY_BUDGET_BYTES`.
    transfer_budget: Rc<RefCell<transfer::Budget>>,
    /// Fires when the writer task has bytes to send (or must retire).
    writer_signal: Signal,
    /// Fires when the core's status may have changed. Nothing parks on
    /// it today -- every export here is latch-then-poll per
    /// terminal.wit, so the page polls `status` instead of blocking --
    /// but the progress contract is that state changes are announced,
    /// and this is where a future in-component waiter would park.
    status_signal: Signal,
}


/// The core's progress contract (wit/deps/wosh-ssh-core/core.wit): after
/// ANY state-changing call, drain to the wire and re-read status. This
/// is that step, done in whichever task made the call.
///
/// Three things happen, repeatedly until the core is quiescent:
///  1. `drain()` -> outbox, wake the writer;
///  2. if the core parked at `signing`, relay the blob to the host's
///     `identity-store` and answer with `provide-signature` (or
///     `fail-signature`, so auth fails legibly instead of parking
///     forever). Only the public half and the finished signature ever
///     cross that interface;
///  3. announce the status change.
///
/// The loop is what makes step 2 safe to fold in: answering a signature
/// produces more outbound bytes, which the next turn drains.
///
/// Note the RefCell discipline: the borrow is dropped before the
/// `sign` await, and re-taken afterwards.
async fn drive(state: &Rc<State>) {
    loop {
        let pending = {
            let mut inner = state.inner.borrow_mut();
            // A scheduler round before the drain: the core's goroutines
            // park on in-memory pipes, and core.wit keeps `pump` for
            // "the rare mid-handshake continuation that needs another
            // tick". Folding it into every drive costs a few rounds and
            // removes the whole class of "the core needed one more tick
            // and nobody gave it one" stalls -- there are no timers
            // here to rescue such a stall.
            inner.core.pump();
            let queued = inner.take_core_output();
            if queued {
                state.writer_signal.notify();
            }
            let status = inner.core.status();
            // Latch the high-water mark: `ready` once reached is what
            // separates a session that was LOST from one that never
            // worked (terminal.wit's `close-kind`).
            if matches!(status, CoreStatus::Ready) {
                inner.was_ready = true;
            }
            match status {
                CoreStatus::Signing if !inner.signing => {
                    let request = inner.core.pending_signature();
                    if request.is_some() {
                        inner.signing = true;
                    }
                    request
                }
                _ => None,
            }
        };
        state.status_signal.notify();

        let Some(request) = pending else { return };

        // No borrow is held here -- see the module header.
        let signed = sign_for(&request).await;

        {
            let mut inner = state.inner.borrow_mut();
            inner.signing = false;
            match signed {
                // The signature is relayed as the keeper produced it.
                // The keeper sits on the host side of the trust
                // boundary (it IS the holder of the key), and the
                // server verifies the signature against the offered
                // public key anyway -- a keeper that signs with a
                // different key than it reports surfaces as a
                // server-side auth rejection.
                Ok(sig) => {
                    if let Err(e) = inner.core.provide_signature(&sig) {
                        inner.core.fail_signature(&format!("signature rejected: {e}"));
                    }
                }
                Err(e) => inner.core.fail_signature(&e),
            }
        }
        // Round again: the answer above is a state-changing call.
    }
}

/// Route one signature request to the keeper that holds the key.
///
/// The core parks with the OFFERED KEY, not just the bytes, precisely
/// so this decision can be made without the client tracking which
/// offer the server settled on. Matching on the algorithm is enough:
/// each keeper owns exactly one.
async fn sign_for(request: &CoreSignRequest) -> Result<CoreSignature, String> {
    if request.key.algorithm == wosh_webauthn_ssh::WEBAUTHN_SK_ECDSA_ALGORITHM {
        let sig = passkey::sign(&request.data).await?;
        return Ok(CoreSignature {
            format: sig.format,
            blob: sig.blob,
            trailer: sig.trailer,
        });
    }
    if request.key.algorithm == wosh_webauthn_ssh::SSH_ED25519_KEY_TYPE {
        let blob = identity_store::sign(request.data.clone())
            .await
            .map_err(|e| format!("identity-store sign: {e}"))?;
        return Ok(CoreSignature {
            format: wosh_webauthn_ssh::SSH_ED25519_KEY_TYPE.to_string(),
            blob,
            trailer: Vec::new(),
        });
    }
    // Unreachable while the core only ever parks on a key this client
    // offered, but a legible refusal beats a park that never ends.
    Err(format!(
        "no keeper holds a {} key",
        request.key.algorithm
    ))
}

/// The reader task. It owns `recv` for the whole lifetime of ONE
/// connection and is NEVER cancelled (module header). `read` resolving
/// `none` is the peer's FIN -- the only clean end; anything else is a
/// transport error.
///
/// In legacy (v1) mode the bytes are the ssh stream verbatim and the
/// end of the connection is the end of the session. In v2 they are
/// tunnel frames, and the end of the connection is a resume trigger.
async fn reader_task(state: Rc<State>, recv: RecvStream, generation: u64) {
    let framed = state.proto.framed();
    let mut decoder = Decoder::new();
    loop {
        let read = recv.read(READ_CHUNK).await;

        // A superseded task retires here, before touching any state:
        // its connection is the OLD one and everything it could report
        // is about a link that has already been replaced.
        if state.inner.borrow().stale(generation) {
            return;
        }

        match read {
            Ok(Some(bytes)) => {
                if bytes.is_empty() {
                    // Not EOF (that is `none`); nothing to feed.
                    continue;
                }
                if !framed {
                    state.inner.borrow_mut().core.feed(&bytes);
                    drive(&state).await;
                    continue;
                }
                decoder.feed(&bytes);
                match consume_frames(&state, &mut decoder) {
                    Ok(fed) => {
                        if fed {
                            drive(&state).await;
                        }
                    }
                    Err(reason) => {
                        // A malformed frame -- or a `Reply` outside the
                        // handshake -- means this connection is not
                        // speaking the protocol. The connection is the
                        // unit of failure (wosh-tunnel Decoder docs), so
                        // treat it exactly like transport death.
                        link_lost(&state, generation, &format!("tunnel: {reason}")).await;
                        return;
                    }
                }
            }
            end => {
                // `none` is the peer's FIN -- the only clean end; an
                // error carries its own diagnostic.
                let reason = match end {
                    Err(e) => format!("connection closed: {e:?}"),
                    _ => "connection closed".to_string(),
                };
                link_lost(&state, generation, &reason).await;
                return;
            }
        }
    }
}

/// Drain every complete frame the decoder holds into session state.
/// Returns whether anything was fed to the core (so the caller knows
/// to `drive`). Purely synchronous: the borrow never spans an await.
fn consume_frames(state: &Rc<State>, decoder: &mut Decoder) -> Result<bool, String> {
    let mut fed = false;
    let mut ack_now = false;
    let mut wake_writer = false;
    {
        let mut inner = state.inner.borrow_mut();
        while let Some(frame) = decoder.next_frame()? {
            // ANY frame is evidence of liveness, not just PONG
            // (wosh-tunnel liveness rules): a peer mid-bulk-transfer
            // never has to answer faster than it is already sending.
            // `now_ms` is a sync host call -- no await, so the borrow
            // above is untouched.
            inner.last_inbound_ms = now_ms();
            inner.ping_outstanding = None;
            match frame {
                Frame::Data(payload) => {
                    if payload.is_empty() {
                        continue;
                    }
                    inner.core.feed(&payload);
                    // Counted once, at frame-payload granularity: this
                    // is the number the peer's replay buffer is trimmed
                    // against.
                    inner.received += payload.len() as u64;
                    fed = true;
                }
                Frame::Ack(n) => inner.replay.ack(n),
                // The protocol says answer EVERY ping, promptly --
                // hence a queue, and hence the writer (sole owner of
                // `send`) doing the writing.
                Frame::Ping(payload) => {
                    if state.proto != Proto::V3 {
                        return Err("ping frame on a connection without liveness".into());
                    }
                    inner.pong_due.push_back(payload);
                    wake_writer = true;
                }
                // Nothing to do beyond the liveness bookkeeping above:
                // the PONG's whole content is that it arrived.
                Frame::Pong(_) => {
                    if state.proto != Proto::V3 {
                        return Err("pong frame on a connection without liveness".into());
                    }
                }
                // The handshake is over; a second reply is a protocol
                // violation, not something to resynchronise from.
                Frame::Reply(_) => return Err("unexpected reply frame mid-session".into()),
                Frame::Hello(_) => return Err("unexpected hello frame from listener".into()),
            }
        }
        if inner.received.saturating_sub(inner.acked_to_peer) >= ACK_EVERY_BYTES {
            // Only the writer task touches `send`; ask it to emit the
            // ACK rather than writing one from here.
            inner.ack_due = true;
            ack_now = true;
        }
    }
    if ack_now || wake_writer {
        state.writer_signal.notify();
    }
    Ok(fed)
}

/// The liveness prober: the one deliberately clock-driven task here
/// (module header), spawned per connection on v3 only.
///
/// It exists for exactly one failure: a path that has gone silently
/// dead. Loud deaths already surface instantly as read/write errors;
/// a black hole after a NAT rebind, a network roam or a freeze-thaw
/// produces nothing at all, and the only other detector is QUIC's
/// 30s idle timeout underneath us.
///
/// It touches `send` never -- it sets `ping_due` and wakes the writer,
/// like every other producer of outbound bytes -- and it holds no
/// borrow across an await: each tick decides under one borrow and acts
/// after dropping it.
async fn keepalive_task(state: Rc<State>, generation: u64) {
    enum Tick {
        Retire,
        Idle,
        Probe,
        Dead,
    }
    loop {
        sleep_ms(KEEPALIVE_TICK_MS).await;
        let tick = {
            let mut inner = state.inner.borrow_mut();
            if inner.stale(generation) || inner.detached || inner.link_down {
                Tick::Retire
            } else if inner.suspended || inner.resuming {
                // No probing while the page is away (its network is
                // being taken from it) or while a resume owns the
                // connection -- the question is already being asked.
                Tick::Idle
            } else {
                let now = now_ms();
                if let Some(sent) = inner.ping_outstanding {
                    if now.saturating_sub(sent) >= PING_VERDICT_MS {
                        Tick::Dead
                    } else {
                        Tick::Idle
                    }
                } else if !inner.ping_due
                    && now.saturating_sub(inner.last_inbound_ms) >= PING_AFTER_IDLE_MS
                {
                    inner.ping_due = true;
                    Tick::Probe
                } else {
                    Tick::Idle
                }
            }
        };
        match tick {
            Tick::Retire => return,
            Tick::Idle => {}
            Tick::Probe => state.writer_signal.notify(),
            Tick::Dead => {
                // A verdict, handed to the same path a read error
                // takes: `link_lost` dedups via `resuming`, honours a
                // suspended page, and the resume loop closes the dead
                // connection itself.
                link_lost(
                    &state,
                    generation,
                    &format!("peer silent: liveness probe unanswered for {PING_VERDICT_MS}ms"),
                )
                .await;
                return;
            }
        }
    }
}

/// Put `bytes` on the wire as DATA, split so that no single frame
/// exceeds [`MAX_WIRE_CHUNK`] -- the one place that invariant is
/// enforced, for both the outbox and the resume tail.
///
/// Splitting is free at the protocol level: DATA frames are a byte
/// stream, the peer concatenates payloads in arrival order, and the
/// receiver's accounting (`received`, and the ACKs it drives) counts
/// payload bytes, not frames. In legacy v1 there is no framing at all,
/// so the bytes go as they are.
///
/// Called only from the writer task, which is the sole owner of `send`
/// (module header).
async fn write_data(send: &SendStream, framed: bool, bytes: &[u8]) -> Result<(), ()> {
    if !framed {
        return send.write(bytes.to_vec()).await.map_err(|_| ());
    }
    for chunk in bytes.chunks(MAX_WIRE_CHUNK) {
        send.write(wosh_tunnel::encode_data(chunk))
            .await
            .map_err(|_| ())?;
    }
    Ok(())
}

/// The writer task: the sole owner of `send` for ONE connection. It
/// parks on `writer_signal` and drains the outbox in order.
///
/// `tail` is the replay tail a resume must retransmit before anything
/// new. It is NOT re-recorded in the replay buffer: those bytes are
/// already accounted for in `replay.sent_total`, and recording them
/// again would double-count the session's byte offsets -- the one
/// bookkeeping mistake that would corrupt every later resume.
async fn writer_task(
    state: Rc<State>,
    send: SendStream,
    generation: u64,
    tail: Vec<u8>,
) {
    let framed = state.proto.framed();
    if !tail.is_empty() && write_data(&send, framed, &tail).await.is_err() {
        link_lost(&state, generation, "connection closed: replay write failed").await;
        return;
    }
    loop {
        state.writer_signal.wait().await;
        if state.inner.borrow().stale(generation) {
            return;
        }
        loop {
            // Control frames first: acks unblock the peer's replay
            // buffer, and pongs are the peer's proof we are alive --
            // a large outbox must not delay either.
            let ack = {
                let mut inner = state.inner.borrow_mut();
                if framed && inner.ack_due {
                    inner.ack_due = false;
                    inner.acked_to_peer = inner.received;
                    Some(wosh_tunnel::encode_ack(inner.received))
                } else {
                    None
                }
            };
            if let Some(frame) = ack {
                if send.write(frame).await.is_err() {
                    link_lost(&state, generation, "connection closed: ack write failed").await;
                    return;
                }
                if state.inner.borrow().stale(generation) {
                    return;
                }
            }

            // Every queued ping gets its echo, in arrival order: the
            // payload is the peer's business and it may be matching
            // them up.
            loop {
                let pong = state.inner.borrow_mut().pong_due.pop_front();
                let Some(payload) = pong else { break };
                if send.write(wosh_tunnel::encode_pong(payload)).await.is_err() {
                    link_lost(&state, generation, "connection closed: pong write failed").await;
                    return;
                }
                if state.inner.borrow().stale(generation) {
                    return;
                }
            }

            // Our own probe. `ping_outstanding` is stamped HERE, where
            // the frame reaches the wire -- not where the ping was
            // requested -- so the verdict clock measures the peer's
            // silence and not our own scheduling.
            let ping = {
                let mut inner = state.inner.borrow_mut();
                if state.proto == Proto::V3 && inner.ping_due && inner.ping_outstanding.is_none() {
                    inner.ping_due = false;
                    inner.ping_counter += 1;
                    let payload = inner.ping_counter;
                    inner.ping_outstanding = Some(now_ms());
                    Some(wosh_tunnel::encode_ping(payload))
                } else {
                    // A request that arrives while a probe is already
                    // in flight is simply kept: the outstanding probe
                    // is already asking the only question it had, and
                    // the next inbound frame clears the way.
                    None
                }
            };
            if let Some(frame) = ping {
                if send.write(frame).await.is_err() {
                    link_lost(&state, generation, "connection closed: ping write failed").await;
                    return;
                }
                if state.inner.borrow().stale(generation) {
                    return;
                }
            }

            let next = {
                let mut inner = state.inner.borrow_mut();
                let bytes = inner.outbox.pop_front();
                // Record BEFORE the write: a write that fails partway
                // may still have put bytes on the wire, and the peer's
                // ACK is what decides what was really received.
                if framed {
                    if let Some(b) = bytes.as_deref() {
                        inner.replay.sent(b);
                    }
                }
                bytes
            };
            let Some(bytes) = next else { break };
            if write_data(&send, framed, &bytes).await.is_err() {
                link_lost(&state, generation, "connection closed: write failed").await;
                return;
            }
            if state.inner.borrow().stale(generation) {
                return;
            }
            // Interactive probe: we just spoke into a link that has
            // been quiet a while, which is the shape of a user typing
            // into a black hole. Ask for a ping now rather than at the
            // prober's leisure -- the control block at the top of this
            // inner loop sends it on the very next turn, so the
            // verdict lands in ~5-7s instead of the 30 QUIC would take.
            if state.proto == Proto::V3 {
                let mut inner = state.inner.borrow_mut();
                if inner.ping_outstanding.is_none()
                    && !inner.ping_due
                    && now_ms().saturating_sub(inner.last_inbound_ms) >= INTERACTIVE_PROBE_MS
                {
                    inner.ping_due = true;
                }
            }
        }
        if state.inner.borrow().detached {
            return;
        }
    }
}

// --- the resume machine ---------------------------------------------
//
// Everything from here to `handshake` is the client half of session
// resume. Entry point: `link_lost`, called by whichever task first
// observes the transport dying.

/// The transport under `generation` died. In legacy mode -- or once the
/// session is detached -- that is the end, exactly as before. In v2 it
/// starts a resume: the SSH core is NOT told, `link_down` stays false,
/// and the session merely stalls while `resume_loop` redials.
async fn link_lost(state: &Rc<State>, generation: u64, reason: &str) {
    enum Next {
        Retire,
        Die,
        Resume,
    }
    let next = {
        let mut inner = state.inner.borrow_mut();
        if inner.stale(generation) || inner.detached {
            // Superseded, or the page already tore the session down:
            // the new connection (or `detach`) owns the outcome.
            Next::Retire
        } else if state.proto == Proto::V1 {
            Next::Die
        } else if inner.resuming {
            // Both tasks of this generation noticed the same death.
            // Exactly one runs the loop.
            Next::Retire
        } else if inner.suspended {
            // The page is away. Redialing now would be a radio wake-up
            // for a network that is not there; the listener holds the
            // session parked either way. `wake` picks this up.
            inner.stalled = true;
            Next::Retire
        } else {
            inner.resuming = true;
            Next::Resume
        }
    };
    match next {
        Next::Retire => {}
        Next::Die => declare_dead(state, reason).await,
        Next::Resume => {
            // The one diagnostic channel this component has is stderr;
            // a transport death is exactly when it earns its keep.
            eprintln!("resume: transport lost ({reason}); redialing");
            resume_loop(state, generation).await;
        }
    }
}

/// The session is over: today's death path, verbatim.
async fn declare_dead(state: &Rc<State>, reason: &str) {
    {
        let mut inner = state.inner.borrow_mut();
        if inner.link_down {
            return;
        }
        inner.resuming = false;
        inner.link_down = true;
        // The machine-readable half, decided by whether this session
        // ever got off the ground: a transport death after `ready` is
        // a session LOST (a fresh one on the same parameters is a
        // sensible reaction), before it a session that FAILED.
        inner.close_kind = Some(if inner.was_ready {
            CloseKind::Lost
        } else {
            CloseKind::Failed
        });
        inner.core.wire_broken(reason);
    }
    drive(state).await;
    state.status_signal.notify();
}

/// Redial and re-handshake until the session is back or the attempt
/// budget is spent.
///
/// While this runs the core is untouched and healthy: `write-input`,
/// `resize` and `drain-output` keep working, and the bytes the core
/// produces pile up in `outbox` (bounded by the core's own buffering)
/// until a writer task exists again.
async fn resume_loop(state: &Rc<State>, generation: u64) {
    // Tear down what we still hold of the dead attempt. `close` is
    // idempotent; we do NOT await `wait-closed` here -- the connection
    // is already gone, and the point of closing is to make the
    // superseded reader's in-flight `read` return so it can retire.
    // The endpoint and the pairing identity are session-lifetime and
    // stay untouched (see `State`).
    let old = state.inner.borrow().conn.clone();
    old.close(0, "resuming");
    drop(old);

    let (addr, pairing) = (state.addr.clone(), state.pairing.clone());

    // Budget spent, in milliseconds of trying. See RESUME_WINDOW_MS:
    // this is deliberately not `now_ms() - started`.
    //
    // Charged in two places, both of which every route out of an
    // attempt must pass through: the sleep charges itself, and the top
    // of the loop charges the attempt that just ended. Nothing is
    // charged where an attempt FAILS, because there are several such
    // places and one of them will eventually be written without it --
    // which is exactly the bug this arrangement exists to make
    // unwritable (an uncharged failure path is an infinite retry: the
    // budget stops advancing and the give-up below is unreachable).
    let mut spent = 0u64;
    let mut attempt_started = now_ms();
    let mut backoff = RESUME_BACKOFF_START_MS;
    // The sleep charges what it ASKED for, whatever the clock says it
    // actually took: a phone suspended mid-backoff, or a hidden tab
    // whose timers are throttled to a fraction of the rate they
    // requested, must not pay for time it could not use.
    macro_rules! backoff_sleep {
        () => {{
            spent += backoff;
            sleep_ms(backoff).await;
            backoff = (backoff * 2).min(RESUME_BACKOFF_CAP_MS);
        }};
    }
    macro_rules! next_attempt {
        ($cleanup:stmt) => {{
            $cleanup
            backoff_sleep!();
            continue;
        }};
    }

    loop {
        // The attempt that just ended costs what it took, capped: one
        // that appears to have taken minutes was suspended, not slow.
        // Unconditional, so no `continue` above can dodge it.
        spent += now_ms()
            .saturating_sub(attempt_started)
            .min(RESUME_ATTEMPT_CAP_MS);
        attempt_started = now_ms();

        // Every await below is a place the page may have detached or a
        // later resume may have won; re-check on the way back.
        if abandoned(state, generation) {
            return;
        }
        // The page went away since the last pass. Stop here rather
        // than at the end of the budget: what is left of it is worth
        // more when there is a page to see the result.
        if stand_down(state) {
            return;
        }
        if spent > RESUME_WINDOW_MS {
            break;
        }

        // REPLAY_CAP bounds what a resume can bridge. If the outbound
        // buffer overflowed while we were disconnected, the peer's
        // missing bytes are simply gone: refuse now, legibly, rather
        // than reconnect into a corrupt ssh stream that fails opaquely
        // later (wosh-tunnel module docs, "Buffer discipline").
        if state.inner.borrow().replay.overflowed {
            declare_dead(state, "resume impossible: unacknowledged data exceeded the replay buffer")
                .await;
            return;
        }

        // The session's OWN dialect, no ladder: a listener that
        // answers only v1 cannot resume anything, so there is no
        // fallback to fall back to, and a v3 session redialing v2
        // would silently lose the liveness frames it depends on. The
        // Rc is cloned out so no RefCell borrow spans the await.
        let ep = state.endpoint.borrow().clone();
        let dialed = ep.connect(addr.clone(), state.proto.alpn().to_vec()).await;
        drop(ep);
        let conn = match dialed {
            Ok(conn) => conn,
            Err(e) => {
                if abandoned(state, generation) {
                    return;
                }
                // The likeliest cause of a dead dial is a dead ENDPOINT:
                // it shares fate with its relay websocket, so a relay
                // restart strands it (every later connect fails Closed).
                // Rebind from the same pairing identity -- same client
                // endpoint id, which the resume authorization keys on --
                // and let the next attempt use the fresh one. Mirrors the
                // listener's own accept-loop rebind.
                eprintln!("resume: dial failed ({e:?}); rebinding the endpoint");
                rebind_endpoint(state).await;
                backoff_sleep!();
                continue;
            }
        };
        if abandoned(state, generation) {
            conn.close(0, "detached");
            return;
        }
        let conn = Rc::new(conn);

        let Ok((send, recv)) = conn.open_bi().await else {
            next_attempt!(conn.close(0, "open-bi failed"));
        };
        if abandoned(state, generation) {
            conn.close(0, "detached");
            return;
        }

        let (session_id, received) = {
            let inner = state.inner.borrow();
            (inner.session_id, inner.received)
        };
        let hello = Hello {
            pairing: pairing.clone(),
            resume: Some(Resume { session_id, received }),
        };
        let mut decoder = Decoder::new();
        let outcome = handshake(&send, &recv, &mut decoder, &hello).await;
        if abandoned(state, generation) {
            conn.close(0, "detached");
            return;
        }
        let (reply, deferred) = match outcome {
            Ok(v) => v,
            Err(e) => {
                // A handshake that dies mid-flight is just another dead
                // attempt; the window covers it.
                eprintln!("resume: handshake failed ({e}); retrying");
                next_attempt!(conn.close(0, "resume handshake failed"));
            }
        };

        match reply {
            HelloReply::Resumed { received: peer_received } => {
                let tail = {
                    let mut inner = state.inner.borrow_mut();
                    // Tail BEFORE ack: `ack` trims the buffer to the
                    // peer's count, which is exactly the tail's start.
                    let tail = inner.replay.tail_from(peer_received);
                    if tail.is_some() {
                        inner.replay.ack(peer_received);
                    }
                    tail
                };
                let Some(tail) = tail else {
                    // A gap: the peer wants bytes we no longer hold.
                    // Unrecoverable by construction.
                    conn.close(0, "replay gap");
                    declare_dead(
                        state,
                        "resume impossible: the listener asked for data no longer buffered",
                    )
                    .await;
                    return;
                };
                eprintln!("resume: session resumed (retransmitting {} bytes)", tail.len());
                install_connection(state, conn, send, recv, decoder, deferred, tail).await;
                return;
            }
            HelloReply::New { .. } => {
                // The listener minted a FRESH session instead of
                // resuming ours: our ssh stream cannot continue on it.
                conn.close(0, "unexpected new session");
                declare_dead(state, "resume refused: the listener started a new session").await;
                return;
            }
            HelloReply::Refused { reason } => {
                conn.close(0, "resume refused");
                declare_dead(state, &format!("resume refused: {reason}")).await;
                return;
            }
        }
    }

    declare_dead(
        state,
        &format!(
            "connection lost and could not be resumed within {}s",
            RESUME_WINDOW_MS / 1000
        ),
    )
    .await;
}

/// The page suspended mid-resume: leave the session stalled -- neither
/// attached nor dead -- for `wake` to pick up, and stop redialing. The
/// listener is holding it parked regardless; the only thing another
/// attempt would buy is a radio wake-up on a device that cannot
/// answer.
fn stand_down(state: &Rc<State>) -> bool {
    let mut inner = state.inner.borrow_mut();
    if !inner.suspended {
        return false;
    }
    inner.resuming = false;
    inner.stalled = true;
    true
}

/// True when the resume should stop touching the session: the page
/// detached, or this resume was superseded.
fn abandoned(state: &Rc<State>, generation: u64) -> bool {
    let inner = state.inner.borrow();
    inner.detached || inner.link_down || inner.stale(generation)
}

/// Replace the session's endpoint with a freshly-bound one (same
/// pairing identity, same options as the original dial). Best-effort:
/// on bind failure the old endpoint stays and the caller's backoff
/// retries the whole attempt.
async fn rebind_endpoint(state: &Rc<State>) {
    let options = EndpointOptions::new(&state.identity);
    options.add_alpn(ALPN_V3);
    options.add_alpn(ALPN_V2);
    options.add_alpn(ALPN_V1);
    options.relay_url(&state.relay_url);
    options.webrtc(true);
    match Endpoint::bind(options).await {
        Ok(ep) => {
            // Swapping drops the old endpoint's last Rc unless a dial
            // still holds a clone; either way the host releases it.
            *state.endpoint.borrow_mut() = Rc::new(ep);
        }
        Err(e) => eprintln!("resume: endpoint rebind failed ({e:?}); retrying on the old one"),
    }
}

/// Adopt a freshly-handshaked connection: bump the generation (which
/// retires the superseded tasks), feed anything the listener pipelined
/// ahead of the reply, and spawn the new pump.
async fn install_connection(
    state: &Rc<State>,
    conn: Rc<Connection>,
    send: SendStream,
    recv: RecvStream,
    decoder: Decoder,
    deferred: Vec<Vec<u8>>,
    tail: Vec<u8>,
) {
    let generation = {
        let mut inner = state.inner.borrow_mut();
        inner.conn = conn;
        inner.resuming = false;
        inner.ack_due = false;
        // Liveness is a property of THIS connection and does not
        // survive one (wosh-tunnel liveness rules): the new link is
        // demonstrably alive as of right now, and a probe or an echo
        // owed on the dead one is meaningless.
        inner.last_inbound_ms = now_ms();
        inner.ping_due = false;
        inner.ping_outstanding = None;
        inner.pong_due.clear();
        inner.generation += 1;
        for payload in &deferred {
            inner.core.feed(payload);
            inner.received += payload.len() as u64;
        }
        inner.generation
    };

    // The reader task starts from the decoder the handshake left, so
    // frames that arrived in the same packet as the reply are not lost.
    wit_bindgen::spawn_local(reader_task_with(state.clone(), recv, generation, decoder));
    wit_bindgen::spawn_local(writer_task(state.clone(), send, generation, tail));
    if state.proto == Proto::V3 {
        wit_bindgen::spawn_local(keepalive_task(state.clone(), generation));
    }

    // Anything the core produced while we were disconnected is waiting
    // in the outbox; wake the new writer for it.
    state.writer_signal.notify();
    drive(state).await;
}

/// `reader_task` seeded with a decoder that may already hold buffered
/// frames from the handshake read.
async fn reader_task_with(
    state: Rc<State>,
    recv: RecvStream,
    generation: u64,
    mut decoder: Decoder,
) {
    match consume_frames(&state, &mut decoder) {
        Ok(fed) => {
            if fed {
                drive(&state).await;
            }
        }
        Err(reason) => {
            link_lost(&state, generation, &format!("tunnel: {reason}")).await;
            return;
        }
    }
    if state.inner.borrow().stale(generation) {
        return;
    }
    reader_task(state, recv, generation).await;
}

/// Write a `Hello` and read frames until the listener's reply.
///
/// DATA and ACK frames that precede the reply are not an error -- the
/// listener may pipeline a retransmission behind its `Resumed` in one
/// packet, and nothing in the protocol forbids the reverse order. DATA
/// payloads are handed back so the caller can feed them in order once
/// the reply has been acted on; ACKs cannot be applied here (no state
/// access) and are dropped, which is safe because acks are cumulative
/// and the next one supersedes them.
async fn handshake(
    send: &SendStream,
    recv: &RecvStream,
    decoder: &mut Decoder,
    hello: &Hello,
) -> Result<(HelloReply, Vec<Vec<u8>>), String> {
    send.write(wosh_tunnel::encode_hello(hello))
        .await
        .map_err(err("tunnel hello write"))?;
    let mut deferred = Vec::new();
    loop {
        loop {
            match decoder.next_frame()? {
                Some(Frame::Reply(reply)) => return Ok((reply, deferred)),
                Some(Frame::Data(payload)) => deferred.push(payload),
                Some(Frame::Ack(_)) => {}
                Some(Frame::Hello(_)) => return Err("listener sent a hello".into()),
                // The listener's FIRST frame is its reply
                // (wosh-tunnel `HelloReply` docs); liveness frames
                // before it are not a protocol this client speaks.
                Some(Frame::Ping(_)) | Some(Frame::Pong(_)) => {
                    return Err("listener sent a liveness frame before replying".into())
                }
                None => break,
            }
        }
        match recv.read(READ_CHUNK).await {
            Ok(Some(bytes)) => decoder.feed(&bytes),
            Ok(None) => return Err("listener closed before replying".into()),
            Err(e) => return Err(format!("tunnel hello read: {e:?}")),
        }
    }
}


pub struct Session {
    state: Rc<State>,
}

struct Component;

impl Guest for Component {
    type Session = Session;
    type Transfer = transfer::TransferHandle;

    /// This browser's SSH identity as an OpenSSH `authorized_keys`
    /// line. Only the public half crosses `identity-store`; the private
    /// half is a non-extractable WebCrypto key the host holds, so
    /// nothing here, in the page, or in an XSS payload can read it out.
    /// Fetched once per instance and cached.
    async fn identity_openssh() -> Result<String, String> {
        // Cached per component instance. Checked and released before
        // any await; the fetch may run twice under concurrent first
        // calls, which is harmless (the store's key is stable).
        if let Some(line) = IDENTITY_LINE.with(|c| c.borrow().clone()) {
            return Ok(line);
        }
        let raw = identity_store::public_key()
            .await
            .map_err(|e| format!("obtain ssh identity: {e}"))?;
        let line = passkey::browser_line(&raw)?;
        IDENTITY_LINE.with(|c| *c.borrow_mut() = Some(line.clone()));
        Ok(line)
    }

    /// The enrolled passkey's `authorized_keys` line, or `none`.
    ///
    /// Deliberately NOT cached, unlike the browser key's line: a
    /// passkey can be enrolled, adopted or forgotten while the page
    /// lives, and a stale line here would be shown to a user about to
    /// paste it into a server.
    async fn passkey_openssh() -> Result<Option<String>, String> {
        match passkey::identity().await? {
            Some(identity) => Ok(Some(passkey::passkey_line(&identity)?)),
            None => Ok(None),
        }
    }

    /// Enrol a passkey and return the line to install on the target.
    async fn enroll_passkey() -> Result<String, String> {
        passkey::enroll().await
    }

    /// Adopt an identity from the line another device printed.
    async fn adopt_passkey(line: String) -> Result<String, String> {
        passkey::adopt(&line).await
    }

    /// Stop offering the enrolled passkey.
    async fn forget_passkey() -> Result<(), String> {
        passkey::forget().await
    }

    /// Work the passkey identity back out of the credential itself,
    /// for when this browser's storage did not survive but the passkey
    /// did.
    async fn recover_passkey() -> Result<String, String> {
        passkey::recover().await
    }
}

thread_local! {
    static IDENTITY_LINE: RefCell<Option<String>> = const { RefCell::new(None) };
}

impl Session {
    /// Read the raw public half of this browser's identity, mapping
    /// store failures into the caller's `result`.
    async fn identity_public_key() -> Result<Vec<u8>, String> {
        identity_store::public_key()
            .await
            .map_err(|e| format!("obtain ssh identity: {e}"))
    }

    /// This browser's key, as an offer for the SSH core.
    async fn browser_offer() -> Result<CoreKey, String> {
        passkey::browser_key(&Self::identity_public_key().await?)
    }

    /// The enrolled passkey as an offer, or `None` if none is enrolled.
    async fn passkey_offer() -> Result<Option<CoreKey>, String> {
        match passkey::identity().await? {
            Some(identity) => Ok(Some(passkey::passkey_key(&identity)?)),
            None => Ok(None),
        }
    }
}

impl GuestSession for Session {
    /// Dial the listener and start the SSH transport handshake.
    /// Resolves once the dial either succeeded (poll `status` from
    /// here) or failed outright -- the handshake itself runs on the
    /// reader task's fed bytes.
    async fn connect(
        connstring: String,
        user: String,
        cols: u16,
        rows: u16,
        command: Option<String>,
    ) -> Result<bindings::exports::wosh::terminal::terminal::Session, String> {
        let parsed =
            ConnString::decode(&connstring).map_err(|e| format!("connection string: {e}"))?;

        // The pairing identity: persistent wherever the host can store
        // it, so the listener can remember this client across visits
        // ("pairing" in the meaningful sense -- an enrolled client
        // reconnects even after the listener rotates its token). It
        // names this client on the iroh layer only and is unrelated to
        // the SSH identity behind `identity-store`.
        let identity = pairing::load_or_create().await.map_err(err("iroh identity"))?;
        let options = EndpointOptions::new(&identity);
        // Every ALPN is offered so the fallback ladder below needs no
        // second endpoint. The dial picks which one is used.
        options.add_alpn(ALPN_V3);
        options.add_alpn(ALPN_V2);
        options.add_alpn(ALPN_V1);
        options.relay_url(&parsed.relay_url);
        // No udp-bind-addr: a browser has no direct UDP path, and the
        // wasi:sockets providers there are fail-on-call stubs (binding
        // with it set fails `not-supported`). WebRTC is the only
        // upgrade off the relay available to us, and the listener
        // answers that signaling.
        options.webrtc(true);
        let endpoint = Endpoint::bind(options).await.map_err(err("iroh bind"))?;

        let addr = EndpointAddr {
            endpoint_id: parsed.pubkey.to_vec(),
            addrs: vec![
                TransportAddr::Relay(parsed.relay_url.clone()),
                TransportAddr::Webrtc(parsed.relay_url.clone()),
            ],
        };
        // The token itself never goes on the wire: what the listener
        // sees is a proof over both endpoint identities and the ALPN,
        // keyed by it (wosh_connstring::pairing_proof). It is computed
        // per dialect below, because the ALPN is part of what the
        // proof binds, and stored rather than the token so that every
        // later Hello (resume replays one) presents the same value.
        //
        // A tokenless connstring stays an empty field, exactly as
        // before: open mode has nothing to prove.
        let client_id: [u8; wosh_connstring::PUBKEY_LEN] = endpoint
            .id()
            .try_into()
            .map_err(|_| "endpoint id is not 32 bytes".to_string())?;
        let prove = |alpn: &[u8]| -> Vec<u8> {
            match parsed.token {
                Some(t) => {
                    wosh_connstring::pairing_proof(&t, &parsed.pubkey, &client_id, alpn).to_vec()
                }
                None => Vec::new(),
            }
        };

        // The connection is authenticated against the connstring's
        // public key: a peer holding a different key never connects.
        //
        // v3, then v2, then v1: one rung per dial. The ladder is not
        // decoration: the page is deployed independently of the
        // listeners people already run, so a browser that has just
        // picked up liveness frames must still reach a listener that
        // only speaks resumable v2 -- or the old raw pipe. An ALPN
        // mismatch surfaces as a failed `connect`, which is why the
        // retries hang off the dial rather than off anything later.
        let (conn, proto) = match endpoint.connect(addr.clone(), ALPN_V3.to_vec()).await {
            Ok(conn) => (conn, Proto::V3),
            Err(v3_err) => match endpoint.connect(addr.clone(), ALPN_V2.to_vec()).await {
                Ok(conn) => (conn, Proto::V2),
                Err(_) => match endpoint.connect(addr.clone(), ALPN_V1.to_vec()).await {
                    Ok(conn) => (conn, Proto::V1),
                    // Report the v3 failure: it is the one that
                    // describes the listener people are actually
                    // expected to run.
                    Err(_) => return Err(err("iroh connect")(v3_err)),
                },
            },
        };
        let conn = Rc::new(conn);

        let (send, recv) = conn.open_bi().await.map_err(err("iroh open-bi"))?;

        // The handshake, in whichever dialect the dial settled on.
        let mut decoder = Decoder::new();
        let mut deferred: Vec<Vec<u8>> = Vec::new();
        let mut session_id = [0u8; 16];
        if proto == Proto::V1 {
            // v1's pairing frame: [len:u8][token], written before any
            // ssh byte and before the writer task exists, so it is
            // trivially ordered ahead of everything the core produces.
            // An absent token is a zero-length field. No ack is
            // expected: a rejected token means the listener drops the
            // connection, which surfaces as the ssh handshake seeing
            // the stream end. (v2 replaces that silent drop with a
            // `Refused` reply -- see below.)
            let proof = prove(ALPN_V1);
            debug_assert!(proof.len() <= u8::MAX as usize);
            let mut hello = Vec::with_capacity(1 + proof.len());
            hello.push(proof.len() as u8);
            hello.extend_from_slice(&proof);
            send.write(hello).await.map_err(err("pairing"))?;
        } else {
            let hello = Hello { pairing: prove(proto.alpn()), resume: None };
            let (reply, pre) = handshake(&send, &recv, &mut decoder, &hello)
                .await
                .map_err(|e| format!("tunnel handshake: {e}"))?;
            deferred = pre;
            match reply {
                // The id is the resume capability; it is never logged
                // in full anywhere in this component.
                HelloReply::New { session_id: id } => session_id = id,
                HelloReply::Refused { reason } => {
                    conn.close(0, "refused");
                    return Err(format!("listener refused the connection: {reason}"));
                }
                HelloReply::Resumed { .. } => {
                    conn.close(0, "unexpected resume");
                    return Err("listener resumed a session we never had".into());
                }
            }
        }

        // `user` is snapshotted by the core's config before the
        // handshake, but is only ever SENT inside an auth request,
        // which cannot happen before the host-key gate resolves.
        //
        // `command` rides only on this initial connect, never on a
        // transport resume: resume never re-creates the core session
        // (see terminal.wit `connect`), so an exec request runs
        // exactly once per SSH session regardless of how many times
        // the underlying tunnel reconnects.
        let core = CoreSession::connect(&user, cols, rows, command.as_deref());

        let state = Rc::new(State {
            inner: RefCell::new(Inner {
                core,
                conn,
                generation: 0,
                outbox: VecDeque::new(),
                link_down: false,
                signing: false,
                detached: false,
                session_id,
                replay: Replay::new(),
                received: 0,
                acked_to_peer: 0,
                ack_due: false,
                resuming: false,
                suspended: false,
                stalled: false,
                // The connection is up as of now; that IS the last
                // inbound evidence we have.
                last_inbound_ms: now_ms(),
                ping_outstanding: None,
                ping_due: false,
                pong_due: VecDeque::new(),
                ping_counter: 0,
                was_ready: false,
                close_kind: None,
            }),
            proto,
            endpoint: RefCell::new(Rc::new(endpoint)),
            identity,
            relay_url: parsed.relay_url.clone(),
            addr,
            // A resume redials the session's own dialect
            // (`State.proto`), and the proof binds the ALPN, so the
            // one stored here is the one every resume replays.
            pairing: prove(proto.alpn()),
            sftp: RefCell::new(None),
            sftp_opening: Cell::new(false),
            transfer_budget: Rc::new(RefCell::new(transfer::Budget::new(
                transfer::REPLAY_BUDGET_BYTES,
            ))),
            writer_signal: Signal::default(),
            status_signal: Signal::default(),
        });

        // Bytes the listener pipelined ahead of its reply (rare, but
        // legal) belong to the ssh stream and go in first.
        if !deferred.is_empty() {
            let mut inner = state.inner.borrow_mut();
            for payload in &deferred {
                inner.core.feed(payload);
                inner.received += payload.len() as u64;
            }
        }

        // The core emits its client version banner during connect; the
        // server will not speak until it arrives, so queue it before
        // anything parks. (`drive` here cannot reach `signing`.)
        drive(&state).await;

        // --- reader task: never cancelled -------------------------
        if proto == Proto::V1 {
            wit_bindgen::spawn_local(reader_task(state.clone(), recv, 0));
        } else {
            wit_bindgen::spawn_local(reader_task_with(state.clone(), recv, 0, decoder));
        }
        // --- writer task: the only writer of `send` ---------------
        wit_bindgen::spawn_local(writer_task(state.clone(), send, 0, Vec::new()));
        // --- liveness prober: the one clock-driven task -----------
        if proto == Proto::V3 {
            wit_bindgen::spawn_local(keepalive_task(state.clone(), 0));
        }

        Ok(
            bindings::exports::wosh::terminal::terminal::Session::new(Session {
                state,
            }),
        )
    }

    /// The page's view of where the session stands. Two shaping rules
    /// on top of the core's status, both mirroring the previous Go
    /// client's `Status()`:
    ///
    /// * `signing` is an internal park -- this component answers it
    ///   from `drive` without the page's help -- so it reports as
    ///   `authenticating`. The page never sees `signing`; it is not
    ///   even in terminal.wit's variant.
    /// * a dead link that the core has not yet turned into `closed`
    ///   (its goroutines observe `wire-broken` on a later tick) reports
    ///   as `closed` with the phase it died in, so the page never sits
    ///   on `connecting` forever after the wire went out.
    ///
    /// A resume in flight is deliberately NOT shaped: `link_down` stays
    /// false, so this reports whatever the core reports. The core IS
    /// healthy -- it is mid-session and simply not receiving bytes --
    /// and claiming `closed` for a session that is about to continue
    /// would be a lie the page could not take back. Output stalls;
    /// nothing else changes.
    async fn status(&self) -> Status {
        let inner = self.state.inner.borrow();
        let core_status = inner.core.status();
        if let CoreStatus::Closed(reason) = core_status {
            return Status::Closed(reason);
        }
        if inner.link_down {
            let phase = match core_status {
                CoreStatus::Ready => "the session",
                CoreStatus::Authenticating | CoreStatus::Signing | CoreStatus::AuthPrompts => {
                    "authentication"
                }
                _ => "the handshake",
            };
            return Status::Closed(format!("connection closed during {phase}"));
        }
        match core_status {
            CoreStatus::Connecting => Status::Connecting,
            CoreStatus::HostKeyCheck => Status::HostKeyCheck,
            CoreStatus::Authenticating | CoreStatus::Signing => Status::Authenticating,
            CoreStatus::AuthPrompts => Status::AuthPrompts,
            CoreStatus::Ready => Status::Ready,
            CoreStatus::Closed(reason) => Status::Closed(reason),
        }
    }

    /// Where the TRANSPORT stands, which `status` deliberately will
    /// not tell (see terminal.wit): a resume in flight keeps reporting
    /// whatever the core reports, because the SSH session really is
    /// alive and merely stalled. This is the orthogonal answer.
    async fn link_state(&self) -> LinkState {
        let inner = self.state.inner.borrow();
        if inner.resuming {
            LinkState::Reconnecting
        } else if inner.stalled {
            LinkState::Stalled
        } else {
            LinkState::Attached
        }
    }

    /// Why the session ended, machine-readably; `none` while it lives.
    /// The point is that a page can decide about reconnecting without
    /// reading the human-readable reason string.
    async fn close_kind(&self) -> Option<WitCloseKind> {
        let inner = self.state.inner.borrow();
        if let Some(kind) = inner.close_kind {
            return Some(match kind {
                CloseKind::Ended => WitCloseKind::Ended,
                CloseKind::Failed => WitCloseKind::Failed,
                CloseKind::Lost => WitCloseKind::Lost,
            });
        }
        if matches!(inner.core.status(), CoreStatus::Closed(_)) {
            // The core ended it, not the wire: a session that had
            // reached `ready` concluded at the protocol level (shell
            // exit, server disconnect, detach); one that never did
            // failed on the way up.
            return Some(if inner.was_ready {
                WitCloseKind::Ended
            } else {
                WitCloseKind::Failed
            });
        }
        if inner.link_down {
            // Defensive: `declare_dead` is the only setter of
            // `link_down` and it always records a kind, so this arm
            // should be unreachable.
            return Some(WitCloseKind::Lost);
        }
        None
    }

    async fn host_key_fingerprint(&self) -> Option<String> {
        self.state.inner.borrow().core.host_key_sha256()
    }

    /// Record the user's verdict. Accepting merely latches consent (the
    /// core proceeds once a credential is also on offer, in whichever
    /// order the two arrive). Rejecting fails the core's handshake --
    /// with no credentials ever sent -- and then tears the iroh
    /// connection down: there is nothing left to say to that peer.
    async fn confirm_host_key(&self, accept: bool) {
        self.state.inner.borrow().core.confirm_host_key(accept);
        drive(&self.state).await;
        if !accept {
            let conn = self.state.inner.borrow().conn.clone();
            conn.close(0, "host key rejected");
            let _ = conn.wait_closed().await;
        }
    }

    /// Offer a password. Latches the credential and RESOLVES AT ONCE
    /// (terminal.wit): authentication runs on the reader task's fed
    /// bytes, so the page polls `status`. The core refuses the
    /// credential outright if the host key has not been confirmed --
    /// nothing is sent to an unapproved server.
    async fn authenticate_password(&self, password: String) -> Result<(), String> {
        let res = self
            .state
            .inner
            .borrow()
            .core
            .authenticate_password(&password);
        drive(&self.state).await;
        res
    }

    /// Authenticate with this browser's non-extractable key. Only the
    /// public half is handed to the core; when the ssh stack needs a
    /// signature it parks at `signing` and `drive` relays the request
    /// to the host's store. Same latch-then-poll contract.
    async fn authenticate_publickey(&self) -> Result<(), String> {
        let keys = vec![Self::browser_offer().await?];
        let res = self
            .state
            .inner
            .borrow()
            .core
            .authenticate_publickey(&keys);
        drive(&self.state).await;
        res
    }

    /// Authenticate with the enrolled passkey. Offering it is all this
    /// does; the ceremony happens later, when the server asks for a
    /// signature and `drive` routes the request to `passkey-store`.
    async fn authenticate_passkey(&self) -> Result<(), String> {
        let key = Self::passkey_offer().await?.ok_or_else(|| {
            "no passkey is enrolled on this device -- enrol one, or adopt the line \
             from a device that already has it"
                .to_string()
        })?;
        let res = self
            .state
            .inner
            .borrow()
            .core
            .authenticate_publickey(&[key]);
        drive(&self.state).await;
        res
    }

    /// Start keyboard-interactive auth. The server drives the batches;
    /// each parks the core at `auth-prompts` until `answer-prompts`.
    async fn authenticate_interactive(&self) -> Result<(), String> {
        let res = self.state.inner.borrow().core.authenticate_interactive();
        drive(&self.state).await;
        res
    }

    /// Let the server steer method selection, stock-ssh style.
    ///
    /// Both keys are offered when both exist, passkey first: the core
    /// offers each unsigned before signing for any, so a server that
    /// will not take webauthn (too old, or configured against it)
    /// declines the passkey and the browser key answers instead --
    /// inside the same connection, with no ceremony spent. A store
    /// that cannot produce the browser key is reported rather than
    /// silently downgrading the offer; a passkey-store that fails is
    /// treated the same way, since an enrolled passkey the user cannot
    /// use is worth saying out loud.
    async fn authenticate_auto(&self) -> Result<(), String> {
        let mut keys = Vec::with_capacity(2);
        if let Some(key) = Self::passkey_offer().await? {
            keys.push(key);
        }
        keys.push(Self::browser_offer().await?);
        let res = self.state.inner.borrow().core.authenticate_auto(&keys);
        drive(&self.state).await;
        res
    }

    async fn pending_prompts(&self) -> Option<PromptBatch> {
        self.state
            .inner
            .borrow()
            .core
            .pending_prompts()
            .map(|b| PromptBatch {
                instruction: b.instruction,
                prompts: b
                    .prompts
                    .into_iter()
                    .map(|p| Prompt {
                        text: p.text,
                        echo: p.echo,
                    })
                    .collect(),
            })
    }

    /// Answer the pending batch. Latches and RESOLVES AT ONCE, like
    /// every credential-bearing export here; the exchange continues on
    /// the reader task's next fed bytes.
    async fn answer_prompts(&self, answers: Vec<String>) -> Result<(), String> {
        let res = self.state.inner.borrow().core.answer_prompts(&answers);
        drive(&self.state).await;
        res
    }

    async fn write_input(&self, data: Vec<u8>) {
        self.state.inner.borrow().core.write_input(&data);
        drive(&self.state).await;
    }

    async fn resize(&self, cols: u16, rows: u16) {
        self.state.inner.borrow().core.resize(cols, rows);
        drive(&self.state).await;
    }

    /// Run a one-shot command on the core's second (probe) channel and
    /// wait for its result, without disturbing `write-input`/
    /// `drain-output`'s interactive channel at all.
    ///
    /// `probe-start` is a state-changing core call like any other, so
    /// it gets the same `drive`-shaped treatment: drain to the outbox
    /// and wake the writer immediately after. But the ANSWER does not
    /// arrive that way -- `probe-poll` only ever reports what a `pump`
    /// tick turned up (core.wit's progress contract), and nothing here
    /// wakes this task when that happens. So this export owns its own
    /// small poll loop: sleep the same tick the keepalive prober uses
    /// ([`sleep_ms`]/[`PROBE_POLL_TICK_MS`]), `pump` the core, drain
    /// and wake exactly as `write-input` does, then check
    /// `probe-poll`. `PROBE_DEADLINE_MS` bounds the wait -- the core
    /// itself is timer-free by design, so the deadline belongs here.
    ///
    /// Every borrow below is taken, used synchronously, and dropped
    /// before the next `.await` (module header): holding a `RefCell`
    /// borrow across a suspension point is the one hazard this file
    /// guards against everywhere.
    async fn probe(&self, command: String) -> Result<ProbeResult, String> {
        {
            let mut inner = self.state.inner.borrow_mut();
            inner.core.probe_start(&command)?;
            inner.take_core_output();
        }
        self.state.writer_signal.notify();

        let deadline = now_ms() + PROBE_DEADLINE_MS;
        loop {
            sleep_ms(PROBE_POLL_TICK_MS).await;

            let (result, closed_reason, wire_gone) = {
                let mut inner = self.state.inner.borrow_mut();
                inner.core.pump();
                inner.take_core_output();
                let result = inner.core.probe_poll();
                let closed_reason = match inner.core.status() {
                    CoreStatus::Closed(reason) => Some(reason),
                    _ => None,
                };
                (result, closed_reason, inner.link_down)
            };
            self.state.writer_signal.notify();

            if let Some(result) = result {
                return Ok(ProbeResult {
                    exit_status: result.exit_status,
                    output: result.output,
                });
            }
            if let Some(reason) = closed_reason {
                return Err(format!("session closed while probe was in flight: {reason}"));
            }
            if wire_gone {
                return Err("connection lost while probe was in flight".to_string());
            }
            if now_ms() >= deadline {
                return Err(
                    "probe timed out (still in flight on the target)".to_string(),
                );
            }
        }
    }

    /// Pty output buffered by the core since the last call. Purely a
    /// read of the core's buffer: it produces no wire bytes and cannot
    /// change state, so it needs no `drive`.
    async fn drain_output(&self) -> Vec<u8> {
        self.state.inner.borrow().core.drain_output()
    }

    async fn exited(&self) -> bool {
        let inner = self.state.inner.borrow();
        inner.core.exited() || inner.link_down
    }

    async fn exit_status(&self) -> Option<i32> {
        self.state.inner.borrow().core.exit_status()
    }

    /// The page is going away. See wit/terminal.wit: this spends no
    /// budget and tears nothing down; it only stops the redialing that
    /// a suspended device cannot complete anyway. A resume already in
    /// flight notices at its next await and stands down, leaving the
    /// session stalled rather than dead.
    async fn suspend(&self) {
        let mut inner = self.state.inner.borrow_mut();
        if inner.detached || inner.link_down || self.state.proto == Proto::V1 {
            return; // nothing to stand down, or nothing that could resume
        }
        inner.suspended = true;
        // A live connection is left exactly as it is: the OS may keep
        // it, and a short absence should cost nothing at all.
    }

    /// The page is back. If the transport went while we were away,
    /// start the resume now rather than at the end of a backoff sized
    /// for a page that was watching.
    async fn wake(&self) {
        let generation = {
            let mut inner = self.state.inner.borrow_mut();
            inner.suspended = false;
            if inner.detached || inner.link_down || !inner.stalled || inner.resuming {
                // Still connected, already resuming, or genuinely
                // over. The first of those is not automatically good
                // news: a page returning from hidden or frozen may be
                // holding a ZOMBIE connection -- one whose path died
                // while we were away and which will not fault until
                // QUIC's 30s idle timeout. Probe it immediately: a
                // genuinely live link answers with one cheap PONG, and
                // a dead one gets its verdict in seconds instead of
                // half a minute of typing into a void.
                let attached = !inner.detached
                    && !inner.link_down
                    && !inner.stalled
                    && !inner.resuming
                    && self.state.proto == Proto::V3;
                if attached {
                    // Clearing the outstanding probe FIRST is the
                    // point: one left over from before the freeze
                    // would otherwise look ancient against the clock
                    // that jumped forward, and the prober would call
                    // a live link dead on its next tick.
                    inner.ping_outstanding = None;
                    inner.last_inbound_ms = now_ms().saturating_sub(PING_AFTER_IDLE_MS);
                    inner.ping_due = true;
                }
                drop(inner);
                if attached {
                    self.state.writer_signal.notify();
                }
                return;
            }
            inner.stalled = false;
            inner.resuming = true;
            inner.generation
        };
        // Stand the resume up rather than riding it. This is a host
        // call, and the host keeps the component entered until the
        // call completes (the canonical enter/leave bracket) -- so
        // awaiting the loop here would hold the instance un-enterable
        // for the length of the redial, up to the whole resume window,
        // and every other page call (a keystroke, the output pump's
        // drain) would find the door shut. The spawned task carries
        // the generation; wake's caller needs "the resume has
        // started", never "finished".
        let state = self.state.clone();
        wit_bindgen::spawn_local(async move {
            resume_loop(&state, generation).await;
        });
    }

    // --- file transfer ---------------------------------------------
    //
    // All three delegate to `transfer`, which owns the SFTP channel, the
    // pump cadence, the replay-budget bound and every resume decision.
    // See that module's header.

    /// List a remote directory. Runs inline: a listing is bounded, so
    /// unlike a transfer it has no engine task of its own.
    async fn list_dir(&self, path: Vec<u8>) -> Result<Vec<DirEntry>, String> {
        transfer::list_dir(&self.state, path).await
    }

    /// Start an upload and return as soon as it is UNDERWAY
    /// (terminal.wit): everything after this point -- including every
    /// resume decision and every failure -- is reported through the
    /// returned resource's `progress`.
    async fn upload(
        &self,
        source: Source,
        remote_path: Vec<u8>,
        overwrite: bool,
    ) -> Result<Transfer, String> {
        transfer::start_upload(&self.state, source, remote_path, overwrite).await
    }

    /// The mirror image. Same contract: underway on return, outcome on
    /// the resource.
    async fn download(
        &self,
        remote_path: Vec<u8>,
        sink: Sink,
        overwrite: bool,
    ) -> Result<Transfer, String> {
        transfer::start_download(&self.state, remote_path, sink, overwrite).await
    }

    /// Stop the session and close the iroh connection. The core is
    /// closed first (it fails any parked gate and emits its final
    /// bytes -- a disconnect message), those bytes are drained, and
    /// only then does the connection go down.
    /// close first (`detached` is latched before anything awaits, and
    /// the resume loop re-checks it after every await).
    async fn detach(&self) {
        // Cheap Rc clone (a refcount bump, not a resource op) so the
        // close + wait-closed `.await`s happen with no borrow held.
        let conn = {
            let mut inner = self.state.inner.borrow_mut();
            inner.detached = true;
            inner.core.close();
            inner.conn.clone()
        };
        drive(&self.state).await;
        // Let the writer observe `detached` and retire even if the
        // core produced nothing.
        self.state.writer_signal.notify();
        conn.close(0, "detached");
        // Close-then-await: a bare `close` races the CONNECTION_CLOSE
        // frame reaching the wire, and the peer would then only learn
        // of the close via idle timeout. `wait-closed` is latched, so
        // this cannot hang a second detach.
        let _ = conn.wait_closed().await;
    }
}

bindings::export!(Component with_types_in bindings);
