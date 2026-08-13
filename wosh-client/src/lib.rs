//! `wosh-client`: the browser SSH client's I/O half (Rust component,
//! wac-composed with the sans-I/O Go `wosh:ssh-core` component and the
//! polymorph-iroh endpoint). It parses the connection string, dials the
//! listener over iroh, pumps bytes between that connection and the SSH
//! core, relays signature requests to the host's `identity-store`, and
//! exports the stable `wosh:terminal/terminal` interface the website
//! drives via deltic.
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
//! * **No timers anywhere.** The core's ssh path is timer-free and
//!   every state change is caused by a call this component makes, so
//!   liveness needs no clock -- and the exported interface carries no
//!   keepalive: wit-bindgen tracks the tasks spawned below.

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "wosh-client",
        generate_all,
    });
}

mod pairing;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::Future;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use bindings::exports::wosh::terminal::terminal::{
    Guest, GuestSession, Prompt, PromptBatch, Status,
};
use bindings::polymorph::iroh::endpoint::{Connection, Endpoint, EndpointOptions, RecvStream, SendStream};
use bindings::polymorph::iroh::identity::Identity;
use bindings::polymorph::iroh::types::{EndpointAddr, TransportAddr};
use bindings::wosh::ssh_core::core::{Session as CoreSession, Status as CoreStatus};
use bindings::wosh::terminal::identity_store;

use wosh_connstring::ConnString;

/// v0 connection ALPN. Must match the listener's.
const ALPN: &[u8] = b"wosh/1";

/// Read size for the reader task. Sized to comfortably hold a
/// full-size ssh packet; the core reassembles regardless.
const READ_CHUNK: u32 = 16 * 1024;

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
        // Borrow held only across `take()` -- no await under it.
        if let Some(w) = self.waker.borrow_mut().take() {
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
    conn: Rc<Connection>,
    /// Owned for the session's lifetime, NOT because anything here
    /// calls them again: dropping a polymorph-iroh resource handle
    /// releases it host-side, and dropping the endpoint closes every
    /// connection it carries. The previous Go client never hit this --
    /// Go's GC releases handles lazily, so its leaked endpoint stayed
    /// alive by accident. In Rust the drop is deterministic, so the
    /// ownership must be too. (Observed, not theoretical: the first
    /// integration run died with the listener logging `accept-bi:
    /// Error::Closed` the moment `connect` returned.)
    _endpoint: Endpoint,
    _endpoint_identity: Identity,
    /// Bytes the core produced, awaiting the writer task.
    outbox: VecDeque<Vec<u8>>,
    /// The reader task observed the connection end (EOF or error).
    link_down: bool,
    /// A signature relay is already in flight; without this flag two
    /// tasks noticing `signing` would both fetch `pending-signature`
    /// and the second `provide-signature` would fail.
    signing: bool,
    detached: bool,
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
}

/// Everything the spawned tasks and the exported methods share.
struct State {
    inner: RefCell<Inner>,
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
            match inner.core.status() {
                CoreStatus::Signing if !inner.signing => {
                    let blob = inner.core.pending_signature();
                    if blob.is_some() {
                        inner.signing = true;
                    }
                    blob
                }
                _ => None,
            }
        };
        state.status_signal.notify();

        let Some(blob) = pending else { return };

        // No borrow is held here -- see the module header.
        let signed = identity_store::sign(blob).await;

        {
            let mut inner = state.inner.borrow_mut();
            inner.signing = false;
            match signed {
                // The signature is relayed as the store produced it.
                // The store sits on the host side of the trust
                // boundary (it IS the keeper of the key), and the
                // server verifies the signature against the offered
                // public key anyway -- a store that signs with a
                // different key than it reports surfaces as a
                // server-side auth rejection.
                Ok(sig) => {
                    if let Err(e) = inner.core.provide_signature(&sig) {
                        inner.core.fail_signature(&format!("signature rejected: {e}"));
                    }
                }
                Err(e) => inner.core.fail_signature(&format!("identity-store sign: {e}")),
            }
        }
        // Round again: the answer above is a state-changing call.
    }
}

/// The reader task. It owns `recv` for the whole session and is NEVER
/// cancelled (module header). `read` resolving `none` is the peer's FIN
/// -- the only clean end; anything else is a transport error. Either
/// way the core is told the wire is dead so it can close legibly.
async fn reader_task(state: Rc<State>, recv: RecvStream) {
    loop {
        match recv.read(READ_CHUNK).await {
            Ok(Some(bytes)) => {
                if bytes.is_empty() {
                    // Not EOF (that is `none`); nothing to feed.
                    continue;
                }
                state.inner.borrow_mut().core.feed(&bytes);
                drive(&state).await;
            }
            end => {
                // `none` is the peer's FIN -- the only clean end; an
                // error carries its own diagnostic.
                let reason = match end {
                    Err(e) => format!("connection closed: {e:?}"),
                    _ => "connection closed".to_string(),
                };
                {
                    let mut inner = state.inner.borrow_mut();
                    inner.link_down = true;
                    inner.core.wire_broken(&reason);
                }
                drive(&state).await;
                state.status_signal.notify();
                return;
            }
        }
    }
}

/// The writer task: the sole owner of `send`. It parks on
/// `writer_signal` and drains the outbox in order.
async fn writer_task(state: Rc<State>, send: SendStream) {
    loop {
        state.writer_signal.wait().await;
        loop {
            let next = state.inner.borrow_mut().outbox.pop_front();
            let Some(bytes) = next else { break };
            if send.write(bytes).await.is_err() {
                state.inner.borrow_mut().link_down = true;
                state.status_signal.notify();
                return;
            }
        }
        if state.inner.borrow().detached {
            return;
        }
    }
}

pub struct Session {
    state: Rc<State>,
}

struct Component;

impl Guest for Component {
    type Session = Session;

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
        let line = authorized_keys_line(&raw)?;
        IDENTITY_LINE.with(|c| *c.borrow_mut() = Some(line.clone()));
        Ok(line)
    }
}

thread_local! {
    static IDENTITY_LINE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Port of client-go/export_wosh_terminal_terminal/identity.go's
/// `IdentityOpenssh`: `ssh-ed25519 <base64(wire blob)> wosh-browser`,
/// where the wire blob is the standard SSH public-key encoding --
/// the algorithm name and the raw 32-byte key, each u32-length-prefixed
/// (RFC 4253 s6.6, what `ssh.PublicKey.Marshal` produces).
fn authorized_keys_line(raw: &[u8]) -> Result<String, String> {
    const ALGO: &str = "ssh-ed25519";
    if raw.len() != 32 {
        return Err(format!(
            "ssh public key is {} bytes, expected 32",
            raw.len()
        ));
    }
    let mut blob = Vec::with_capacity(4 + ALGO.len() + 4 + raw.len());
    blob.extend_from_slice(&(ALGO.len() as u32).to_be_bytes());
    blob.extend_from_slice(ALGO.as_bytes());
    blob.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    blob.extend_from_slice(raw);

    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
    Ok(format!("{ALGO} {b64} wosh-browser"))
}

impl Session {
    /// Read the raw public half of this browser's identity, mapping
    /// store failures into the caller's `result`.
    async fn identity_public_key() -> Result<Vec<u8>, String> {
        identity_store::public_key()
            .await
            .map_err(|e| format!("obtain ssh identity: {e}"))
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
        options.add_alpn(ALPN);
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
        // The connection is authenticated against the connstring's
        // public key: a peer holding a different key never connects.
        let conn = Rc::new(
            endpoint
                .connect(addr, ALPN.to_vec())
                .await
                .map_err(err("iroh connect"))?,
        );

        let (send, recv) = conn.open_bi().await.map_err(err("iroh open-bi"))?;

        // The pairing frame: [len:u8][token], written before any ssh
        // byte and before the writer task exists, so it is trivially
        // ordered ahead of everything the core produces. An absent
        // token is a zero-length field. No ack is expected: a rejected
        // token means the listener drops the connection, which surfaces
        // as the ssh handshake seeing the stream end.
        let token = parsed.token.map(|t| t.to_vec()).unwrap_or_default();
        debug_assert!(token.len() <= u8::MAX as usize);
        let mut hello = Vec::with_capacity(1 + token.len());
        hello.push(token.len() as u8);
        hello.extend_from_slice(&token);
        send.write(hello).await.map_err(err("pairing"))?;

        // `user` is snapshotted by the core's config before the
        // handshake, but is only ever SENT inside an auth request,
        // which cannot happen before the host-key gate resolves.
        let core = CoreSession::connect(&user, cols, rows);

        let state = Rc::new(State {
            inner: RefCell::new(Inner {
                core,
                conn,
                _endpoint: endpoint,
                _endpoint_identity: identity,
                outbox: VecDeque::new(),
                link_down: false,
                signing: false,
                detached: false,
            }),
            writer_signal: Signal::default(),
            status_signal: Signal::default(),
        });

        // The core emits its client version banner during connect; the
        // server will not speak until it arrives, so queue it before
        // anything parks. (`drive` here cannot reach `signing`.)
        drive(&state).await;

        // --- reader task: never cancelled -------------------------
        wit_bindgen::spawn_local(reader_task(state.clone(), recv));
        // --- writer task: the only writer of `send` ---------------
        wit_bindgen::spawn_local(writer_task(state.clone(), send));

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
    /// signature it parks at `signing` and `drive` relays the blob to
    /// the host's store. Same latch-then-poll contract.
    async fn authenticate_publickey(&self) -> Result<(), String> {
        let public = Self::identity_public_key().await?;
        let res = self
            .state
            .inner
            .borrow()
            .core
            .authenticate_publickey(&public);
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

    /// Let the server steer method selection, stock-ssh style. The
    /// browser's key is offered when the store has one; a store that
    /// cannot produce it is reported rather than silently downgrading
    /// the offer.
    async fn authenticate_auto(&self) -> Result<(), String> {
        let public = Self::identity_public_key().await?;
        let res = self
            .state
            .inner
            .borrow()
            .core
            .authenticate_auto(Some(&public));
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

    /// Stop the session and close the iroh connection. The core is
    /// closed first (it fails any parked gate and emits its final
    /// bytes -- a disconnect message), those bytes are drained, and
    /// only then does the connection go down.
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
