//! The irsh browser SSH client glue (Rust component, wac-composed with
//! the Go `irsh:ssh-engine` component and the polymorph-iroh
//! endpoint): dials the listener over iroh using a parsed connection
//! string, bridges bytes between that connection and the Go engine's
//! sans-I/O session, and exports the stable `irsh:terminal` interface
//! the website drives via deltic.
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
//!   the ssh byte stream. Everything that produces outbound bytes
//!   pushes them onto `outbox` and notifies the writer instead.
//! * **A `RefCell` borrow is never held across an `.await`.** That
//!   hazard is real here: polymorph-iroh's own endpoint has a
//!   documented guest-side panic of exactly this shape.

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "ssh-client-world",
        generate_all,
    });
}

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::Future;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use bindings::exports::irsh::terminal::terminal::{Guest, GuestSession, Status};
use bindings::irsh::ssh_engine::ssh::{Session as EngineSession, Status as EngineStatus};
use bindings::polymorph::iroh::endpoint::{Connection, Endpoint, EndpointOptions};
use bindings::polymorph::iroh::identity_generate::generate as identity_generate;
use bindings::polymorph::iroh::types::{EndpointAddr, TransportAddr};

use irsh_connstring::ConnString;

/// v0 connection ALPN. Must match the listener's.
const ALPN: &[u8] = b"irsh/1";

fn err<E: std::fmt::Debug>(what: &str) -> impl FnOnce(E) -> String + '_ {
    move |e| format!("{what}: {e:?}")
}

/// A sticky, single-consumer wake signal. `notify()` before `wait()`
/// is captured (the flag persists), so there is no missed-wakeup race
/// between "the reader fed new bytes" and "a waiter parked".
#[derive(Default)]
struct Signal {
    dirty: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}

impl Signal {
    fn notify(&self) {
        self.dirty.set(true);
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
    engine: EngineSession,
    conn: Rc<Connection>,
    /// Bytes produced by the engine, awaiting the writer task.
    outbox: VecDeque<Vec<u8>>,
    /// The user approved the host key fingerprint.
    confirmed: bool,
    /// A password has been granted to the engine.
    credentialed: bool,
    /// `host-key-decision` has already been delivered to the engine.
    released: bool,
    /// The reader task observed the connection end.
    link_down: bool,
    detached: bool,
}

impl Inner {
    /// Drain whatever the engine has produced and queue it for the
    /// writer. Sync throughout -- no `.await`, so callers may hold the
    /// borrow.
    fn pump_engine_out(&mut self) -> bool {
        let bytes = self.engine.drain();
        if bytes.is_empty() {
            false
        } else {
            self.outbox.push_back(bytes);
            true
        }
    }

    /// Release the parked host-key gate iff the user has approved the
    /// fingerprint *and* credentials exist. The engine requires the
    /// password to be set before the gate opens (its password
    /// callback fails closed otherwise), while the natural UI order is
    /// the reverse -- so whichever arrives second triggers this.
    fn maybe_release_gate(&mut self) {
        if self.confirmed && self.credentialed && !self.released {
            self.engine.host_key_decision(true);
            self.released = true;
        }
    }
}

pub struct Session {
    inner: Rc<RefCell<Inner>>,
    /// Fires when the writer task has bytes to send.
    writer_signal: Rc<Signal>,
    /// Fires when the engine's status may have changed (the reader fed
    /// bytes, or the link went down).
    status_signal: Rc<Signal>,
}

impl Session {
    /// Queue any engine output and wake the writer.
    fn flush(&self) {
        let queued = self.inner.borrow_mut().pump_engine_out();
        if queued {
            self.writer_signal.notify();
        }
    }
}

struct Component;

impl Guest for Component {
    type Session = Session;
}

impl GuestSession for Session {
    async fn connect(
        connstring: String,
        user: String,
        cols: u16,
        rows: u16,
    ) -> Result<bindings::exports::irsh::terminal::terminal::Session, String> {
        let parsed =
            ConnString::decode(&connstring).map_err(|e| format!("connection string: {e}"))?;

        let identity = identity_generate().await.map_err(err("identity"))?;
        let options = EndpointOptions::new(&identity);
        options.add_alpn(ALPN);
        options.relay_url(&parsed.relay_url);
        // No udp-bind-addr: browsers have no direct UDP path. WebRTC
        // is the only upgrade off the relay available to us.
        options.webrtc(true);
        let endpoint = Endpoint::bind(options).await.map_err(err("bind"))?;

        let addr = EndpointAddr {
            endpoint_id: parsed.pubkey.to_vec(),
            addrs: vec![
                TransportAddr::Relay(parsed.relay_url.clone()),
                TransportAddr::Webrtc(parsed.relay_url.clone()),
            ],
        };
        let conn = Rc::new(
            endpoint
                .connect(addr, ALPN.to_vec())
                .await
                .map_err(err("connect"))?,
        );

        let (send, recv) = conn.open_bi().await.map_err(err("open-bi"))?;

        // Pairing handshake: one length-prefixed token field (empty
        // when the connstring carries none), then the rest of this
        // same stream is the raw ssh byte stream. No ack is expected:
        // a rejected token means the listener drops the connection,
        // which surfaces as the ssh handshake seeing the stream end.
        let token = parsed.token.map(|t| t.to_vec()).unwrap_or_default();
        debug_assert!(token.len() <= u8::MAX as usize);
        let mut hello = Vec::with_capacity(1 + token.len());
        hello.push(token.len() as u8);
        hello.extend_from_slice(&token);
        send.write(hello).await.map_err(err("hello"))?;

        let engine = EngineSession::connect(&user, cols, rows);

        let inner = Rc::new(RefCell::new(Inner {
            engine,
            conn,
            outbox: VecDeque::new(),
            confirmed: false,
            credentialed: false,
            released: false,
            link_down: false,
            detached: false,
        }));
        let writer_signal = Rc::new(Signal::default());
        let status_signal = Rc::new(Signal::default());

        // The engine emits its client version banner during connect;
        // ship it before anything parks.
        {
            let mut i = inner.borrow_mut();
            if i.pump_engine_out() {
                writer_signal.notify();
            }
        }

        // --- reader task: never cancelled -------------------------
        {
            let inner = inner.clone();
            let writer_signal = writer_signal.clone();
            let status_signal = status_signal.clone();
            wit_bindgen::spawn_local(async move {
                loop {
                    let chunk = recv.read(16 * 1024).await;
                    let queued = match chunk {
                        Ok(Some(bytes)) if !bytes.is_empty() => {
                            let mut i = inner.borrow_mut();
                            i.engine.feed(&bytes);
                            i.pump_engine_out()
                        }
                        Ok(Some(_)) => continue, // empty chunk, not EOF
                        Ok(None) | Err(_) => {
                            inner.borrow_mut().link_down = true;
                            status_signal.notify();
                            break;
                        }
                    };
                    if queued {
                        writer_signal.notify();
                    }
                    // Feeding bytes can move the engine between
                    // states (host-key gate reached, auth done, shell
                    // up, connection closed) and can produce pty
                    // output; wake anyone waiting on either.
                    status_signal.notify();
                }
            });
        }

        // --- writer task: the only writer of `send` ---------------
        {
            let inner = inner.clone();
            let writer_signal = writer_signal.clone();
            wit_bindgen::spawn_local(async move {
                loop {
                    writer_signal.wait().await;
                    loop {
                        let next = inner.borrow_mut().outbox.pop_front();
                        let Some(bytes) = next else { break };
                        if send.write(bytes).await.is_err() {
                            inner.borrow_mut().link_down = true;
                            return;
                        }
                    }
                    if inner.borrow().detached {
                        break;
                    }
                }
            });
        }

        Ok(bindings::exports::irsh::terminal::terminal::Session::new(
            Session {
                inner,
                writer_signal,
                status_signal,
            },
        ))
    }

    fn status(&self) -> Status {
        let inner = self.inner.borrow();
        match inner.engine.status() {
            EngineStatus::HostKeyCheck => Status::HostKeyCheck,
            EngineStatus::Ready => Status::Ready,
            EngineStatus::Closed(reason) => Status::Closed(reason),
            EngineStatus::Connecting if inner.released => Status::Authenticating,
            EngineStatus::Connecting => Status::Connecting,
        }
    }

    fn host_key_fingerprint(&self) -> Option<String> {
        self.inner.borrow().engine.host_key_sha256()
    }

    /// Record the user's verdict on the fingerprint. Accepting does
    /// NOT by itself resume the handshake: the engine needs
    /// credentials in hand before the gate opens, so the release
    /// happens in whichever of {this, `authenticate`} runs second.
    /// Rejecting tears down immediately, with no credentials ever
    /// granted and nothing sent to the server.
    fn confirm_host_key(&self, accept: bool) {
        {
            let mut inner = self.inner.borrow_mut();
            if !accept {
                if !inner.released {
                    inner.engine.host_key_decision(false);
                    inner.released = true;
                }
            } else {
                inner.confirmed = true;
                inner.maybe_release_gate();
            }
        }
        self.flush();
    }

    async fn authenticate(&self, password: String) -> Result<(), String> {
        {
            let mut inner = self.inner.borrow_mut();
            if !inner.confirmed {
                return Err(
                    "the host key fingerprint has not been confirmed yet (call confirm-host-key \
                     first -- the password is never sent to an unapproved server)"
                        .into(),
                );
            }
            inner.engine.authenticate(&password);
            inner.credentialed = true;
            inner.maybe_release_gate();
        }
        self.flush();

        // Park until the engine reaches a terminal state. The reader
        // task notifies `status_signal` on every fed chunk and on link
        // death, so this never spins.
        loop {
            {
                let inner = self.inner.borrow();
                match inner.engine.status() {
                    EngineStatus::Ready => return Ok(()),
                    EngineStatus::Closed(reason) => return Err(reason),
                    _ if inner.link_down => {
                        return Err("connection closed during authentication".into())
                    }
                    _ => {}
                }
            }
            self.status_signal.wait().await;
        }
    }

    fn write_input(&self, data: Vec<u8>) {
        self.inner.borrow_mut().engine.write_input(&data);
        self.flush();
    }

    fn resize(&self, cols: u16, rows: u16) {
        self.inner.borrow_mut().engine.resize(cols, rows);
        self.flush();
    }

    async fn drain_output(&self) -> Vec<u8> {
        self.inner.borrow().engine.drain_output()
    }

    fn exited(&self) -> bool {
        let inner = self.inner.borrow();
        inner.engine.exited() || inner.link_down
    }

    async fn detach(&self) {
        // Cheap Rc clone (a refcount bump, not a resource op) so the
        // close + wait-closed `.await`s happen with no borrow held.
        let conn = {
            let mut inner = self.inner.borrow_mut();
            inner.detached = true;
            inner.conn.clone()
        };
        self.writer_signal.notify(); // let the writer observe `detached` and retire
        conn.close(0, "detached");
        // Close-then-await: a bare `close` races the CONNECTION_CLOSE
        // frame reaching the wire; awaiting keeps the connection alive
        // until it really went out.
        let _ = conn.wait_closed().await;
    }
}

bindings::export!(Component with_types_in bindings);
