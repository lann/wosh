//! wosh proxy-core (M4/M6, workstream C).
//!
//! The proxy's brain as a component: accepts iroh connections through
//! the polymorph-iroh endpoint (fused in by wac), authorizes peers via
//! the host (TOFU policy and prompts stay native), speaks the control
//! channel (proto, shared with the client-core glue), and pumps
//! datagrams between each connection and its session's mosh-server
//! over `wasi:sockets` UDP — sub-framing oversized server datagrams
//! (finding 9). M6 adds passkey ceremonies (relayed to the host's
//! webauthn-rs RP as opaque blobs) and assertion-gated reattach to
//! persistent sessions. M7 adds the inner-ssh posture: SSH_FORWARD
//! streams are forwarded to sshd on the proxy host's loopback
//! (tcp.rs), `ForwardDatagrams` routes the tunnel to a client-managed
//! mosh-server, and proxy-spawned sessions (`NewSession`) are refused
//! unless the shell opts in to personal mode. The native shell
//! (proxy/) provides process spawning, TOFU, the RP, the escrow
//! store, and logging (D9).

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "proxy-world",
        generate_all,
    });
}

mod tcp;
mod udp;

use std::cell::Cell;
use std::future::Future as _;
use std::rc::Rc;

use wosh_proto as proto;

use bindings::experiment::mosh_proxy::host::{self, CeremonyKind};
use bindings::exports::experiment::mosh_proxy::proxy::{Guest, Started};
use bindings::polymorph::iroh::endpoint::{
    Connection, Endpoint, EndpointOptions, RecvStream, SendStream,
};
use bindings::polymorph::iroh::identity_generate::generate;

/// v0 connection ALPN, shared with the client-core glue.
const ALPN: &[u8] = b"wosh/0";

fn err<E: std::fmt::Debug>(what: &str) -> impl FnOnce(E) -> String + '_ {
    move |e| format!("{what}: {e:?}")
}

struct Component;

impl Guest for Component {
    async fn start(relay_url: String, ssh_target: String, personal: bool) -> Result<Started, String> {
        // Fail fast on a bad target; the shell already enforces the
        // loopback-host policy at arg-parse.
        let ssh_target: std::net::SocketAddr = ssh_target
            .parse()
            .map_err(|e| format!("ssh-target {ssh_target:?}: {e}"))?;

        let identity = generate().await.map_err(err("identity"))?;
        let options = EndpointOptions::new(&identity);
        options.add_alpn(ALPN);
        options.relay_url(&relay_url);
        options.udp_bind_addr("0.0.0.0:0");
        // Answer WebRTC signaling from browser clients (their only
        // off-relay path). Acceptor side: no addr hints to offer —
        // clients relay-dial and carry the upgrade hint.
        options.webrtc(true);

        let endpoint = Endpoint::bind(options).await.map_err(err("bind"))?;
        let endpoint = Rc::new(endpoint);
        let started = Started {
            endpoint_id_hex: hex::encode(endpoint.id()),
            direct_addr: endpoint.direct_addr(),
        };

        let acceptor = endpoint.clone();
        wit_bindgen::spawn_local(async move {
            let mut next_conn = 0u64;
            loop {
                match acceptor.accept().await {
                    Ok(conn) => {
                        next_conn += 1;
                        let id = next_conn;
                        wit_bindgen::spawn_local(async move {
                            let peer = hex::encode(conn.peer());
                            match serve_connection(&conn, id, &peer, ssh_target, personal).await {
                                Ok(summary) => host::log(&format!("[conn {id}] {peer}: {summary}")),
                                Err(e) => host::log(&format!("[conn {id}] {peer}: {e}")),
                            }
                            conn.close(0, "done");
                        });
                    }
                    Err(e) => {
                        host::log(&format!("accept: {e:?}"));
                        break;
                    }
                }
            }
        });

        // The acceptor task holds one Rc; keep another alive forever so
        // the endpoint outlives this call regardless.
        std::mem::forget(endpoint);
        Ok(started)
    }
}

/// The proxy side of the control channel.
struct Control {
    send: SendStream,
    recv: RecvStream,
    buf: Vec<u8>,
}

impl Control {
    async fn next(&mut self) -> Result<proto::Client, String> {
        loop {
            if let Some(msg) = proto::decode::<proto::Client>(&mut self.buf)? {
                return Ok(msg);
            }
            match self.recv.read(4096).await.map_err(err("control read"))? {
                Some(bytes) => self.buf.extend_from_slice(&bytes),
                None => return Err("control stream closed".into()),
            }
        }
    }

    async fn send(&self, msg: &proto::Proxy) -> Result<(), String> {
        self.send
            .write(proto::encode(msg))
            .await
            .map_err(err("control write"))
    }

    /// Send a terminal `Error` and wait for the peer to close its
    /// side before the caller tears the connection down: closing
    /// races in-flight stream data, and a refusal the client never
    /// sees is indistinguishable from a crash. A well-behaved client
    /// closes promptly on `Error`; a peer that instead keeps talking
    /// only pins its own doomed connection (bounded by its lifetime).
    /// Returns the message for the connection log.
    async fn fail(&mut self, message: String) -> String {
        let _ = self
            .send(&proto::Proxy::Error {
                message: message.clone(),
            })
            .await;
        while self.next().await.is_ok() {}
        message
    }
}

/// One connection: control handshake (hello/TOFU), then two
/// concurrent phases until the session ends — the session phase
/// (establishment, datagram pumps, ceremony loop; `run_session`) and
/// a stream-accept daemon serving SSH_FORWARD streams. The daemon
/// must already be listening during the control wait: the client's
/// ssh leg runs BEFORE its session-establishing control message
/// (`ForwardDatagrams` names a port that only exists once mosh-server
/// was started through ssh).
async fn serve_connection(
    conn: &Connection,
    id: u64,
    peer_hex: &str,
    ssh_target: std::net::SocketAddr,
    personal: bool,
) -> Result<String, String> {
    // The client opens the control stream.
    let (ctl_send, ctl_recv) = conn.accept_bi().await.map_err(err("accept-bi"))?;
    let mut control = Control {
        send: ctl_send,
        recv: ctl_recv,
        buf: Vec::new(),
    };

    // Hello: version + pairing token; host owns the TOFU decision.
    match control.next().await? {
        proto::Client::Hello {
            version,
            pairing_token,
        } => {
            if version != proto::CONTROL_VERSION {
                return Err(control
                    .fail(format!("control v{version} unsupported"))
                    .await);
            }
            if !host::authorize(peer_hex.to_string(), pairing_token).await {
                // Refused: close without ceremony (prompt-fatigue defense).
                return Err("peer refused".into());
            }
        }
        other => return Err(format!("expected Hello, got {other:?}")),
    }
    control
        .send(&proto::Proxy::HelloAck {
            version: proto::CONTROL_VERSION,
        })
        .await?;

    // Stream-accept daemon: the first byte of every client-opened bi
    // stream after the control stream names its purpose (proto
    // stream_tag). Forwards are served sequentially per connection by
    // design (v0: one ssh leg per connection); unknown tags are
    // logged and dropped.
    let stream_loop = async {
        loop {
            let (send, recv) = match conn.accept_bi().await {
                Ok(pair) => pair,
                Err(_) => break, // connection closed
            };
            match read_tag(&recv).await {
                Some(proto::stream_tag::SSH_FORWARD) => {
                    match tcp::forward(send, recv, ssh_target).await {
                        Ok(summary) => host::log(&format!("[conn {id}] ssh forward: {summary}")),
                        Err(e) => host::log(&format!("[conn {id}] ssh forward: {e}")),
                    }
                }
                Some(tag) => {
                    host::log(&format!("[conn {id}] unknown stream tag {tag:#04x}; dropped"))
                }
                None => {} // stream ended before a tag arrived
            }
        }
    };

    // Drive both phases; the session phase decides completion.
    // No-cancel discipline: a parked accept-bi is never dropped
    // mid-flight — the connection close below resolves it and the
    // daemon runs to its natural end.
    let mut stream_loop = std::pin::pin!(stream_loop);
    let mut session = std::pin::pin!(run_session(conn, control, id, peer_hex, personal));
    let mut loop_done = false;
    let result = std::future::poll_fn(|cx| {
        if !loop_done {
            loop_done = stream_loop.as_mut().poll(cx).is_ready();
        }
        session.as_mut().poll(cx)
    })
    .await;

    // On establishment errors this close is the active teardown (and
    // resolves the parked accept-bi); on the happy path the
    // connection is already dead and it is a no-op.
    conn.close(0, "session over");
    if !loop_done {
        stream_loop.await;
    }

    let (session_id, udp_port, fragmented) = result?;
    host::end_session(udp_port);
    Ok(format!(
        "session {session_id} closed (fragmented={fragmented} oversized server datagrams)"
    ))
}

/// The route byte of a client-opened stream (written by the client
/// immediately after open; the QUIC stream exists network-side only
/// once bytes flow).
async fn read_tag(recv: &RecvStream) -> Option<u8> {
    loop {
        match recv.read(1).await {
            Ok(Some(bytes)) => {
                if let Some(&tag) = bytes.first() {
                    return Some(tag);
                }
                // Empty chunk: keep waiting for the byte.
            }
            Ok(None) | Err(_) => return None,
        }
    }
}

/// The session phase of one connection: establishment (NewSession /
/// Reattach / ForwardDatagrams), then datagram pumps + the ceremony
/// loop until either side ends. Returns `(session-id, udp-port,
/// fragmented-count)` for serve_connection's teardown and summary.
async fn run_session(
    conn: &Connection,
    mut control: Control,
    id: u64,
    peer_hex: &str,
    personal: bool,
) -> Result<(u64, u16, u64), String> {
    // Session establishment: fresh (NewSession), persistent
    // (Reattach, gated on a verified assertion), or client-managed
    // (ForwardDatagrams, M7).
    let (session_id, udp_port) = match control.next().await? {
        proto::Client::NewSession { .. } => {
            if !personal {
                // M7 posture: no proxy-spawned sessions, no key
                // custody — the host is not even asked (its own
                // refusal is defense in depth behind this one).
                return Err(control
                    .fail(
                        "personal mode disabled: bring your own mosh-server over ssh \
                         (connect-ssh)"
                            .into(),
                    )
                    .await);
            }
            let session = match host::new_session().await {
                Ok(s) => s,
                Err(e) => return Err(control.fail(format!("new-session: {e}")).await),
            };
            control
                .send(&proto::Proxy::SessionReady {
                    session_id: session.session_id,
                    key: session.key.clone(),
                })
                .await?;
            host::log(&format!(
                "[conn {id}] {peer_hex}: session {} on udp:{}",
                session.session_id, session.udp_port
            ));
            (session.session_id, session.udp_port)
        }
        proto::Client::Reattach { session_id } => {
            let challenge = match host::webauthn_step(
                CeremonyKind::AuthStart,
                session_id,
                Vec::new(),
            )
            .await
            {
                Ok(c) => c,
                Err(e) => return Err(control.fail(format!("auth-start: {e}")).await),
            };
            control
                .send(&proto::Proxy::AuthChallenge { challenge })
                .await?;
            let assertion = match control.next().await? {
                proto::Client::AuthFinish { assertion } => assertion,
                other => return Err(format!("expected AuthFinish, got {other:?}")),
            };
            if let Err(e) =
                host::webauthn_step(CeremonyKind::AuthFinish, session_id, assertion).await
            {
                return Err(control.fail(format!("assertion refused: {e}")).await);
            }
            let info = match host::reattach(session_id).await {
                Ok(i) => i,
                Err(e) => return Err(control.fail(format!("reattach: {e}")).await),
            };
            control
                .send(&proto::Proxy::ReattachReady {
                    session_id,
                    escrow: info.escrow,
                })
                .await?;
            host::log(&format!(
                "[conn {id}] {peer_hex}: REATTACHED session {session_id} on udp:{}",
                info.udp_port
            ));
            (session_id, info.udp_port)
        }
        proto::Client::ForwardDatagrams { port } => {
            // Client-managed session (M7): the client booted its own
            // mosh-server on the proxy host's loopback through the
            // forwarded ssh stream and owns the key. The host only
            // assigns a session id and records the port, so passkey
            // binding works unchanged for forwarded sessions.
            match host::register_forward(port).await {
                Ok(session_id) => {
                    control
                        .send(&proto::Proxy::ForwardOk { session_id })
                        .await?;
                    host::log(&format!(
                        "[conn {id}] {peer_hex}: FORWARD session {session_id} to udp:{port} \
                         (client-managed mosh-server)"
                    ));
                    (session_id, port)
                }
                Err(e) => return Err(control.fail(format!("register-forward: {e}")).await),
            }
        }
        other => {
            return Err(format!(
                "expected NewSession, Reattach, or ForwardDatagrams, got {other:?}"
            ))
        }
    };

    // Datagram pumps with tunnel framing.
    let sock = Rc::new(udp::UdpWire::bind("127.0.0.1:0")?);
    let mosh_addr = std::net::SocketAddr::from(([127, 0, 0, 1], udp_port));
    let max_size = conn
        .max_datagram_size()
        .ok_or("peer accepts no datagrams")? as usize;
    // Test-isolation knob (m4 sub-framing): polymorph-iroh#52's per-path MTU
    // discovery lifts the loopback ceiling above mosh's largest datagrams
    // (~1252 B), so on localhost nothing fragments and the sub-framing
    // machinery would go unexercised. The cap only ever LOWERS the
    // negotiated ceiling (production paths are unaffected: the variable is
    // unset there).
    let max_size = std::env::var("WOSH_DATAGRAM_CEILING")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n >= 64)
        .map_or(max_size, |cap| cap.min(max_size));

    let alive = Rc::new(Cell::new(true));
    let fragmented = Rc::new(Cell::new(0u64));

    // conn → UDP (defragment). Owns liveness: when the connection
    // dies, wake the UDP receive so the other pump can exit too.
    let inbound = {
        let sock = sock.clone();
        let alive = alive.clone();
        async move {
            let mut defrag = proto::Defragmenter::default();
            loop {
                match conn.recv_datagram().await {
                    Ok(datagram) => {
                        if let Some(payload) = defrag.push(&datagram) {
                            let _ = sock.send(mosh_addr, &payload).await;
                        }
                    }
                    Err(_) => break,
                }
            }
            alive.set(false);
            sock.wake_receiver().await;
        }
    };

    // UDP → conn (fragment as needed).
    let outbound = {
        let sock = sock.clone();
        let alive = alive.clone();
        let fragmented = fragmented.clone();
        async move {
            let mut next_id = 0u8;
            while alive.get() {
                let Ok((payload, _from)) = sock.receive().await else {
                    break;
                };
                if payload.is_empty() {
                    continue; // wake datagram
                }
                match proto::frame(&payload, max_size, &mut next_id) {
                    Ok(frames) => {
                        if frames.len() > 1 {
                            fragmented.set(fragmented.get() + 1);
                        }
                        for frame in frames {
                            let _ = conn.send_datagram(&frame);
                        }
                    }
                    Err(e) => host::log(&format!("[conn {id}] frame: {e}")),
                }
            }
        }
    };

    // Ceremony loop: registration and persistence requests arrive on
    // the live control channel (M6). Ends when the stream does.
    let ceremonies = async move {
        loop {
            let msg = match control.next().await {
                Ok(m) => m,
                Err(_) => break, // stream closed with the connection
            };
            let reply = match msg {
                proto::Client::RegisterStart => {
                    match host::webauthn_step(CeremonyKind::RegisterStart, session_id, Vec::new())
                        .await
                    {
                        Ok(challenge) => proto::Proxy::RegisterChallenge { challenge },
                        Err(e) => proto::Proxy::Error {
                            message: format!("register-start: {e}"),
                        },
                    }
                }
                proto::Client::RegisterFinish { response } => {
                    match host::webauthn_step(CeremonyKind::RegisterFinish, session_id, response)
                        .await
                    {
                        Ok(_) => proto::Proxy::RegisterOk,
                        Err(e) => proto::Proxy::Error {
                            message: format!("register-finish: {e}"),
                        },
                    }
                }
                proto::Client::MakePersistent { escrow } => {
                    match host::make_persistent(session_id, escrow).await {
                        Ok(()) => proto::Proxy::PersistOk,
                        Err(e) => proto::Proxy::Error {
                            message: format!("make-persistent: {e}"),
                        },
                    }
                }
                other => proto::Proxy::Error {
                    message: format!("unexpected control message: {other:?}"),
                },
            };
            if control.send(&reply).await.is_err() {
                break;
            }
        }
    };

    futures::join3(inbound, outbound, ceremonies).await;
    Ok((session_id, udp_port, fragmented.get()))
}

/// Minimal join for unit futures (avoids pulling the futures crate
/// into the guest).
mod futures {
    use std::future::Future;
    use std::pin::pin;
    use std::task::Poll;

    pub async fn join3(
        a: impl Future<Output = ()>,
        b: impl Future<Output = ()>,
        c: impl Future<Output = ()>,
    ) {
        let mut a = pin!(a);
        let mut b = pin!(b);
        let mut c = pin!(c);
        let mut a_done = false;
        let mut b_done = false;
        let mut c_done = false;
        std::future::poll_fn(|cx| {
            if !a_done {
                a_done = a.as_mut().poll(cx).is_ready();
            }
            if !b_done {
                b_done = b.as_mut().poll(cx).is_ready();
            }
            if !c_done {
                c_done = c.as_mut().poll(cx).is_ready();
            }
            if a_done && b_done && c_done {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

bindings::export!(Component with_types_in bindings);
