//! experiment-mosh proxy-core (M4/M6, workstream C).
//!
//! The proxy's brain as a component: accepts iroh connections through
//! the polymorph-iroh endpoint (fused in by wac), authorizes peers via
//! the host (TOFU policy and prompts stay native), speaks the control
//! channel (proto, shared with the client-core glue), and pumps
//! datagrams between each connection and its session's mosh-server
//! over `wasi:sockets` UDP — sub-framing oversized server datagrams
//! (finding 9). M6 adds passkey ceremonies (relayed to the host's
//! webauthn-rs RP as opaque blobs) and assertion-gated reattach to
//! persistent sessions. The native shell (proxy/) provides process
//! spawning, TOFU, the RP, the escrow store, and logging (D9).

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "proxy-world",
        generate_all,
    });
}

mod udp;

use std::cell::Cell;
use std::rc::Rc;

use experiment_mosh_proto as proto;

use bindings::experiment::mosh_proxy::host::{self, CeremonyKind};
use bindings::exports::experiment::mosh_proxy::proxy::{Guest, Started};
use bindings::polymorph::iroh::endpoint::{
    Connection, Endpoint, EndpointOptions, RecvStream, SendStream,
};
use bindings::polymorph::iroh::identity_generate::generate;

/// v0 connection ALPN, shared with the client-core glue.
const ALPN: &[u8] = b"experiment-mosh/0";

fn err<E: std::fmt::Debug>(what: &str) -> impl FnOnce(E) -> String + '_ {
    move |e| format!("{what}: {e:?}")
}

struct Component;

impl Guest for Component {
    async fn start(relay_url: String) -> Result<Started, String> {
        let identity = generate().await.map_err(err("identity"))?;
        let options = EndpointOptions::new(&identity);
        options.add_alpn(ALPN);
        options.relay_url(&relay_url);
        options.udp_bind_addr("0.0.0.0:0");

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
                            match serve_connection(&conn, id, &peer).await {
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
}

/// One connection: control handshake (new session or assertion-gated
/// reattach), datagram pumps + the ceremony loop until either side
/// ends.
async fn serve_connection(conn: &Connection, id: u64, peer_hex: &str) -> Result<String, String> {
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
                let _ = control
                    .send(&proto::Proxy::Error {
                        message: format!("control v{version} unsupported"),
                    })
                    .await;
                return Err(format!("client speaks control v{version}"));
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

    // Session establishment: fresh (NewSession) or persistent
    // (Reattach, gated on a verified assertion).
    let (session_id, udp_port) = match control.next().await? {
        proto::Client::NewSession { .. } => {
            let session = match host::new_session().await {
                Ok(s) => s,
                Err(e) => {
                    let _ = control
                        .send(&proto::Proxy::Error { message: e.clone() })
                        .await;
                    return Err(format!("new-session: {e}"));
                }
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
            let fail = async |control: &Control, e: String| -> String {
                let _ = control
                    .send(&proto::Proxy::Error { message: e.clone() })
                    .await;
                e
            };
            let challenge = match host::webauthn_step(
                CeremonyKind::AuthStart,
                session_id,
                Vec::new(),
            )
            .await
            {
                Ok(c) => c,
                Err(e) => return Err(fail(&control, format!("auth-start: {e}")).await),
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
                return Err(fail(&control, format!("assertion refused: {e}")).await);
            }
            let info = match host::reattach(session_id).await {
                Ok(i) => i,
                Err(e) => return Err(fail(&control, format!("reattach: {e}")).await),
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
        other => return Err(format!("expected NewSession or Reattach, got {other:?}")),
    };

    // Datagram pumps with tunnel framing.
    let sock = Rc::new(udp::UdpWire::bind("127.0.0.1:0")?);
    let mosh_addr = std::net::SocketAddr::from(([127, 0, 0, 1], udp_port));
    let max_size = conn
        .max_datagram_size()
        .ok_or("peer accepts no datagrams")? as usize;

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
    host::end_session(udp_port);
    Ok(format!(
        "session {session_id} closed (fragmented={} oversized server datagrams)",
        fragmented.get()
    ))
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
