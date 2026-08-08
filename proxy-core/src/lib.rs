//! experiment-mosh proxy-core (M4, workstream C).
//!
//! The proxy's brain as a component: accepts iroh connections through
//! the polymorph-iroh endpoint (fused in by wac), authorizes peers via
//! the host (TOFU policy and prompts stay native), speaks the control
//! channel (proto, shared with the client-core glue), and pumps
//! datagrams between each connection and its session's mosh-server
//! over `wasi:sockets` UDP — sub-framing oversized server datagrams
//! (finding 9). The native shell (proxy/) provides exactly four
//! things: authorize, new-session, end-session, log.

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

use bindings::experiment::mosh_proxy::host;
use bindings::exports::experiment::mosh_proxy::proxy::{Guest, Started};
use bindings::polymorph::iroh::endpoint::{Connection, Endpoint, EndpointOptions};
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

/// One connection: control handshake, session spawn via the host,
/// datagram pumps until either side ends.
async fn serve_connection(conn: &Connection, id: u64, peer_hex: &str) -> Result<String, String> {
    // The client opens the control stream.
    let (ctl_send, ctl_recv) = conn.accept_bi().await.map_err(err("accept-bi"))?;

    let mut buf: Vec<u8> = Vec::new();
    let mut next = async || -> Result<proto::Client, String> {
        loop {
            if let Some(msg) = proto::decode::<proto::Client>(&mut buf)? {
                return Ok(msg);
            }
            match ctl_recv.read(4096).await.map_err(err("control read"))? {
                Some(bytes) => buf.extend_from_slice(&bytes),
                None => return Err("control stream closed".into()),
            }
        }
    };

    // Hello: version + pairing token; host owns the TOFU decision.
    match next().await? {
        proto::Client::Hello {
            version,
            pairing_token,
        } => {
            if version != proto::CONTROL_VERSION {
                let msg = proto::encode(&proto::Proxy::Error {
                    message: format!("control v{version} unsupported"),
                });
                let _ = ctl_send.write(msg).await;
                return Err(format!("client speaks control v{version}"));
            }
            if !host::authorize(peer_hex.to_string(), pairing_token).await {
                // Refused: close without ceremony (prompt-fatigue defense).
                return Err("peer refused".into());
            }
        }
        other => return Err(format!("expected Hello, got {other:?}")),
    }
    ctl_send
        .write(proto::encode(&proto::Proxy::HelloAck {
            version: proto::CONTROL_VERSION,
        }))
        .await
        .map_err(err("hello-ack write"))?;

    // NewSession → host spawns mosh-server; deliver the key.
    match next().await? {
        proto::Client::NewSession { .. } => {}
        other => return Err(format!("expected NewSession, got {other:?}")),
    }
    let session = match host::new_session().await {
        Ok(s) => s,
        Err(e) => {
            let msg = proto::encode(&proto::Proxy::Error { message: e.clone() });
            let _ = ctl_send.write(msg).await;
            return Err(format!("new-session: {e}"));
        }
    };
    ctl_send
        .write(proto::encode(&proto::Proxy::SessionReady {
            session_id: id,
            key: session.key.clone(),
        }))
        .await
        .map_err(err("session-ready write"))?;
    host::log(&format!(
        "[conn {id}] {peer_hex}: session on udp:{}",
        session.udp_port
    ));

    // Datagram pumps with tunnel framing.
    let sock = Rc::new(udp::UdpWire::bind("127.0.0.1:0")?);
    let mosh_addr = std::net::SocketAddr::from(([127, 0, 0, 1], session.udp_port));
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

    futures::join(inbound, outbound).await;
    host::end_session(session.udp_port);
    Ok(format!(
        "session closed (fragmented={} oversized server datagrams)",
        fragmented.get()
    ))
}

/// Minimal join for two unit futures (avoids pulling the futures
/// crate into the guest).
mod futures {
    use std::future::Future;
    use std::pin::pin;
    use std::task::Poll;

    pub async fn join(a: impl Future<Output = ()>, b: impl Future<Output = ()>) {
        let mut a = pin!(a);
        let mut b = pin!(b);
        let mut a_done = false;
        let mut b_done = false;
        std::future::poll_fn(|cx| {
            if !a_done {
                a_done = a.as_mut().poll(cx).is_ready();
            }
            if !b_done {
                b_done = b.as_mut().poll(cx).is_ready();
            }
            if a_done && b_done {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

bindings::export!(Component with_types_in bindings);
