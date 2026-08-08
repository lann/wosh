//! experiment-mosh client-core glue (D7/B2).
//!
//! The composition seam: imports the pure-sync mosh engine and the
//! async polymorph-iroh endpoint, owns the two pumps (recv-datagram
//! loop, ~8 ms tick), speaks the proxy control channel (D8: control
//! lives here, not in the embedder — ciborium shapes shared with the
//! proxy via the proto crate), and exports the `client` driver
//! interface. The engine stays sans-I/O (finding 5); everything here
//! runs on `wit_bindgen::spawn_local` tasks.
//!
//! Datagram paths: `connect-proxy` / `attach-proxy` apply the tunnel
//! framing (proto: 1-byte header, 2-fragment split — finding 9);
//! `dial` pumps raw mosh datagrams for harnesses and interop peers.

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "client-world",
        generate_all,
    });
}

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use experiment_mosh_proto as proto;

use bindings::experiment::mosh::engine::Session as EngineSession;
use bindings::exports::experiment::mosh_client::client::{
    ClientSession, Guest, GuestClientSession, SessionStats,
};
use bindings::exports::experiment::mosh_client::embed::Guest as EmbedGuest;
use bindings::polymorph::iroh::endpoint::{
    Connection, Endpoint, EndpointOptions, RecvStream, SendStream,
};
use bindings::polymorph::iroh::identity_generate::generate;
use bindings::polymorph::iroh::types::{EndpointAddr, TransportAddr};
use bindings::wasi::clocks::monotonic_clock::wait_for;

/// v0 connection ALPN: control stream + datagram tunnel share it.
const ALPN: &[u8] = b"experiment-mosh/0";

/// Engine tick cadence — mosh's SEND_MINDELAY keystroke batching.
const TICK_NS: u64 = 8_000_000;

struct Inner {
    session: EngineSession,
    conn: Connection,
    /// Keeps a self-bound endpoint alive for the session's lifetime
    /// (dropping it would close the connection under it).
    _endpoint: Option<Endpoint>,
    /// Control stream halves, held open for the session's lifetime
    /// (dropping them reads as detach to the proxy). M6 ceremonies
    /// ride these.
    _control: Option<(SendStream, RecvStream)>,
    /// Tunnel framing on the datagram path (proxy flows) or raw
    /// (dial). None ⇒ raw.
    framing: Option<RefCell<(u8, proto::Defragmenter)>>,
    alive: Cell<bool>,
}

struct ClientSessionRes {
    inner: Rc<Inner>,
}

fn err<E: std::fmt::Debug>(what: &str) -> impl FnOnce(E) -> String + '_ {
    move |e| format!("{what}: {e:?}")
}

/// Bind a throwaway-identity endpoint and connect to the peer.
async fn dial_connection(
    relay_url: &str,
    peer_id_hex: &str,
    direct: Option<String>,
) -> Result<(Endpoint, Connection), String> {
    let peer: Vec<u8> = hex::decode(peer_id_hex).map_err(err("peer id"))?;
    if peer.len() != 32 {
        return Err("peer id is not 32 bytes".into());
    }

    let identity = generate().await.map_err(err("identity"))?;
    let options = EndpointOptions::new(&identity);
    options.add_alpn(ALPN);
    options.relay_url(relay_url);
    options.udp_bind_addr("0.0.0.0:0");

    let endpoint = Endpoint::bind(options).await.map_err(err("bind"))?;

    let mut addrs = Vec::new();
    if let Some(hint) = direct {
        addrs.push(TransportAddr::Ip(hint));
    }
    addrs.push(TransportAddr::Relay(relay_url.to_string()));

    let conn = endpoint
        .connect(
            EndpointAddr {
                endpoint_id: peer,
                addrs,
            },
            ALPN.to_vec(),
        )
        .await
        .map_err(err("connect"))?;
    Ok((endpoint, conn))
}

/// Run the client half of the control channel: hello (pairing token),
/// new-session, key delivery. Returns the mosh key and the held-open
/// stream halves.
async fn control_handshake(
    conn: &Connection,
    pairing_token: &str,
    cols: u16,
    rows: u16,
) -> Result<(String, SendStream, RecvStream), String> {
    let (send, recv) = conn.open_bi().await.map_err(err("open-bi"))?;

    let hello = proto::encode(&proto::Client::Hello {
        version: proto::CONTROL_VERSION,
        pairing_token: pairing_token.to_string(),
    });
    send.write(hello).await.map_err(err("hello write"))?;

    let mut buf: Vec<u8> = Vec::new();
    let mut next = async || -> Result<proto::Proxy, String> {
        loop {
            if let Some(msg) = proto::decode::<proto::Proxy>(&mut buf)? {
                return Ok(msg);
            }
            match recv.read(4096).await.map_err(err("control read"))? {
                Some(bytes) => buf.extend_from_slice(&bytes),
                None => return Err("control stream closed by proxy".into()),
            }
        }
    };

    match next().await? {
        proto::Proxy::HelloAck { version } if version == proto::CONTROL_VERSION => {}
        proto::Proxy::HelloAck { version } => {
            return Err(format!("proxy speaks control v{version}, we speak v0"));
        }
        proto::Proxy::Error { message } => return Err(format!("proxy: {message}")),
        other => return Err(format!("unexpected control message: {other:?}")),
    }

    let new_session = proto::encode(&proto::Client::NewSession { cols, rows });
    send.write(new_session).await.map_err(err("new-session write"))?;

    match next().await? {
        proto::Proxy::SessionReady { key, .. } => Ok((key, send, recv)),
        proto::Proxy::Error { message } => Err(format!("proxy: {message}")),
        other => Err(format!("unexpected control message: {other:?}")),
    }
}

impl ClientSessionRes {
    fn start(
        endpoint: Option<Endpoint>,
        conn: Connection,
        control: Option<(SendStream, RecvStream)>,
        framed: bool,
        key: String,
        cols: u16,
        rows: u16,
    ) -> Result<ClientSession, String> {
        let session = EngineSession::connect(&key, cols, rows)?;
        let inner = Rc::new(Inner {
            session,
            conn,
            _endpoint: endpoint,
            _control: control,
            framing: framed.then(|| RefCell::new((0u8, proto::Defragmenter::default()))),
            alive: Cell::new(true),
        });

        // The tick pump: flush pending actions/acks/retransmits and
        // push the produced datagrams to the wire. send-datagram is
        // sync and lossy by contract — errors are wire-loss, not ours.
        let tick = inner.clone();
        wit_bindgen::spawn_local(async move {
            while tick.alive.get() {
                wait_for(TICK_NS).await;
                let max = tick.conn.max_datagram_size().unwrap_or(0) as usize;
                for datagram in tick.session.tick() {
                    match &tick.framing {
                        Some(framing) => {
                            let mut f = framing.borrow_mut();
                            if let Ok(frames) = proto::frame(&datagram, max, &mut f.0) {
                                for frame in frames {
                                    let _ = tick.conn.send_datagram(&frame);
                                }
                            }
                        }
                        None => {
                            let _ = tick.conn.send_datagram(&datagram);
                        }
                    }
                }
            }
        });

        // The recv pump: every inbound datagram goes to the engine,
        // through the defragmenter on framed paths. Errors mean the
        // connection is gone — stop.
        let recv = inner.clone();
        wit_bindgen::spawn_local(async move {
            loop {
                match recv.conn.recv_datagram().await {
                    Ok(datagram) => {
                        if !recv.alive.get() {
                            break;
                        }
                        match &recv.framing {
                            Some(framing) => {
                                let payload = framing.borrow_mut().1.push(&datagram);
                                if let Some(payload) = payload {
                                    recv.session.handle_datagram(&payload);
                                }
                            }
                            None => recv.session.handle_datagram(&datagram),
                        }
                    }
                    Err(_) => break,
                }
            }
            recv.alive.set(false);
        });

        Ok(ClientSession::new(ClientSessionRes { inner }))
    }

    async fn attach_framed(
        endpoint: Option<Endpoint>,
        conn: Connection,
        pairing_token: &str,
        cols: u16,
        rows: u16,
    ) -> Result<ClientSession, String> {
        let (key, send, recv) = control_handshake(&conn, pairing_token, cols, rows).await?;
        Self::start(endpoint, conn, Some((send, recv)), true, key, cols, rows)
    }
}

impl GuestClientSession for ClientSessionRes {
    async fn connect_proxy(
        relay_url: String,
        peer_id_hex: String,
        direct: Option<String>,
        pairing_token: String,
        cols: u16,
        rows: u16,
    ) -> Result<ClientSession, String> {
        let (endpoint, conn) = dial_connection(&relay_url, &peer_id_hex, direct).await?;
        Self::attach_framed(Some(endpoint), conn, &pairing_token, cols, rows).await
    }

    async fn dial(
        relay_url: String,
        peer_id_hex: String,
        direct: Option<String>,
        key: String,
        cols: u16,
        rows: u16,
    ) -> Result<ClientSession, String> {
        let (endpoint, conn) = dial_connection(&relay_url, &peer_id_hex, direct).await?;
        Self::start(Some(endpoint), conn, None, false, key, cols, rows)
    }

    async fn feed_keys(&self, keys: Vec<u8>) {
        self.inner.session.feed_keys(&keys);
    }

    async fn resize(&self, cols: u16, rows: u16) {
        self.inner.session.resize(cols, rows);
    }

    async fn drain_output(&self) -> Vec<u8> {
        self.inner.session.drain_output()
    }

    async fn stats(&self) -> SessionStats {
        self.inner.session.stats()
    }

    async fn max_datagram_size(&self) -> Option<u32> {
        self.inner.conn.max_datagram_size()
    }

    async fn detach(&self) {
        self.inner.alive.set(false);
        // Closing resolves the pending recv-datagram with an error,
        // which stops the recv pump; the tick pump exits on its next
        // wakeup.
        self.inner.conn.close(0, "detach");
    }
}

struct Component;

impl Guest for Component {
    type ClientSession = ClientSessionRes;
}

impl EmbedGuest for Component {
    async fn attach_proxy(
        conn: Connection,
        pairing_token: String,
        cols: u16,
        rows: u16,
    ) -> Result<ClientSession, String> {
        ClientSessionRes::attach_framed(None, conn, &pairing_token, cols, rows).await
    }
}

bindings::export!(Component with_types_in bindings);
