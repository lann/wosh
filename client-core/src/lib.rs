//! experiment-mosh client-core glue (D7/B2).
//!
//! The composition seam: imports the pure-sync mosh engine and the
//! async polymorph-iroh endpoint, owns the two pumps (recv-datagram
//! loop, ~8 ms tick), and exports the `client` driver interface. This
//! component is the only place in the client where async I/O and the
//! engine meet; the engine stays sans-I/O (finding 5), and everything
//! here runs on `wit_bindgen::spawn_local` tasks — no threads, no Go
//! timers, no jco-scheduler dependence on the wasmtime path.

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "client-world",
        generate_all,
    });
}

use std::cell::Cell;
use std::rc::Rc;

use bindings::experiment::mosh::engine::Session as EngineSession;
use bindings::exports::experiment::mosh_client::client::{
    ClientSession, Guest, GuestClientSession, SessionStats,
};
use bindings::exports::experiment::mosh_client::embed::Guest as EmbedGuest;
use bindings::polymorph::iroh::endpoint::{Connection, Endpoint, EndpointOptions};
use bindings::polymorph::iroh::identity_generate::generate;
use bindings::polymorph::iroh::types::{EndpointAddr, TransportAddr};
use bindings::wasi::clocks::monotonic_clock::wait_for;

/// v0 session ALPN; the control channel (M4+) shares the connection.
const ALPN: &[u8] = b"experiment-mosh/0";

/// Engine tick cadence — mosh's SEND_MINDELAY keystroke batching.
const TICK_NS: u64 = 8_000_000;

struct Inner {
    session: EngineSession,
    conn: Connection,
    /// Keeps a dial()-created endpoint alive for the session's
    /// lifetime (dropping it would close the connection under it).
    _endpoint: Option<Endpoint>,
    alive: Cell<bool>,
}

struct ClientSessionRes {
    inner: Rc<Inner>,
}

impl ClientSessionRes {
    fn start(
        endpoint: Option<Endpoint>,
        conn: Connection,
        key: String,
        cols: u16,
        rows: u16,
    ) -> Result<ClientSession, String> {
        let session = EngineSession::connect(&key, cols, rows)?;
        let inner = Rc::new(Inner {
            session,
            conn,
            _endpoint: endpoint,
            alive: Cell::new(true),
        });

        // The tick pump: flush pending actions/acks/retransmits and
        // push the produced datagrams to the wire. send-datagram is
        // sync and lossy by contract — errors are wire-loss, not ours.
        let tick = inner.clone();
        wit_bindgen::spawn_local(async move {
            while tick.alive.get() {
                wait_for(TICK_NS).await;
                for datagram in tick.session.tick() {
                    let _ = tick.conn.send_datagram(&datagram);
                }
            }
        });

        // The recv pump: every inbound datagram goes straight into the
        // engine. Errors mean the connection is gone — stop.
        let recv = inner.clone();
        wit_bindgen::spawn_local(async move {
            loop {
                match recv.conn.recv_datagram().await {
                    Ok(datagram) => {
                        if !recv.alive.get() {
                            break;
                        }
                        recv.session.handle_datagram(&datagram);
                    }
                    Err(_) => break,
                }
            }
            recv.alive.set(false);
        });

        Ok(ClientSession::new(ClientSessionRes { inner }))
    }
}

impl GuestClientSession for ClientSessionRes {
    async fn dial(
        relay_url: String,
        peer_id_hex: String,
        direct: Option<String>,
        key: String,
        cols: u16,
        rows: u16,
    ) -> Result<ClientSession, String> {
        let peer: Vec<u8> = hex::decode(&peer_id_hex).map_err(|e| format!("peer id: {e}"))?;
        if peer.len() != 32 {
            return Err("peer id is not 32 bytes".into());
        }

        let identity = generate().await.map_err(|e| format!("identity: {e:?}"))?;
        let options = EndpointOptions::new(&identity);
        options.add_alpn(ALPN);
        options.relay_url(&relay_url);
        // The direct path: bind a UDP socket so `ip` dial hints work.
        options.udp_bind_addr("0.0.0.0:0");

        let endpoint = Endpoint::bind(options)
            .await
            .map_err(|e| format!("bind: {e:?}"))?;

        let mut addrs = Vec::new();
        if let Some(hint) = direct {
            addrs.push(TransportAddr::Ip(hint));
        }
        addrs.push(TransportAddr::Relay(relay_url.clone()));

        let conn = endpoint
            .connect(
                EndpointAddr {
                    endpoint_id: peer,
                    addrs,
                },
                ALPN.to_vec(),
            )
            .await
            .map_err(|e| format!("connect: {e:?}"))?;

        Self::start(Some(endpoint), conn, key, cols, rows)
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
    async fn attach(
        conn: Connection,
        key: String,
        cols: u16,
        rows: u16,
    ) -> Result<ClientSession, String> {
        ClientSessionRes::start(None, conn, key, cols, rows)
    }
}

bindings::export!(Component with_types_in bindings);
