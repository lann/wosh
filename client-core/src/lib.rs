//! wosh client-core glue (D7/B2).
//!
//! The composition seam: imports the pure-sync mosh engine and the
//! async polymorph-iroh endpoint, owns the two pumps (recv-datagram
//! loop, ~8 ms tick), speaks the proxy control channel (D8: control
//! lives here, not in the embedder — ciborium shapes shared with the
//! proxy via the proto crate), and exports the `client` driver
//! interface. The engine stays sans-I/O (finding 5); everything here
//! runs on `wit_bindgen::spawn_local` tasks.
//!
//! Datagram paths: `connect-proxy` / `attach-proxy` / `reattach-flow`
//! apply the tunnel framing (proto: 1-byte header, 2-fragment split —
//! finding 9); `dial` pumps raw mosh datagrams for harnesses and
//! interop peers.
//!
//! M6 adds the passkey surfaces: ceremony pass-through on the control
//! channel (the embedder owns the authenticator), the session key +
//! sequence-floor accessors for embedder-side persistence (D4,
//! finding 13), and the two-phase reattach flow.

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "client-world",
        generate_all,
    });
}

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use wosh_proto as proto;

use bindings::experiment::mosh::engine::Session as EngineSession;
use bindings::experiment::mosh::ssh::{SshSession, SshStatus};
use bindings::exports::experiment::mosh_client::client::{
    ClientSession, Guest, GuestClientSession, GuestReattachFlow, ReattachFlow, SessionStats,
};
use bindings::exports::experiment::mosh_client::embed::Guest as EmbedGuest;
use bindings::polymorph::iroh::endpoint::{
    Connection, Endpoint, EndpointOptions, RecvStream, SendStream,
};
use bindings::polymorph::iroh::identity_generate::generate;
use bindings::polymorph::iroh::types::{EndpointAddr, TransportAddr};
use bindings::wasi::clocks::monotonic_clock::wait_for;

/// v0 connection ALPN: control stream + datagram tunnel share it.
const ALPN: &[u8] = b"wosh/0";

/// Engine tick cadence — mosh's SEND_MINDELAY keystroke batching.
const TICK_NS: u64 = 8_000_000;

fn err<E: std::fmt::Debug>(what: &str) -> impl FnOnce(E) -> String + '_ {
    move |e| format!("{what}: {e:?}")
}

/// The control channel: stream halves plus the reassembly buffer.
/// Driver calls are serialized by the embedder, so plain RefCell
/// interior mutability suffices.
struct Control {
    send: SendStream,
    recv: RecvStream,
    buf: RefCell<Vec<u8>>,
}

impl Control {
    fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            buf: RefCell::new(Vec::new()),
        }
    }

    async fn next(&self) -> Result<proto::Proxy, String> {
        loop {
            if let Some(msg) = proto::decode::<proto::Proxy>(&mut self.buf.borrow_mut())? {
                return Ok(msg);
            }
            match self.recv.read(4096).await.map_err(err("control read"))? {
                Some(bytes) => self.buf.borrow_mut().extend_from_slice(&bytes),
                None => return Err("control stream closed by proxy".into()),
            }
        }
    }

    async fn send(&self, msg: &proto::Client) -> Result<(), String> {
        self.send
            .write(proto::encode(msg))
            .await
            .map_err(err("control write"))
    }

    async fn request(&self, msg: &proto::Client) -> Result<proto::Proxy, String> {
        self.send(msg).await?;
        match self.next().await? {
            proto::Proxy::Error { message } => Err(format!("proxy: {message}")),
            other => Ok(other),
        }
    }
}

struct Inner {
    session: EngineSession,
    conn: Connection,
    /// Keeps a self-bound endpoint alive for the session's lifetime
    /// (dropping it would close the connection under it).
    _endpoint: Option<Endpoint>,
    /// Control channel, held open for the session's lifetime (dropping
    /// it reads as detach to the proxy). M6 ceremonies ride it.
    control: Option<Control>,
    /// Tunnel framing on the datagram path (proxy flows) or raw
    /// (dial). None ⇒ raw.
    framing: Option<RefCell<(u8, proto::Defragmenter)>>,
    session_id: Option<u64>,
    key: String,
    /// The ssh server's host key fingerprint (connect-ssh path only):
    /// base64 SHA-256, for embedder-side TOFU pinning.
    ssh_host_key: Option<String>,
    alive: Cell<bool>,
}

struct ClientSessionRes {
    inner: Rc<Inner>,
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
    // Embedder path policy (guest env, no WIT surface): WOSH_UDP=off
    // skips the UDP direct path — the browser profile, where the
    // `wasi:sockets` providers are honest fail-on-call stubs and a
    // socket bind would fail the whole dial. Default: on (native).
    if std::env::var("WOSH_UDP").map(|v| v != "off").unwrap_or(true) {
        options.udp_bind_addr("0.0.0.0:0");
    }

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

/// Open the control stream and run the hello (pairing token) exchange.
async fn control_hello(conn: &Connection, pairing_token: &str) -> Result<Control, String> {
    let (send, recv) = conn.open_bi().await.map_err(err("open-bi"))?;
    let control = Control::new(send, recv);
    match control
        .request(&proto::Client::Hello {
            version: proto::CONTROL_VERSION,
            pairing_token: pairing_token.to_string(),
        })
        .await?
    {
        proto::Proxy::HelloAck { version } if version == proto::CONTROL_VERSION => Ok(control),
        proto::Proxy::HelloAck { version } => {
            Err(format!("proxy speaks control v{version}, we speak v0"))
        }
        other => Err(format!("unexpected control message: {other:?}")),
    }
}

/// Find `MOSH CONNECT <port> <key>` among the *complete* lines of the
/// exec output (a partial chunk could truncate the key — only lines
/// terminated by `\n` are parsed).
fn parse_mosh_connect(output: &[u8]) -> Option<(u16, String)> {
    let text = String::from_utf8_lossy(output);
    for line in text.split_inclusive('\n') {
        if !line.ends_with('\n') {
            break; // trailing partial line: wait for more output
        }
        let mut parts = line.split_whitespace();
        if parts.next() == Some("MOSH") && parts.next() == Some("CONNECT") {
            let port: u16 = parts.next()?.parse().ok()?;
            let key = parts.next()?.to_string();
            return Some((port, key));
        }
    }
    None
}

/// Drive the sans-I/O ssh engine over the forwarded stream until the
/// mosh bootstrap completes: handshake (with the host-key gate — the
/// password is never sent to an unapproved host), exec the mosh-server
/// command, and parse `MOSH CONNECT` from its output. Returns
/// `(udp-port, mosh-key, host-fingerprint)`.
///
/// Loop order matters (no starvation, no read-deadlock): flush the
/// engine's outbound bytes first — pumping and re-draining until quiet
/// — then act on status (the host-key gate parks the handshake with
/// nothing in flight, so it must be handled *before* awaiting a read),
/// then park on the stream read and feed. Awaiting the read while quiet
/// is safe mid-handshake: ssh is strict request-response.
async fn drive_ssh(
    send: &SendStream,
    recv: &RecvStream,
    user: &str,
    password: &str,
    expected_host_key: Option<&str>,
    command: &str,
) -> Result<(u16, String, String), String> {
    let ssh = SshSession::connect(user, password);
    let mut host_fp: Option<String> = None;
    let mut exec_started = false;
    let mut output: Vec<u8> = Vec::new();

    loop {
        // 1. Flush outbound: drain → write, pump, repeat until quiet.
        let bytes = ssh.drain();
        if !bytes.is_empty() {
            send.write(bytes).await.map_err(err("ssh write"))?;
            ssh.pump();
            continue;
        }

        // 2. Status gate (before any read-await).
        match ssh.status() {
            SshStatus::Connecting => {}
            SshStatus::HostKeyCheck => {
                let fp = ssh
                    .host_key_sha256()
                    .ok_or("host-key-check without a fingerprint")?;
                if let Some(expected) = expected_host_key {
                    if expected != fp {
                        ssh.host_key_decision(false);
                        return Err(format!(
                            "ssh host key mismatch: expected {expected}, server presented {fp} \
                             — refusing before authentication"
                        ));
                    }
                }
                host_fp = Some(fp);
                ssh.host_key_decision(true);
                ssh.pump();
                continue;
            }
            SshStatus::Ready => {
                if !exec_started {
                    ssh.exec(command)?;
                    exec_started = true;
                    ssh.pump();
                    continue;
                }
                output.extend_from_slice(&ssh.read_output());
                if let Some((port, key)) = parse_mosh_connect(&output) {
                    let fp = host_fp.ok_or("ready without a host key")?;
                    return Ok((port, key, fp));
                }
                if let Some(code) = ssh.exit_status() {
                    // Exit-status can beat the last output through the
                    // engine's internal buffers: stdout rides a separate
                    // goroutine reader, and one network flight can carry
                    // data + exit together (first seen when the upstream
                    // endpoint moved to event-driven wakeups and arrival
                    // coalescing changed). No further input exists after
                    // exit, so the drain strictly converges: pump
                    // scheduler rounds until read-output stays quiet a
                    // few consecutive rounds, then parse once more.
                    let mut quiet = 0;
                    while quiet < 4 {
                        ssh.pump();
                        let more = ssh.read_output();
                        if more.is_empty() {
                            quiet += 1;
                        } else {
                            quiet = 0;
                            output.extend_from_slice(&more);
                        }
                    }
                    if let Some((port, key)) = parse_mosh_connect(&output) {
                        let fp = host_fp.ok_or("ready without a host key")?;
                        return Ok((port, key, fp));
                    }
                    return Err(format!(
                        "'{command}' exited with status {code} without MOSH CONNECT: {}",
                        String::from_utf8_lossy(&output).trim()
                    ));
                }
            }
            SshStatus::Failed(e) => return Err(format!("ssh: {e}")),
        }

        // 3. Feed inbound: park on the stream, then run the scheduler.
        match recv.read(4096).await.map_err(err("ssh read"))? {
            Some(bytes) => {
                ssh.feed(&bytes);
                ssh.pump();
            }
            None => return Err("ssh stream closed by proxy".into()),
        }
    }
}

impl ClientSessionRes {
    #[allow(clippy::too_many_arguments)]
    fn start(
        endpoint: Option<Endpoint>,
        conn: Connection,
        control: Option<Control>,
        framed: bool,
        session_id: Option<u64>,
        key: String,
        initial_seq: Option<u64>,
        cols: u16,
        rows: u16,
        ssh_host_key: Option<String>,
    ) -> Result<ClientSession, String> {
        let session = EngineSession::connect(&key, cols, rows, initial_seq)?;
        let inner = Rc::new(Inner {
            session,
            conn,
            _endpoint: endpoint,
            control,
            framing: framed.then(|| RefCell::new((0u8, proto::Defragmenter::default()))),
            session_id,
            key,
            ssh_host_key,
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
        let control = control_hello(&conn, pairing_token).await?;
        let (session_id, key) = match control
            .request(&proto::Client::NewSession { cols, rows })
            .await?
        {
            proto::Proxy::SessionReady { session_id, key } => (session_id, key),
            other => return Err(format!("unexpected control message: {other:?}")),
        };
        Self::start(
            endpoint,
            conn,
            Some(control),
            true,
            Some(session_id),
            key,
            None,
            cols,
            rows,
            None,
        )
    }

    fn control(&self) -> Result<&Control, String> {
        self.inner
            .control
            .as_ref()
            .ok_or_else(|| "no control channel on this path (dial)".to_string())
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
        Self::start(
            Some(endpoint),
            conn,
            None,
            false,
            None,
            key,
            None,
            cols,
            rows,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_ssh(
        relay_url: String,
        peer_id_hex: String,
        direct: Option<String>,
        pairing_token: String,
        user: String,
        password: String,
        expected_host_key: Option<String>,
        mosh_command: Option<String>,
        cols: u16,
        rows: u16,
    ) -> Result<ClientSession, String> {
        let (endpoint, conn) = dial_connection(&relay_url, &peer_id_hex, direct).await?;
        let control = control_hello(&conn, &pairing_token).await?;

        // The forwarded ssh stream: tag byte first (the control stream
        // needs no tag — it is the first stream; every later one names
        // its purpose up front).
        let (send, recv) = conn.open_bi().await.map_err(err("open-bi (ssh)"))?;
        send.write(vec![proto::stream_tag::SSH_FORWARD])
            .await
            .map_err(err("ssh tag"))?;

        let command = mosh_command
            .unwrap_or_else(|| "mosh-server new -i 127.0.0.1 -c 256".to_string());
        let (port, key, host_fp) = drive_ssh(
            &send,
            &recv,
            &user,
            &password,
            expected_host_key.as_deref(),
            &command,
        )
        .await?;
        // mosh-server has detached; the ssh session and its stream are
        // done. Dropping them closes the proxy's TCP leg to sshd.
        drop(send);
        drop(recv);

        let session_id = match control
            .request(&proto::Client::ForwardDatagrams { port })
            .await?
        {
            proto::Proxy::ForwardOk { session_id } => session_id,
            other => return Err(format!("unexpected control message: {other:?}")),
        };

        Self::start(
            Some(endpoint),
            conn,
            Some(control),
            true,
            Some(session_id),
            key,
            None,
            cols,
            rows,
            Some(host_fp),
        )
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

    async fn session_id(&self) -> Option<u64> {
        self.inner.session_id
    }

    async fn ssh_host_key(&self) -> Option<String> {
        self.inner.ssh_host_key.clone()
    }

    async fn session_key(&self) -> String {
        self.inner.key.clone()
    }

    async fn register_start(&self) -> Result<Vec<u8>, String> {
        match self.control()?.request(&proto::Client::RegisterStart).await? {
            proto::Proxy::RegisterChallenge { challenge } => Ok(challenge),
            other => Err(format!("unexpected control message: {other:?}")),
        }
    }

    async fn register_finish(&self, response: Vec<u8>) -> Result<(), String> {
        match self
            .control()?
            .request(&proto::Client::RegisterFinish { response })
            .await?
        {
            proto::Proxy::RegisterOk => Ok(()),
            other => Err(format!("unexpected control message: {other:?}")),
        }
    }

    async fn make_persistent(&self, escrow: Vec<u8>) -> Result<(), String> {
        match self
            .control()?
            .request(&proto::Client::MakePersistent { escrow })
            .await?
        {
            proto::Proxy::PersistOk => Ok(()),
            other => Err(format!("unexpected control message: {other:?}")),
        }
    }

    async fn detach(&self) {
        self.inner.alive.set(false);
        // Closing resolves the pending recv-datagram with an error,
        // which stops the recv pump; the tick pump exits on its next
        // wakeup. Awaiting wait-closed keeps this export call — and
        // therefore the embedder's drive of the store — alive until
        // the CONNECTION_CLOSE actually reaches the wire; without it
        // a host that stops driving right after detach leaves the
        // peer to find out via idle timeout.
        self.inner.conn.close(0, "detach");
        self.inner.conn.wait_closed().await;
    }
}

/// The two-phase reattach (M6): connection + control live here until
/// `attach` hands them to a client session.
struct ReattachFlowRes {
    endpoint: RefCell<Option<Endpoint>>,
    conn: RefCell<Option<Connection>>,
    control: RefCell<Option<Control>>,
    session_id: u64,
    challenge: Vec<u8>,
    escrow_seen: Cell<bool>,
}

impl GuestReattachFlow for ReattachFlowRes {
    async fn begin(
        relay_url: String,
        peer_id_hex: String,
        direct: Option<String>,
        pairing_token: String,
        session_id: u64,
    ) -> Result<ReattachFlow, String> {
        let (endpoint, conn) = dial_connection(&relay_url, &peer_id_hex, direct).await?;
        let control = control_hello(&conn, &pairing_token).await?;
        let challenge = match control
            .request(&proto::Client::Reattach { session_id })
            .await?
        {
            proto::Proxy::AuthChallenge { challenge } => challenge,
            other => return Err(format!("unexpected control message: {other:?}")),
        };
        Ok(ReattachFlow::new(ReattachFlowRes {
            endpoint: RefCell::new(Some(endpoint)),
            conn: RefCell::new(Some(conn)),
            control: RefCell::new(Some(control)),
            session_id,
            challenge,
            escrow_seen: Cell::new(false),
        }))
    }

    async fn challenge(&self) -> Vec<u8> {
        self.challenge.clone()
    }

    async fn finish(&self, assertion: Vec<u8>) -> Result<Vec<u8>, String> {
        let control = self.control.borrow();
        let control = control.as_ref().ok_or("flow already attached")?;
        match control
            .request(&proto::Client::AuthFinish { assertion })
            .await?
        {
            proto::Proxy::ReattachReady { session_id, escrow } => {
                if session_id != self.session_id {
                    return Err("proxy readied a different session".into());
                }
                self.escrow_seen.set(true);
                Ok(escrow)
            }
            other => Err(format!("unexpected control message: {other:?}")),
        }
    }

    async fn attach(
        &self,
        key: String,
        initial_seq: u64,
        cols: u16,
        rows: u16,
    ) -> Result<ClientSession, String> {
        if !self.escrow_seen.get() {
            return Err("finish the assertion before attaching".into());
        }
        let endpoint = self.endpoint.borrow_mut().take();
        let conn = self.conn.borrow_mut().take().ok_or("flow already attached")?;
        let control = self.control.borrow_mut().take();
        ClientSessionRes::start(
            endpoint,
            conn,
            control,
            true,
            Some(self.session_id),
            key,
            Some(initial_seq),
            cols,
            rows,
            None,
        )
    }
}

struct Component;

impl Guest for Component {
    type ClientSession = ClientSessionRes;
    type ReattachFlow = ReattachFlowRes;
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
