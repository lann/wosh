//! wosh-listener-core: a wasi:cli component. Loads (or mints and
//! persists) an iroh identity, binds a polymorph-iroh endpoint on a
//! configured relay, prints a QR code + link (URL fragment =
//! connection string: iroh pubkey + relay + optional pairing token),
//! and for each accepted connection reads a short pairing-token prefix
//! off the first stream the peer opens and -- if it matches -- bridges
//! the rest of that stream, byte for byte, to a configured TCP
//! endpoint. This component never parses SSH; it is a dumb pipe once
//! the token check passes.

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "listener",
        generate_all,
    });
}

mod identity;
mod tcp;

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;

use bindings::polymorph::iroh::endpoint::{Connection, Endpoint, EndpointOptions};

use clap::Parser;
use wosh_connstring::ConnString;

/// v0 connection ALPN, shared with the browser client.
const ALPN: &[u8] = b"wosh/1";

/// n0's public NA-East relay, first of the defaults baked into iroh
/// itself (`iroh::defaults::prod`; the others are usw1-1, euc1-1,
/// aps1-1). Spelled without iroh's trailing FQDN dot: browsers accept
/// either, but rustls-based websocket hosts reject a trailing dot in
/// the TLS server name, and the connstring hands this exact string to
/// both sides.
const DEFAULT_RELAY: &str = "https://use1-1.relay.n0.iroh.link";

/// Expose a local TCP endpoint (an sshd, by default) to the browser
/// client as a QR code / link.
#[derive(Parser)]
#[command(name = "wosh-listener")]
struct Cli {
    /// Relay URL this endpoint homes on; embedded in the connection
    /// string, so the browser client dials the same relay
    #[arg(long, env = "RELAY_URL", default_value = DEFAULT_RELAY)]
    relay: String,

    /// ip:port each paired connection is bridged to
    #[arg(long, default_value = "127.0.0.1:22")]
    target: SocketAddr,

    /// Pairing token, 32 hex chars [default: freshly random]
    #[arg(long, value_parser = parse_token, conflicts_with = "no_token")]
    token: Option<[u8; wosh_connstring::TOKEN_LEN]>,

    /// Open mode: no pairing token; anyone with the link can connect
    #[arg(long)]
    no_token: bool,

    /// Base URL the QR/link points at (the connection string rides its
    /// #fragment). The QR code is the whole bootstrap, so this must be
    /// a site a phone can open; point it at your own copy to avoid
    /// depending on the default origin
    #[arg(long, default_value = "https://lann.github.io/wosh/#")]
    qr_base: String,

    /// Print the link only, no QR code
    #[arg(long)]
    no_qr: bool,

    /// Mint a fresh identity for this run instead of loading/persisting
    /// one: the endpoint id (and so the connection string) changes every
    /// start, and browser host-key pins keyed on it will not carry over
    #[arg(long)]
    ephemeral_identity: bool,
}

fn parse_token(s: &str) -> Result<[u8; wosh_connstring::TOKEN_LEN], String> {
    const LEN: usize = wosh_connstring::TOKEN_LEN;
    let bytes = decode_hex(s).ok_or("not valid hex")?;
    if bytes.len() != LEN {
        return Err(format!(
            "must be exactly {} hex chars ({LEN} bytes), got {} bytes",
            LEN * 2,
            bytes.len()
        ));
    }
    let mut t = [0u8; LEN];
    t.copy_from_slice(&bytes);
    Ok(t)
}

fn random_token() -> [u8; wosh_connstring::TOKEN_LEN] {
    let mut t = [0u8; wosh_connstring::TOKEN_LEN];
    getrandom::getrandom(&mut t).expect("system randomness (wasi:random) unavailable");
    t
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

struct Component;

impl bindings::exports::wasi::cli::run::Guest for Component {
    async fn run() -> Result<(), ()> {
        let mut cli = match Cli::try_parse() {
            Ok(cli) => cli,
            Err(e) => {
                // clap renders help/version/errors itself, to the
                // right stream; --help must still exit 0.
                let real_error = e.use_stderr();
                let _ = e.print();
                return if real_error { Err(()) } else { Ok(()) };
            }
        };
        // Default: a fresh random pairing token. After this point
        // `token: None` means exactly open mode (`--no-token`).
        if !cli.no_token && cli.token.is_none() {
            cli.token = Some(random_token());
        }
        match run_listener(cli).await {
            Ok(()) => Ok(()),
            Err(e) => {
                eprintln!("wosh-listener: {e}");
                Err(())
            }
        }
    }
}

bindings::export!(Component with_types_in bindings);

async fn run_listener(cli: Cli) -> Result<(), String> {
    // Persistent by default: a stable endpoint id is what lets the
    // browser pin this listener's SSH host key across restarts.
    let identity = identity::load_or_create(cli.ephemeral_identity).await?;
    let options = EndpointOptions::new(&identity);
    options.add_alpn(ALPN);
    options.relay_url(&cli.relay);
    // Direct UDP is a real option for this side (unlike the browser
    // client): helps same-LAN peers and gives iroh a lower-latency
    // path to discover even off-LAN. WebRTC answers browser peers'
    // signaling for their own relay-to-datachannel upgrade.
    options.udp_bind_addr("0.0.0.0:0");
    options.webrtc(true);
    let endpoint = Endpoint::bind(options).await.map_err(|e| format!("bind: {e:?}"))?;

    let pubkey = endpoint.id();
    if pubkey.len() != wosh_connstring::PUBKEY_LEN {
        return Err(format!(
            "endpoint id is {} bytes, expected {}",
            pubkey.len(),
            wosh_connstring::PUBKEY_LEN
        ));
    }
    let mut pk = [0u8; wosh_connstring::PUBKEY_LEN];
    pk.copy_from_slice(&pubkey);

    let connstring = ConnString {
        pubkey: pk,
        relay_url: cli.relay.clone(),
        token: cli.token,
    }
    .encode();
    let url = format!("{}{}", cli.qr_base, connstring);

    println!("connstring: {connstring}");
    if let Some(direct) = endpoint.direct_addr() {
        println!("direct-addr: {direct}");
    }
    if !cli.no_qr {
        match qrcode::QrCode::new(url.as_bytes()) {
            Ok(code) => {
                let rendered = code
                    .render::<qrcode::render::unicode::Dense1x2>()
                    .quiet_zone(true)
                    .build();
                println!("{rendered}");
            }
            Err(e) => println!("(no QR: {e})"),
        }
    }
    println!("scan or open -> {url}");
    match &cli.token {
        Some(t) => println!("ready; target {} (pairing token required, hex: {})", cli.target, encode_hex(t)),
        None => println!(
            "ready; target {} (OPEN MODE -- no pairing token: anyone with the link can connect)",
            cli.target
        ),
    }

    // Clients this listener has PAIRED: iroh endpoint ids that once
    // presented a valid token. iroh authenticates the peer's id during
    // the handshake, so an enrolled id is as good as the token it once
    // showed -- which is what lets a printed QR outlive token rotation
    // for the devices that already used it (TOFU, listener->client
    // direction; the client's own TOFU of the listener is the SSH
    // host-key pin). Rotating the token only gates NEW devices.
    let paired = Rc::new(RefCell::new(pairing::load()));

    loop {
        match endpoint.accept().await {
            Ok(conn) => {
                let target = cli.target;
                let token = cli.token;
                let paired = paired.clone();
                wit_bindgen::spawn_local(async move {
                    let peer = encode_hex(&conn.peer());
                    match serve_connection(&conn, target, token, &paired).await {
                        Ok(summary) => eprintln!("[{peer}] {summary}"),
                        Err(e) => eprintln!("[{peer}] {e}"),
                    }
                    conn.close(0, "done");
                });
            }
            Err(e) => {
                eprintln!("accept: {e:?}");
                break;
            }
        }
    }
    Ok(())
}

async fn serve_connection(
    conn: &Connection,
    target: SocketAddr,
    token: Option<[u8; wosh_connstring::TOKEN_LEN]>,
    paired: &RefCell<std::collections::HashSet<String>>,
) -> Result<String, String> {
    let (send, recv) = conn.accept_bi().await.map_err(|e| format!("accept-bi: {e:?}"))?;
    // The frame always arrives (a tokenless connstring sends a
    // zero-length one); it must be consumed either way. The verdict:
    //   open mode          -> everyone bridges, nothing is enrolled
    //                         (no token means no enrollment signal);
    //   enrolled peer      -> bridges, whatever the frame says (its
    //                         token may be stale -- that is the point);
    //   valid token        -> bridges AND enrolls the peer id;
    //   anything else      -> refused.
    let (presented, leftover) = tcp::read_pairing_frame(&recv).await?;
    if let Some(want) = token {
        let peer = encode_hex(&conn.peer());
        let enrolled = paired.borrow().contains(&peer);
        if !enrolled {
            if presented.len() == want.len() && presented == want {
                paired.borrow_mut().insert(peer.clone());
                pairing::persist(&peer);
                eprintln!("[{peer}] paired (valid token; this device now reconnects across token rotations)");
            } else {
                return Err("refused: bad pairing token (and not a paired device)".into());
            }
        }
    }
    tcp::forward(send, recv, leftover, target).await
}

/// The paired-device store: one lowercase-hex endpoint id per line in
/// `wosh-data/paired`, next to the identity. Every failure degrades to
/// in-memory-only pairing (`--ephemeral-identity` runs have no mount
/// at all): the listener still works, enrollment just does not outlive
/// the process.
mod pairing {
    use std::collections::HashSet;
    use std::io::Write;

    const PATH: &str = "wosh-data/paired";

    pub fn load() -> HashSet<String> {
        match std::fs::read_to_string(PATH) {
            Ok(s) => s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
            Err(_) => HashSet::new(),
        }
    }

    pub fn persist(peer_hex: &str) {
        let appended = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(PATH)
            .and_then(|mut f| writeln!(f, "{peer_hex}"));
        if let Err(e) = appended {
            eprintln!("pairing: could not persist {PATH} ({e}); this pairing lasts until restart");
        }
    }
}
