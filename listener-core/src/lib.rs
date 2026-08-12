//! wosh-listener-core: a wasi:cli component. Generates an iroh
//! identity, binds a polymorph-iroh endpoint on a configured relay,
//! prints a QR code + link (URL fragment = connection string: iroh
//! pubkey + relay + optional pairing token), and for each accepted
//! connection reads a short pairing-token prefix off the first stream
//! the peer opens and -- if it matches -- bridges the rest of that
//! stream, byte for byte, to a configured TCP endpoint. This component
//! never parses SSH; it is a dumb pipe once the token check passes.

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "listener",
        generate_all,
    });
}

mod tcp;

use std::net::SocketAddr;

use bindings::polymorph::iroh::endpoint::{Connection, Endpoint, EndpointOptions};
use bindings::polymorph::iroh::identity_generate::generate as identity_generate;

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
    let identity = identity_generate().await.map_err(|e| format!("identity: {e:?}"))?;
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

    loop {
        match endpoint.accept().await {
            Ok(conn) => {
                let target = cli.target;
                let token = cli.token;
                wit_bindgen::spawn_local(async move {
                    let peer = encode_hex(&conn.peer());
                    match serve_connection(&conn, target, token).await {
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
) -> Result<String, String> {
    let (send, recv) = conn.accept_bi().await.map_err(|e| format!("accept-bi: {e:?}"))?;
    let leftover = tcp::read_token_prefix(&recv, token)
        .await?
        .ok_or("refused: bad pairing token")?;
    tcp::forward(send, recv, leftover, target).await
}
