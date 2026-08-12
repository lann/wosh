//! irsh-listener-core: a wasi:cli component. Generates an iroh
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

use irsh_connstring::ConnString;

/// v0 connection ALPN, shared with the browser client.
const ALPN: &[u8] = b"irsh/1";

struct Cli {
    relay: String,
    target: SocketAddr,
    /// `None` = open mode (no pairing token required); anyone who has
    /// the link can connect. Default is a fresh random token.
    token: Option<[u8; irsh_connstring::TOKEN_LEN]>,
    qr_base: String,
    no_qr: bool,
}

fn usage() -> String {
    "usage: irsh-listener-core --relay <url> --target <ip:port> \
     [--qr-base <url>] [--token <hex>] [--no-token] [--no-qr]\n\
     \n\
     --qr-base defaults to the deployed client at \
     https://lann.github.io/wosh/# ; point it at your own copy to avoid \
     depending on that origin."
        .into()
}

fn parse_args() -> Result<Cli, String> {
    let mut relay = None;
    let mut target = None;
    let mut token: Option<Option<[u8; irsh_connstring::TOKEN_LEN]>> = None; // None = unset (generate); Some(None) = --no-token
    let mut qr_base = None;
    let mut no_qr = false;

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(usage);
        match flag.as_str() {
            "--relay" => relay = Some(value()?),
            "--target" => {
                let v = value()?;
                target = Some(v.parse::<SocketAddr>().map_err(|e| format!("--target {v:?}: {e}"))?);
            }
            "--qr-base" => qr_base = Some(value()?),
            "--token" => {
                let v = value()?;
                let bytes = decode_hex(&v).ok_or_else(|| format!("--token {v:?}: not valid hex"))?;
                if bytes.len() != irsh_connstring::TOKEN_LEN {
                    return Err(format!(
                        "--token must be exactly {} bytes ({} hex chars), got {}",
                        irsh_connstring::TOKEN_LEN,
                        irsh_connstring::TOKEN_LEN * 2,
                        bytes.len()
                    ));
                }
                let mut t = [0u8; irsh_connstring::TOKEN_LEN];
                t.copy_from_slice(&bytes);
                token = Some(Some(t));
            }
            "--no-token" => token = Some(None),
            "--no-qr" => no_qr = true,
            "--help" | "-h" => return Err(usage()),
            other => return Err(format!("unknown flag {other:?}\n{}", usage())),
        }
    }

    let token = match token {
        Some(t) => t, // explicit --token or --no-token
        None => Some(random_token()), // default: a fresh random pairing token
    };

    Ok(Cli {
        relay: relay.ok_or_else(usage)?,
        target: target.ok_or_else(usage)?,
        token,
        // The deployed client. The QR code is the whole bootstrap, so
        // this has to point at a site a phone can actually open; use
        // --qr-base to aim at a self-hosted copy instead.
        qr_base: qr_base.unwrap_or_else(|| "https://lann.github.io/wosh/#".into()),
        no_qr,
    })
}

fn random_token() -> [u8; irsh_connstring::TOKEN_LEN] {
    let mut t = [0u8; irsh_connstring::TOKEN_LEN];
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
        let cli = match parse_args() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{e}");
                return Err(());
            }
        };
        match run_listener(cli).await {
            Ok(()) => Ok(()),
            Err(e) => {
                eprintln!("irsh-listener: {e}");
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
    if pubkey.len() != irsh_connstring::PUBKEY_LEN {
        return Err(format!(
            "endpoint id is {} bytes, expected {}",
            pubkey.len(),
            irsh_connstring::PUBKEY_LEN
        ));
    }
    let mut pk = [0u8; irsh_connstring::PUBKEY_LEN];
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
    token: Option<[u8; irsh_connstring::TOKEN_LEN]>,
) -> Result<String, String> {
    let (send, recv) = conn.accept_bi().await.map_err(|e| format!("accept-bi: {e:?}"))?;
    let leftover = tcp::read_token_prefix(&recv, token)
        .await?
        .ok_or("refused: bad pairing token")?;
    tcp::forward(send, recv, leftover, target).await
}
