//! Two small jobs: (1) read the pairing-token prefix off a freshly
//! accepted bi-stream and compare it, and (2) bridge whatever comes
//! after to a TCP connection. The `wasi:sockets` 0.3 surface is
//! stream-shaped: `send` is called once with a `stream<u8>` the guest
//! writes into over time, and `receive` is called once and yields a
//! `stream<u8>` the guest reads. Teardown rides the natural FIN
//! cascade -- when the iroh stream ends we drop the send writer (FIN
//! to the target), the target closes its side, the receive stream
//! completes, and both pumps retire without cancelling any in-flight
//! import.

use std::cell::RefCell;
use std::net::SocketAddr;

use wit_bindgen::StreamResult;
use wosh_hostkey as hostkey;

use crate::bindings::polymorph::iroh::endpoint::{RecvStream, SendStream};
use crate::bindings::wasi::sockets::types::{
    IpAddressFamily, IpSocketAddress, Ipv4SocketAddress, Ipv6SocketAddress, TcpSocket,
};
use crate::bindings::wit_stream;

pub(crate) fn to_wasi(addr: SocketAddr) -> IpSocketAddress {
    match addr {
        SocketAddr::V4(a) => {
            let o = a.ip().octets();
            IpSocketAddress::Ipv4(Ipv4SocketAddress {
                port: a.port(),
                address: (o[0], o[1], o[2], o[3]),
            })
        }
        SocketAddr::V6(a) => {
            let s = a.ip().segments();
            IpSocketAddress::Ipv6(Ipv6SocketAddress {
                port: a.port(),
                flow_info: 0,
                address: (s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]),
                scope_id: 0,
            })
        }
    }
}

/// Read the pairing frame (`[len:u8][token]`) the client writes as the
/// very first thing on its opened stream. Returns the frame's token
/// bytes and any leftover bytes read past it -- those are
/// already-arrived proxied-stream bytes and must be forwarded first.
/// The VERDICT on the token is the caller's: it depends on enrollment
/// state and open mode, neither of which belongs here.
pub async fn read_pairing_frame(recv: &RecvStream) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut buf = Vec::new();
    while buf.is_empty() {
        match recv.read(64).await.map_err(|e| format!("read: {e:?}"))? {
            Some(chunk) if !chunk.is_empty() => buf.extend_from_slice(&chunk),
            Some(_) => continue, // an empty chunk can arrive without EOF; keep waiting
            None => return Err("connection closed before the pairing-token prefix".into()),
        }
    }
    let token_len = buf[0] as usize;
    while buf.len() < 1 + token_len {
        match recv.read(64).await.map_err(|e| format!("read: {e:?}"))? {
            Some(chunk) => buf.extend_from_slice(&chunk),
            None => return Err("connection closed mid pairing-token prefix".into()),
        }
    }
    let token = buf[1..1 + token_len].to_vec();
    let leftover = buf[1 + token_len..].to_vec();
    Ok((token, leftover))
}

/// Forward the rest of `recv` (with `leading` bytes already consumed
/// from it, by `read_token_prefix`) and `send` to/from a TCP
/// connection to `target`. Returns a small human summary for the
/// connection log.
pub async fn forward(
    send: SendStream,
    recv: RecvStream,
    leading: Vec<u8>,
    target: SocketAddr,
) -> Result<String, String> {
    let family = match target {
        SocketAddr::V4(_) => IpAddressFamily::Ipv4,
        SocketAddr::V6(_) => IpAddressFamily::Ipv6,
    };
    let sock = TcpSocket::create(family).map_err(|e| format!("tcp create: {e:?}"))?;
    // The single most likely operator error is a target that is not
    // actually there (nothing on the default 127.0.0.1:22, sshd
    // stopped, wrong --target). The peer only ever sees its tunnel
    // close, so this log line is the ONE place the real cause is
    // visible -- make it say so.
    sock.connect(to_wasi(target)).await.map_err(|e| {
        format!(
            "WARNING: could not reach the target {target}: {e:?} -- is the \
             service running? (--target sets it; this connection was dropped)"
        )
    })?;

    // iroh stream -> TCP: one send stream for the socket's lifetime.
    let (mut tcp_tx, tcp_tx_reader) = wit_stream::new();
    let send_done = sock.send(tcp_tx_reader);
    let to_tcp = async move {
        let mut n = leading.len() as u64;
        if !leading.is_empty() {
            let unwritten = tcp_tx.write_all(leading).await;
            if !unwritten.is_empty() {
                drop(tcp_tx);
                return n;
            }
        }
        loop {
            match recv.read(16 * 1024).await {
                Ok(Some(bytes)) => {
                    n += bytes.len() as u64;
                    if !tcp_tx.write_all(bytes).await.is_empty() {
                        break; // target side gone
                    }
                }
                Ok(None) | Err(_) => break, // client finished or connection died
            }
        }
        drop(tcp_tx); // FIN -> the target closes its side
        n
    };

    // TCP -> iroh stream. This is the direction that carries the
    // server's KEX reply, so it is where a COPY of each chunk goes to
    // the host-key observer. Strictly passive: the bytes written to
    // the tunnel below are the same bytes, in the same order, at the
    // same time, whatever the sniffer makes of them -- the only thing
    // it can do is end the connection, and only when known_hosts says
    // the server on the other end is not the one we were promised.
    let (mut tcp_rx, _rx_done) = sock.receive();
    let from_tcp = async move {
        let mut n = 0u64;
        let mut sniffer = hostkey::Sniffer::new();
        let mut refusal = None;
        loop {
            let (result, buf) = tcp_rx.read(Vec::with_capacity(16 * 1024)).await;
            if !buf.is_empty() {
                if !sniffer.finished() {
                    if let Some(key) = sniffer.feed(&buf) {
                        if let Err(e) = observe(target, key) {
                            // Refuse BEFORE forwarding this chunk: the
                            // client must not receive the KEX reply of
                            // a server we have decided to reject.
                            refusal = Some(e);
                            break;
                        }
                    }
                }
                n += buf.len() as u64;
                if send.write(buf).await.is_err() {
                    break; // stream/connection gone; FIN cascade ends the other pump
                }
            }
            match result {
                StreamResult::Complete(_) => {}
                StreamResult::Dropped | StreamResult::Cancelled => break,
            }
        }
        (n, refusal)
    };

    let ((sent, received), refusal) = join2_or_refuse(to_tcp, from_tcp).await;
    if let Some(e) = refusal {
        // Deliberately NOT awaiting `send_done` here. The normal
        // teardown rides the FIN cascade and lets every in-flight
        // import retire; a refusal cannot wait for that, because the
        // pump that would end it is parked reading from a client that
        // has no reason to say anything. Dropping the futures with
        // the connection is the price of tearing down promptly, and
        // it happens only on this path.
        return Err(e);
    }
    let _ = send_done.await;
    Ok(format!("{sent}B -> target, {received}B <- target"))
}

/// Run both pumps to completion -- except that the second one can end
/// the whole thing early: once it reports a refusal there is nothing
/// left to forward, and waiting for the other pump would mean waiting
/// for a client that will never speak again.
async fn join2_or_refuse(
    a: impl std::future::Future<Output = u64>,
    b: impl std::future::Future<Output = (u64, Option<String>)>,
) -> ((u64, u64), Option<String>) {
    let mut a = std::pin::pin!(a);
    let mut b = std::pin::pin!(b);
    let mut ra: Option<u64> = None;
    let mut rb: Option<(u64, Option<String>)> = None;
    std::future::poll_fn(|cx| {
        if ra.is_none() {
            if let std::task::Poll::Ready(v) = a.as_mut().poll(cx) {
                ra = Some(v);
            }
        }
        if rb.is_none() {
            if let std::task::Poll::Ready(v) = b.as_mut().poll(cx) {
                rb = Some(v);
            }
        }
        let refused = matches!(&rb, Some((_, Some(_))));
        if (ra.is_some() && rb.is_some()) || refused {
            let (received, refusal) = rb.take().unwrap();
            std::task::Poll::Ready(((ra.take().unwrap_or(0), received), refusal))
        } else {
            std::task::Poll::Pending
        }
    })
    .await
}

/// Process configuration for the host-key check: the operator's
/// opt-out, and the known_hosts text the native host handed in (as
/// CONTENT, not a directory handle -- see listener-host/src/main.rs
/// for why). Read once at startup rather than threaded through the
/// session state machine, because that is what it is: configuration.
#[derive(Default)]
struct HostKeyConfig {
    allow_host_key_mismatch: bool,
    known_hosts: String,
}

thread_local! {
    static CONFIG: RefCell<HostKeyConfig> = RefCell::new(HostKeyConfig::default());
}

/// Called once at startup, before any connection is served.
pub(crate) fn init_host_key_check(allow_host_key_mismatch: bool) {
    CONFIG.with(|c| {
        *c.borrow_mut() = HostKeyConfig {
            allow_host_key_mismatch,
            known_hosts: std::env::var("WOSH_KNOWN_HOSTS").unwrap_or_default(),
        };
    });
}

/// The process-wide host-key verdict.
///
/// Once per PROCESS, not once per connection: the fingerprint of the
/// sshd behind `--target` is a property of the target, and reprinting
/// it on every connection would bury the one line the operator is
/// meant to read. What IS per-connection is the check -- a later
/// connection presenting a DIFFERENT key is a change of identity
/// under a running listener, and gets its own verdict.
///
/// Returns `Err(message)` when this connection must be torn down.
pub(crate) fn observe(target: SocketAddr, key: &hostkey::PublicKey) -> Result<(), String> {
    let allow_host_key_mismatch = CONFIG.with(|c| c.borrow().allow_host_key_mismatch);
    thread_local! {
        /// (fingerprint we already ruled on, the refusal it earned).
        static SEEN: RefCell<Option<(String, Option<String>)>> = const { RefCell::new(None) };
    }
    let fp = hostkey::fingerprint(key);
    SEEN.with(|seen| {
        let mut seen = seen.borrow_mut();
        match seen.as_ref() {
            // The same key as before: the verdict was already spoken,
            // and repeating it every connection would be noise. The
            // REFUSAL is not noise, though -- it still applies.
            Some((prev, refusal)) if *prev == fp => match refusal {
                Some(e) => Err(e.clone()),
                None => Ok(()),
            },
            Some((prev, _)) => {
                let d = hostkey::policy_changed(prev, &fp, &target, allow_host_key_mismatch);
                if d.refuses() {
                    // Do NOT record the new key: leaving the earlier,
                    // corroborated one in place means the target
                    // coming back to its real key is silently fine,
                    // while every appearance of the impostor is
                    // refused loudly rather than once.
                    return Err(d.message);
                }
                say(&d);
                *seen = Some((fp, None));
                Ok(())
            }
            None => {
                // The operator's known_hosts, handed in by the native
                // host as CONTENT (see listener-host/src/main.rs for
                // why it is not a directory handle). Absent or empty
                // means every target is simply unknown.
                let text = CONFIG.with(|c| c.borrow().known_hosts.clone());
                let lookup = hostkey::lookup(&text, &hostkey::host_lookup_key(target), key);
                let d = hostkey::policy(&lookup, &fp, &target, allow_host_key_mismatch);
                let refusal = d.refuses().then(|| d.message.clone());
                if !d.refuses() {
                    say(&d);
                }
                *seen = Some((fp, refusal.clone()));
                match refusal {
                    Some(e) => Err(e),
                    None => Ok(()),
                }
            }
        }
    })
}

/// Where a verdict goes. The fingerprint the operator is meant to
/// compare with the phone belongs beside the QR code on stdout;
/// anything that opens with WARNING is a thing that went wrong and
/// belongs on stderr with the rest of the diagnostics. Refusals never
/// reach here -- they ride the `Err` back to the accept loop, which
/// already logs `[{peer}] {e}`.
fn say(d: &hostkey::Decision) {
    if d.message.starts_with("WARNING") {
        eprintln!("{}", d.message);
    } else {
        println!("{}", d.message);
    }
}
