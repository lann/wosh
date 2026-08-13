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

use std::net::SocketAddr;

use wit_bindgen::StreamResult;

use crate::bindings::polymorph::iroh::endpoint::{RecvStream, SendStream};
use crate::bindings::wasi::sockets::types::{
    IpAddressFamily, IpSocketAddress, Ipv4SocketAddress, Ipv6SocketAddress, TcpSocket,
};
use crate::bindings::wit_stream;

fn to_wasi(addr: SocketAddr) -> IpSocketAddress {
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

    // TCP -> iroh stream.
    let (mut tcp_rx, _rx_done) = sock.receive();
    let from_tcp = async move {
        let mut n = 0u64;
        loop {
            let (result, buf) = tcp_rx.read(Vec::with_capacity(16 * 1024)).await;
            if !buf.is_empty() {
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
        n
    };

    let (sent, received) = join2(to_tcp, from_tcp).await;
    let _ = send_done.await;
    Ok(format!("{sent}B -> target, {received}B <- target"))
}

async fn join2<A, B>(
    a: impl std::future::Future<Output = A>,
    b: impl std::future::Future<Output = B>,
) -> (A, B) {
    let mut a = std::pin::pin!(a);
    let mut b = std::pin::pin!(b);
    let mut ra = None;
    let mut rb = None;
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
        if ra.is_some() && rb.is_some() {
            std::task::Poll::Ready((ra.take().unwrap(), rb.take().unwrap()))
        } else {
            std::task::Poll::Pending
        }
    })
    .await
}
