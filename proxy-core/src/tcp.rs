//! The SSH_FORWARD stream ↔ TCP leg (M7, workstream F): proxy-core
//! forwards a client-opened bi stream to the ssh target on the proxy
//! host's loopback over `wasi:sockets` 0.3 TCP.
//!
//! The p3 TCP surface is stream-shaped: `send` is called once with a
//! `stream<u8>` the guest writes into over time; `receive` is called
//! once and yields a `stream<u8>` the guest reads. Teardown rides the
//! natural FIN cascade — when the iroh stream ends we drop the send
//! writer (FIN to sshd), sshd closes its side, the receive stream
//! completes, and both pumps retire without cancelling any in-flight
//! import (the teardown discipline).

use std::net::SocketAddr;

use wit_bindgen::StreamResult;

use crate::bindings::polymorph::iroh::endpoint::{RecvStream, SendStream};
use crate::bindings::wasi::sockets::types::{IpAddressFamily, TcpSocket};
use crate::bindings::wit_stream;
use crate::udp::to_wasi;

/// Forward one tagged stream to `target` until either side ends.
/// Returns a small human summary for the connection log.
pub async fn forward(
    send: SendStream,
    recv: RecvStream,
    target: SocketAddr,
) -> Result<String, String> {
    let family = match target {
        SocketAddr::V4(_) => IpAddressFamily::Ipv4,
        SocketAddr::V6(_) => IpAddressFamily::Ipv6,
    };
    let sock = TcpSocket::create(family).map_err(|e| format!("tcp create: {e:?}"))?;
    sock.connect(to_wasi(target))
        .await
        .map_err(|e| format!("tcp connect {target}: {e:?}"))?;

    // iroh stream → TCP: one send stream for the socket's lifetime.
    let (mut tcp_tx, tcp_tx_reader) = wit_stream::new();
    let send_done = sock.send(tcp_tx_reader);
    let to_tcp = async move {
        let mut n = 0u64;
        loop {
            match recv.read(4096).await {
                Ok(Some(bytes)) => {
                    n += bytes.len() as u64;
                    if !tcp_tx.write_all(bytes).await.is_empty() {
                        break; // socket side gone
                    }
                }
                Ok(None) | Err(_) => break, // client finished or connection died
            }
        }
        drop(tcp_tx); // FIN → the ssh server closes its side
        n
    };

    // TCP → iroh stream.
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
    // The send-side future resolves once the writer is dropped and the
    // socket flushed; awaiting it keeps the socket resource alive until
    // the FIN is really out.
    let _ = send_done.await;
    Ok(format!("{sent}B → ssh, {received}B ← ssh"))
}

async fn join2<A, B>(a: impl std::future::Future<Output = A>, b: impl std::future::Future<Output = B>) -> (A, B) {
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
