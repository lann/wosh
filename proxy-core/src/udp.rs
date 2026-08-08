//! A bound `wasi:sockets` UDP socket — cribbed from polymorph-iroh's
//! endpoint `udp.rs` (the same host surface serves both).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::bindings::wasi::sockets::types::{
    ErrorCode, IpAddressFamily, IpSocketAddress, Ipv4SocketAddress, Ipv6SocketAddress, UdpSocket,
};

pub struct UdpWire {
    socket: UdpSocket,
    local: SocketAddr,
}

impl UdpWire {
    /// Create and bind at `bind_addr` (`ip:port`; port 0 picks one).
    pub fn bind(bind_addr: &str) -> Result<Self, String> {
        let addr: SocketAddr = bind_addr
            .parse()
            .map_err(|e| format!("udp bind address {bind_addr:?}: {e}"))?;
        let family = match addr {
            SocketAddr::V4(_) => IpAddressFamily::Ipv4,
            SocketAddr::V6(_) => IpAddressFamily::Ipv6,
        };
        let socket = UdpSocket::create(family).map_err(|e| format!("udp create: {e:?}"))?;
        socket
            .bind(to_wasi(addr))
            .map_err(|e| format!("udp bind: {e:?}"))?;
        let local = from_wasi(
            socket
                .get_local_address()
                .map_err(|e| format!("udp local address: {e:?}"))?,
        );
        Ok(Self { socket, local })
    }

    /// Send one datagram to `remote`.
    pub async fn send(&self, remote: SocketAddr, payload: &[u8]) -> Result<(), String> {
        self.socket
            .send(payload.to_vec(), Some(to_wasi(remote)))
            .await
            .map_err(|e| format!("udp send: {e:?}"))
    }

    /// The next inbound datagram and its source.
    pub async fn receive(&self) -> Result<(Vec<u8>, SocketAddr), ErrorCode> {
        let (payload, remote) = self.socket.receive().await?;
        Ok((payload, from_wasi(remote)))
    }

    /// Send a zero-length datagram to our own address: resolves a
    /// pending `receive` so a pump can retire without cancelling an
    /// in-flight import (the teardown discipline).
    pub async fn wake_receiver(&self) {
        let _ = self.socket.send(Vec::new(), Some(to_wasi(self.local))).await;
    }
}

fn to_wasi(addr: SocketAddr) -> IpSocketAddress {
    match addr {
        SocketAddr::V4(v4) => IpSocketAddress::Ipv4(Ipv4SocketAddress {
            port: v4.port(),
            address: {
                let o = v4.ip().octets();
                (o[0], o[1], o[2], o[3])
            },
        }),
        SocketAddr::V6(v6) => IpSocketAddress::Ipv6(Ipv6SocketAddress {
            port: v6.port(),
            flow_info: v6.flowinfo(),
            scope_id: v6.scope_id(),
            address: v6.ip().segments().into(),
        }),
    }
}

fn from_wasi(addr: IpSocketAddress) -> SocketAddr {
    match addr {
        IpSocketAddress::Ipv4(v4) => {
            let (a, b, c, d) = v4.address;
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), v4.port)
        }
        IpSocketAddress::Ipv6(v6) => {
            let [a, b, c, d, e, f, g, h] = v6.address.into();
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)),
                v6.port,
            )
        }
    }
}
