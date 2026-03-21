// SPDX-License-Identifier: AGPL-3.0-or-later

//! `UdpCapture` — a `CaptureBackend` backed by a `UdpSocket`.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::{backend::CaptureBackend, error::CaptureError, packet::CapturedPacket};

/// Maximum UDP datagram size we will receive. Larger datagrams are
/// truncated by the kernel and rejected at the protocol layer.
pub const MAX_DATAGRAM_LEN: usize = 1500;

/// A capture backend that listens on a UDP socket.
#[derive(Debug)]
pub struct UdpCapture {
    socket: UdpSocket,
}

impl UdpCapture {
    /// Bind a new UDP capture socket to the given address.
    pub fn bind(addr: SocketAddr) -> Result<Self, CaptureError> {
        let socket = UdpSocket::bind(addr).map_err(CaptureError::Bind)?;
        Ok(Self { socket })
    }

    /// Borrow the underlying socket's local address (used by tests to
    /// inspect the bound port).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl CaptureBackend for UdpCapture {
    fn recv(&self) -> Result<CapturedPacket, CaptureError> {
        // Make sure we're in blocking-no-timeout mode for plain recv.
        self.socket
            .set_read_timeout(None)
            .map_err(CaptureError::Recv)?;
        let mut buf = [0u8; MAX_DATAGRAM_LEN];
        let (len, peer) = self.socket.recv_from(&mut buf).map_err(CaptureError::Recv)?;
        Ok(CapturedPacket {
            source_ip: peer.ip(),
            data: buf[..len].to_vec(),
        })
    }

    fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<CapturedPacket>, CaptureError> {
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(CaptureError::Recv)?;
        let mut buf = [0u8; MAX_DATAGRAM_LEN];
        match self.socket.recv_from(&mut buf) {
            Ok((len, peer)) => Ok(Some(CapturedPacket {
                source_ip: peer.ip(),
                data: buf[..len].to_vec(),
            })),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(CaptureError::Recv(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::Duration;

    use super::*;

    #[test]
    fn bind_to_ephemeral_port_succeeds() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let cap = UdpCapture::bind(addr).unwrap();
        let bound = cap.local_addr().unwrap();
        assert_eq!(bound.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(bound.port(), 0);
    }

    #[test]
    fn bind_to_already_bound_port_fails() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let first = UdpCapture::bind(addr).unwrap();
        let bound = first.local_addr().unwrap();
        let second = UdpCapture::bind(bound);
        assert!(second.is_err());
    }

    #[test]
    fn recv_returns_sent_payload() {
        let server =
            UdpCapture::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client =
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        let payload = b"hello fwknox";
        client.send_to(payload, server_addr).unwrap();
        let pkt = server.recv().unwrap();
        assert_eq!(pkt.data, payload);
        assert_eq!(pkt.source_ip, std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn recv_truncates_oversize_datagrams() {
        let server =
            UdpCapture::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client =
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        let big_payload = vec![0xAA; 2000];
        client.send_to(&big_payload, server_addr).unwrap();
        let pkt = server.recv().unwrap();
        // Kernel truncates to MAX_DATAGRAM_LEN.
        assert_eq!(pkt.data.len(), MAX_DATAGRAM_LEN);
    }

    #[test]
    fn recv_timeout_returns_none_on_timeout() {
        let server = UdpCapture::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        // No client sends anything; the recv must time out.
        let pkt = server.recv_timeout(Duration::from_millis(50)).unwrap();
        assert!(pkt.is_none());
    }

    #[test]
    fn recv_timeout_returns_packet_when_one_arrives() {
        let server = UdpCapture::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        client.send_to(b"hello timeout", server_addr).unwrap();
        // Generous timeout so loopback delivery completes.
        let pkt = server
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .expect("packet should arrive");
        assert_eq!(pkt.data, b"hello timeout");
    }
}
