// SPDX-License-Identifier: AGPL-3.0-or-later

//! UDP send routine for the fwknox client.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};

use crate::error::ClientError;

/// Send a SPA packet to `destination:port` over UDP. Binds an ephemeral
/// local port and sends a single datagram.
pub fn send_udp_packet(
    packet: &[u8],
    destination: &str,
    port: u16,
) -> Result<(), ClientError> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let target = resolve(destination, port)?;
    socket.send_to(packet, target)?;
    Ok(())
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, ClientError> {
    let mut addrs = (host, port)
        .to_socket_addrs()
        .map_err(ClientError::Io)?;
    addrs
        .next()
        .ok_or(ClientError::InvalidArgument {
            field: "destination",
            reason: "host did not resolve to any address".into(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_to_loopback_succeeds_when_listener_is_bound() {
        // Bind a listener so the destination is reachable.
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        send_udp_packet(b"hello", "127.0.0.1", addr.port()).unwrap();
        // Verify it arrived.
        let mut buf = [0u8; 1500];
        let (len, _) = listener.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
    }

    #[test]
    fn unresolvable_host_returns_io_error() {
        // The .invalid TLD never resolves per RFC 6761.
        let err = send_udp_packet(b"x", "definitely.does.not.exist.invalid", 9).unwrap_err();
        assert!(matches!(err, ClientError::Io(_)));
    }
}
