// SPDX-License-Identifier: AGPL-3.0-or-later

//! `UdpCapture` — a `CaptureBackend` backed by a `UdpSocket`.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    os::fd::AsRawFd as _,
    sync::Mutex,
    time::Duration,
};

use crate::{backend::CaptureBackend, error::CaptureError, packet::CapturedPacket};

/// Maximum UDP datagram size we will receive. Larger datagrams are
/// detected via `MSG_TRUNC` and dropped with a warning so they never
/// reach the protocol layer as truncated bodies.
pub const MAX_DATAGRAM_LEN: usize = 1500;

/// A capture backend that listens on a UDP socket.
///
/// `last_timeout` caches the most recently applied read timeout so that
/// steady-state `recv_timeout` calls (the daemon's main loop polls with
/// the same duration on every iteration) skip a redundant
/// `set_read_timeout` syscall per packet.
#[derive(Debug)]
pub struct UdpCapture {
    socket: UdpSocket,
    last_timeout: Mutex<Option<Duration>>,
}

impl UdpCapture {
    /// Bind a new UDP capture socket to the given address.
    pub fn bind(addr: SocketAddr) -> Result<Self, CaptureError> {
        let socket = UdpSocket::bind(addr).map_err(CaptureError::Bind)?;
        Ok(Self {
            socket,
            last_timeout: Mutex::new(None),
        })
    }

    /// Wrap an already-bound [`UdpSocket`] in a [`UdpCapture`].
    ///
    /// Used by the daemon binary when the privsep orchestrator and the
    /// single-process run loop share the same bind step — the socket
    /// is bound once up front, then handed to whichever entry point
    /// the config dispatches to.
    #[must_use]
    pub fn from_socket(socket: UdpSocket) -> Self {
        Self {
            socket,
            last_timeout: Mutex::new(None),
        }
    }

    /// Borrow the underlying socket's local address (used by tests to
    /// inspect the bound port).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl CaptureBackend for UdpCapture {
    fn recv_timeout(&self, timeout: Duration) -> Result<Option<CapturedPacket>, CaptureError> {
        // Only issue the `set_read_timeout` syscall when the requested
        // timeout differs from the last one we applied. The daemon's
        // main loop polls with a fixed duration on every iteration, so
        // this elides one syscall per packet in steady state.
        {
            let mut cached = self.last_timeout.lock().expect("last_timeout poisoned");
            if *cached != Some(timeout) {
                self.socket
                    .set_read_timeout(Some(timeout))
                    .map_err(CaptureError::Recv)?;
                *cached = Some(timeout);
            }
        }
        let mut buf = [0u8; MAX_DATAGRAM_LEN];
        match recvmsg_with_trunc(&self.socket, &mut buf) {
            Ok(RecvOutcome::Packet { len, source_ip }) => Ok(Some(CapturedPacket {
                source_ip,
                data: buf[..len].to_vec(),
            })),
            Ok(RecvOutcome::Truncated {
                reported,
                source_ip,
            }) => {
                tracing::warn!(
                    source = %source_ip,
                    reported_len = reported,
                    max = MAX_DATAGRAM_LEN,
                    "UDP datagram larger than buffer; dropped"
                );
                // Surface as a poll tick so the daemon's main loop can
                // check its shutdown flag and try again on the next
                // iteration rather than returning a truncated body.
                Ok(None)
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(CaptureError::Recv(e)),
        }
    }
}

/// Outcome of a single `recvmsg` call.
enum RecvOutcome {
    /// A complete datagram was delivered; `len` bytes at the head of
    /// the caller's buffer are valid.
    Packet { len: usize, source_ip: IpAddr },
    /// The kernel reported `MSG_TRUNC` — the datagram did not fit in
    /// our buffer and was silently truncated. The caller should drop
    /// it rather than forward a partial body upstream.
    Truncated { reported: usize, source_ip: IpAddr },
}

/// Call `recvmsg` with `MSG_TRUNC` so the kernel reports the wire
/// length of oversized datagrams instead of silently truncating them.
/// Mirrors `fwknox_privsep::ipc::recv_msg`.
fn recvmsg_with_trunc(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<RecvOutcome> {
    // Safety: sockaddr_storage is a POD type; zero-initialization is
    // a valid bit pattern for it.
    let mut src_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };
    // Safety: msghdr is a POD type; zero-initialization is valid.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw mut src_storage).cast::<libc::c_void>();
    #[allow(clippy::cast_possible_truncation)]
    {
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    }
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;

    let fd = socket.as_raw_fd();
    // Safety: fd is owned by `socket` and valid for the duration of
    // this call; `msg` points at stack-allocated buffers we own and
    // keep live until recvmsg returns; MSG_TRUNC is a documented flag.
    let n = unsafe { libc::recvmsg(fd, &raw mut msg, libc::MSG_TRUNC) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::cast_sign_loss)]
    let reported = n as usize;
    let source_ip = sockaddr_storage_to_ip(&src_storage, msg.msg_namelen)?;

    if (msg.msg_flags & libc::MSG_TRUNC) != 0 {
        return Ok(RecvOutcome::Truncated {
            reported,
            source_ip,
        });
    }
    // With MSG_TRUNC set on a non-truncated datagram, `reported` equals
    // the datagram length, which must be within `buf.len()`.
    let len = reported.min(buf.len());
    Ok(RecvOutcome::Packet { len, source_ip })
}

/// Convert a populated `sockaddr_storage` (as returned by `recvmsg`)
/// into an `IpAddr`. Supports `AF_INET` and `AF_INET6`; anything else is
/// rejected as an I/O error so a misbehaving kernel never silently
/// fabricates a source address for us.
fn sockaddr_storage_to_ip(
    storage: &libc::sockaddr_storage,
    namelen: libc::socklen_t,
) -> io::Result<IpAddr> {
    match i32::from(storage.ss_family) {
        libc::AF_INET => {
            #[allow(clippy::cast_possible_truncation)]
            if (namelen as usize) < std::mem::size_of::<libc::sockaddr_in>() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short sockaddr_in from recvmsg",
                ));
            }
            // Safety: ss_family == AF_INET means the storage bytes are
            // a valid sockaddr_in; sockaddr_storage is at least as
            // large and at least as aligned as sockaddr_in.
            let sin: &libc::sockaddr_in =
                unsafe { &*std::ptr::from_ref(storage).cast::<libc::sockaddr_in>() };
            let bits = u32::from_be(sin.sin_addr.s_addr);
            Ok(IpAddr::V4(Ipv4Addr::from(bits)))
        }
        libc::AF_INET6 => {
            #[allow(clippy::cast_possible_truncation)]
            if (namelen as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short sockaddr_in6 from recvmsg",
                ));
            }
            // Safety: ss_family == AF_INET6 means the storage bytes are
            // a valid sockaddr_in6; sockaddr_storage is at least as
            // large and at least as aligned as sockaddr_in6.
            let sin6: &libc::sockaddr_in6 =
                unsafe { &*std::ptr::from_ref(storage).cast::<libc::sockaddr_in6>() };
            Ok(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("recvmsg returned unsupported address family {other}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        time::Duration,
    };

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
        let pkt = server
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .expect("packet should arrive");
        assert_eq!(pkt.data, payload);
        assert_eq!(pkt.source_ip, std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn oversize_udp_datagram_is_detected_and_dropped() {
        // A datagram larger than MAX_DATAGRAM_LEN must not bubble up
        // to the caller as a truncated body. The backend should log a
        // warning and return Ok(None) for that poll tick so the
        // daemon's main loop simply retries on the next iteration.
        let server =
            UdpCapture::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client =
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        let big_payload = vec![0xAA; MAX_DATAGRAM_LEN + 500];
        client.send_to(&big_payload, server_addr).unwrap();
        // First poll drains the oversized datagram and reports it as
        // dropped; no packet is delivered upward.
        let first = server.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            first.is_none(),
            "oversized datagram must not deliver a truncated body upward"
        );
        // And a small follow-up still works — the socket is healthy.
        client.send_to(b"hello", server_addr).unwrap();
        let second = server
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .expect("subsequent packet should arrive");
        assert_eq!(second.data, b"hello");
    }

    #[test]
    fn exact_max_len_datagram_is_delivered_intact() {
        // A datagram exactly at MAX_DATAGRAM_LEN must pass through
        // without triggering the truncation path.
        let server =
            UdpCapture::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client =
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        let payload = vec![0x5A; MAX_DATAGRAM_LEN];
        client.send_to(&payload, server_addr).unwrap();
        let pkt = server
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .expect("packet should arrive");
        assert_eq!(pkt.data.len(), MAX_DATAGRAM_LEN);
        assert_eq!(pkt.data, payload);
    }

    #[test]
    fn recv_timeout_returns_none_on_timeout() {
        let server =
            UdpCapture::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        // No client sends anything; the recv must time out.
        let pkt = server.recv_timeout(Duration::from_millis(50)).unwrap();
        assert!(pkt.is_none());
    }

    #[test]
    fn recv_timeout_returns_packet_when_one_arrives() {
        let server =
            UdpCapture::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client =
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        client.send_to(b"hello timeout", server_addr).unwrap();
        // Generous timeout so loopback delivery completes.
        let pkt = server
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .expect("packet should arrive");
        assert_eq!(pkt.data, b"hello timeout");
    }

    #[test]
    fn from_socket_wraps_existing_socket() {
        let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
        let original_addr = raw.local_addr().unwrap();
        let cap = UdpCapture::from_socket(raw);
        assert_eq!(cap.local_addr().unwrap(), original_addr);
    }
}
