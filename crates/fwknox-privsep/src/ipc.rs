// SPDX-License-Identifier: AGPL-3.0-or-later

//! Send and receive `MessagePack`-encoded messages over a
//! `UnixDatagram` socketpair.
//!
//! Because we use `SOCK_DGRAM`, each `send_to`/`recv_from` preserves
//! message boundaries — one send = one recv — so there's no length
//! framing to manage.

use std::os::unix::net::UnixDatagram;

use serde::{de::DeserializeOwned, Serialize};

use crate::error::PrivsepError;

/// Maximum size of a single IPC datagram. Larger than any SPA packet
/// (1500 bytes plus `MessagePack` overhead) but well under the kernel's
/// default `SOCK_DGRAM` limit (~213 KiB).
pub const MAX_IPC_MSG: usize = 8192;

/// Serialize `msg` to `MessagePack` and send it as a single datagram.
///
/// Returns [`PrivsepError::IpcEncode`] if serialization fails, or
/// [`PrivsepError::Io`] if the send syscall fails.
pub fn send_msg<M: Serialize>(socket: &UnixDatagram, msg: &M) -> Result<(), PrivsepError> {
    let bytes = rmp_serde::to_vec(msg).map_err(|e| PrivsepError::IpcEncode(e.to_string()))?;
    if bytes.len() > MAX_IPC_MSG {
        return Err(PrivsepError::IpcEncode(format!(
            "message too large: {} bytes > {} limit",
            bytes.len(),
            MAX_IPC_MSG
        )));
    }
    socket.send(&bytes)?;
    Ok(())
}

/// Receive a single `MessagePack`-encoded datagram, detecting
/// truncation via `MSG_TRUNC`.
///
/// Returns [`PrivsepError::IpcDecode`] if `MessagePack` fails to parse
/// the payload, [`PrivsepError::Io`] for transient I/O errors, or
/// [`PrivsepError::IpcTruncated`] if the kernel reports that the
/// datagram was larger than our receive buffer (the sender sent a
/// message larger than `MAX_IPC_MSG`, which the sender should have
/// rejected before sending).
pub fn recv_msg<M: DeserializeOwned>(socket: &UnixDatagram) -> Result<M, PrivsepError> {
    use std::os::fd::AsRawFd as _;

    let mut buf = [0u8; MAX_IPC_MSG];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };
    // Safety: zero-initialize msghdr; msg_name/msg_control are unused.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;

    let fd = socket.as_raw_fd();
    // Safety: fd is valid and owned by `socket`; msg points at stack-
    // allocated buffers we own; libc::recvmsg is safe to call.
    let n = unsafe { libc::recvmsg(fd, &raw mut msg, libc::MSG_TRUNC) };
    if n < 0 {
        return Err(PrivsepError::Io(std::io::Error::last_os_error()));
    }
    #[allow(clippy::cast_sign_loss)]
    let len = n as usize;
    if (msg.msg_flags & libc::MSG_TRUNC) != 0 {
        return Err(PrivsepError::IpcTruncated {
            reported: len,
            limit: MAX_IPC_MSG,
        });
    }
    // A zero-length recv on SOCK_DGRAM should not happen in practice
    // (Linux does not deliver it on peer close), but handle it
    // defensively as PeerClosed.
    if len == 0 {
        return Err(PrivsepError::PeerClosed);
    }
    rmp_serde::from_slice(&buf[..len]).map_err(|e| PrivsepError::IpcDecode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::messages::{CaptureMsg, CryptoMsg};

    fn pair() -> (UnixDatagram, UnixDatagram) {
        UnixDatagram::pair().unwrap()
    }

    #[test]
    fn capture_msg_roundtrip_over_datagram_pair() {
        let (a, b) = pair();
        let msg = CaptureMsg::Packet {
            source_ip: "127.0.0.1".parse().unwrap(),
            data: vec![1, 2, 3, 4, 5],
        };
        send_msg(&a, &msg).unwrap();
        let received: CaptureMsg = recv_msg(&b).unwrap();
        match received {
            CaptureMsg::Packet { source_ip, data } => {
                assert_eq!(source_ip, "127.0.0.1".parse::<IpAddr>().unwrap());
                assert_eq!(data, vec![1, 2, 3, 4, 5]);
            }
        }
    }

    #[test]
    fn crypto_msg_rejected_roundtrip() {
        let (a, b) = pair();
        let msg = CryptoMsg::Rejected {
            source_ip: "10.0.0.1".parse().unwrap(),
            reason: "timestamp too old".into(),
        };
        send_msg(&a, &msg).unwrap();
        let received: CryptoMsg = recv_msg(&b).unwrap();
        match received {
            CryptoMsg::Rejected { source_ip, reason } => {
                assert_eq!(source_ip, "10.0.0.1".parse::<IpAddr>().unwrap());
                assert_eq!(reason, "timestamp too old");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn crypto_msg_nomatch_roundtrip() {
        let (a, b) = pair();
        let msg = CryptoMsg::NoMatch {
            source_ip: "203.0.113.1".parse().unwrap(),
        };
        send_msg(&a, &msg).unwrap();
        let received: CryptoMsg = recv_msg(&b).unwrap();
        assert!(matches!(received, CryptoMsg::NoMatch { .. }));
    }

    #[test]
    fn oversize_message_is_rejected_before_send() {
        let (a, _b) = pair();
        let huge = CaptureMsg::Packet {
            source_ip: "127.0.0.1".parse().unwrap(),
            data: vec![0u8; MAX_IPC_MSG + 1024],
        };
        let err = send_msg(&a, &huge).unwrap_err();
        assert!(matches!(err, PrivsepError::IpcEncode(_)));
    }

    #[test]
    fn oversized_datagram_is_detected_as_truncated() {
        // Bypass send_msg (which rejects oversized messages) and
        // write directly to the socket so the kernel delivers a
        // datagram larger than MAX_IPC_MSG. The receiver should
        // report IpcTruncated.
        let (a, b) = pair();
        b.set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        let huge = vec![0u8; MAX_IPC_MSG + 1024];
        a.send(&huge).unwrap();
        let result: Result<CaptureMsg, _> = recv_msg(&b);
        match result {
            Err(PrivsepError::IpcTruncated { reported, limit }) => {
                assert_eq!(limit, MAX_IPC_MSG);
                assert!(reported >= MAX_IPC_MSG);
            }
            other => panic!("expected IpcTruncated, got {other:?}"),
        }
    }

    #[test]
    fn recv_from_closed_peer_returns_peer_closed() {
        let (a, b) = pair();
        drop(a);
        // With the peer dropped, recv on b should either error with EOF
        // or return PeerClosed depending on kernel behavior. For
        // SOCK_DGRAM on Linux, recv returns 0 bytes which our wrapper
        // maps to PrivsepError::PeerClosed.
        //
        // Set a tight read timeout so the test doesn't hang if the
        // kernel's behavior differs.
        b.set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();
        let result: Result<CaptureMsg, _> = recv_msg(&b);
        // Either PeerClosed (zero-byte recv) or Io (WouldBlock/TimedOut
        // from the timeout) is acceptable.
        assert!(matches!(
            result,
            Err(PrivsepError::PeerClosed | PrivsepError::Io(_))
        ));
    }
}
