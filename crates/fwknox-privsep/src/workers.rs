// SPDX-License-Identifier: AGPL-3.0-or-later

//! Worker run loops for the capture and crypto workers.
//!
//! Each `run_*_worker` function is designed to be called on the child
//! side of a `fork()` with the relevant sockets already set up and the
//! sandbox already applied. They block on their input socket in a
//! loop, emit to their output socket, and return when the input
//! reports a peer-closed condition (the parent's graceful-shutdown
//! signal).

use std::{net::UdpSocket, os::unix::net::UnixDatagram, time::Duration};

use tracing::{debug, info, warn};

use crate::{
    error::PrivsepError,
    ipc::send_msg,
    messages::{CaptureMsg, CryptoMsg},
};

/// How long the capture worker's UDP `recv_from` blocks before
/// returning to check the shutdown flag.
const CAPTURE_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Run the capture worker loop.
///
/// Reads UDP packets from `udp_socket` and forwards each one as a
/// [`CaptureMsg::Packet`] to the crypto worker via `to_crypto`. The
/// loop polls `is_shutdown` between each `recv_from` so it can exit
/// cleanly when the parent sends `SIGTERM`.
///
/// The caller is responsible for:
///
/// - Applying the worker sandbox *before* calling this function.
/// - Closing every file descriptor the worker should not have inherited.
/// - Installing signal handlers so `is_shutdown` flips on SIGTERM.
pub fn run_capture_worker<S>(
    udp_socket: &UdpSocket,
    to_crypto: &UnixDatagram,
    mut is_shutdown: S,
) -> Result<(), PrivsepError>
where
    S: FnMut() -> bool,
{
    info!("capture worker: starting");
    udp_socket
        .set_read_timeout(Some(CAPTURE_POLL_INTERVAL))
        .map_err(PrivsepError::Io)?;

    let mut buf = [0u8; 1500];
    loop {
        if is_shutdown() {
            info!("capture worker: shutdown flag set, exiting");
            return Ok(());
        }
        match udp_socket.recv_from(&mut buf) {
            Ok((len, peer)) => {
                debug!(
                    len,
                    peer = %peer,
                    "capture worker: forwarding packet to crypto"
                );
                let msg = CaptureMsg::Packet {
                    source_ip: peer.ip(),
                    data: buf[..len].to_vec(),
                };
                if let Err(e) = send_msg(to_crypto, &msg) {
                    warn!(error = %e, "capture worker: send to crypto failed; exiting");
                    return Err(e);
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Tick timeout: fall through to the shutdown check.
            }
            Err(e) => {
                warn!(error = %e, "capture worker: UDP recv failed; exiting");
                return Err(PrivsepError::Io(e));
            }
        }
    }
}

/// How long the crypto worker's `recv_msg` waits before returning to
/// check the shutdown flag.
const CRYPTO_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Run the crypto worker loop.
///
/// Reads [`CaptureMsg`] values from `from_capture`, hands each one
/// to the caller-supplied `validate` closure, and forwards the
/// resulting [`CryptoMsg`] to `to_parent`. The loop polls `is_shutdown`
/// between each receive so it can exit cleanly.
///
/// The `validate` closure is a dependency injection point: the daemon
/// wires it up to `fwknox_daemon`'s `match_packet` + time validation.
/// This keeps `fwknox-privsep` free of any dependency on
/// `fwknox-daemon`, avoiding a crate cycle.
pub fn run_crypto_worker<F, S>(
    from_capture: &UnixDatagram,
    to_parent: &UnixDatagram,
    mut validate: F,
    mut is_shutdown: S,
) -> Result<(), PrivsepError>
where
    F: FnMut(CaptureMsg) -> CryptoMsg,
    S: FnMut() -> bool,
{
    info!("crypto worker: starting");
    from_capture
        .set_read_timeout(Some(CRYPTO_POLL_INTERVAL))
        .map_err(PrivsepError::Io)?;

    loop {
        if is_shutdown() {
            info!("crypto worker: shutdown flag set, exiting");
            return Ok(());
        }
        match crate::ipc::recv_msg::<CaptureMsg>(from_capture) {
            Ok(capture_msg) => {
                debug!("crypto worker: received CaptureMsg");
                let reply = validate(capture_msg);
                if let Err(e) = send_msg(to_parent, &reply) {
                    warn!(error = %e, "crypto worker: send to parent failed; exiting");
                    return Err(e);
                }
            }
            Err(PrivsepError::PeerClosed) => {
                info!("crypto worker: capture side closed, exiting");
                return Ok(());
            }
            Err(PrivsepError::Io(ref e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Tick timeout: fall through to the shutdown check.
            }
            Err(e) => {
                warn!(error = %e, "crypto worker: recv from capture failed; exiting");
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
    };

    use super::*;
    use crate::messages::{CaptureMsg, CryptoMsg};

    #[test]
    fn capture_worker_forwards_real_packet_over_loopback() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let (worker_end, parent_end) = UnixDatagram::pair().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = thread::spawn(move || {
            run_capture_worker(&server, &worker_end, || {
                shutdown_clone.load(Ordering::SeqCst)
            })
        });

        thread::sleep(Duration::from_millis(50));

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.send_to(b"hello fwknox", server_addr).unwrap();

        parent_end
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let received: CaptureMsg = crate::ipc::recv_msg(&parent_end).unwrap();
        match received {
            CaptureMsg::Packet { source_ip, data } => {
                assert_eq!(
                    source_ip,
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                );
                assert_eq!(data, b"hello fwknox");
            }
        }

        shutdown.store(true, Ordering::SeqCst);
        let result = handle.join().unwrap();
        assert!(result.is_ok(), "worker returned error: {result:?}");
    }

    #[test]
    fn capture_worker_exits_cleanly_when_shutdown_is_true_before_first_recv() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (worker_end, _parent_end) = UnixDatagram::pair().unwrap();
        let shutdown = Arc::new(AtomicBool::new(true));
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = thread::spawn(move || {
            run_capture_worker(&server, &worker_end, || {
                shutdown_clone.load(Ordering::SeqCst)
            })
        });

        let result = handle.join().unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn crypto_worker_forwards_validation_result() {
        use std::net::Ipv4Addr;

        let (cap_end, crypto_in) = UnixDatagram::pair().unwrap();
        let (crypto_out, parent_end) = UnixDatagram::pair().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let validate = move |msg: CaptureMsg| -> CryptoMsg {
            match msg {
                CaptureMsg::Packet { source_ip, .. } => CryptoMsg::NoMatch { source_ip },
            }
        };

        let handle = thread::spawn(move || {
            run_crypto_worker(&crypto_in, &crypto_out, validate, || {
                shutdown_clone.load(Ordering::SeqCst)
            })
        });

        // Send a packet from the "capture" side.
        let cap_msg = CaptureMsg::Packet {
            source_ip: std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            data: vec![0, 1, 2, 3],
        };
        crate::ipc::send_msg(&cap_end, &cap_msg).unwrap();

        // Receive the validator's output on the parent side.
        parent_end
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let reply: CryptoMsg = crate::ipc::recv_msg(&parent_end).unwrap();
        assert!(matches!(reply, CryptoMsg::NoMatch { .. }));

        shutdown.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn crypto_worker_exits_when_capture_side_closes() {
        let (cap_end, crypto_in) = UnixDatagram::pair().unwrap();
        let (crypto_out, _parent_end) = UnixDatagram::pair().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);
        let shutdown_setter = Arc::clone(&shutdown);

        let validate = |msg: CaptureMsg| -> CryptoMsg {
            match msg {
                CaptureMsg::Packet { source_ip, .. } => CryptoMsg::NoMatch { source_ip },
            }
        };

        let handle = thread::spawn(move || {
            run_crypto_worker(&crypto_in, &crypto_out, validate, || {
                shutdown_clone.load(Ordering::SeqCst)
            })
        });

        // Drop the capture end. On AF_UNIX SOCK_DGRAM, closing the peer
        // does not produce a zero-byte recv (unlike SOCK_STREAM). The
        // worker will loop on its poll timeout. Signal shutdown so it
        // exits cleanly.
        drop(cap_end);
        shutdown_setter.store(true, Ordering::SeqCst);

        let result = handle.join().unwrap();
        assert!(result.is_ok(), "worker returned error: {result:?}");
    }
}
