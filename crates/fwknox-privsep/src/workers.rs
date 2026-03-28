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

use crate::{error::PrivsepError, ipc::send_msg, messages::CaptureMsg};

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
    use crate::messages::CaptureMsg;

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
}
