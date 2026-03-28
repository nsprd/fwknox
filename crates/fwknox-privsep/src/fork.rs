// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helpers for creating socketpairs and reaping forked workers.

use std::os::unix::net::UnixDatagram;

use nix::{
    sys::{
        signal::{kill, Signal},
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};
use tracing::{debug, warn};

use crate::error::PrivsepError;

/// Create a pair of connected `SOCK_DGRAM` Unix sockets.
///
/// Returns `(parent_side, child_side)`. The caller keeps `parent_side`
/// and gives `child_side` to a forked worker.
pub fn make_socketpair() -> Result<(UnixDatagram, UnixDatagram), PrivsepError> {
    UnixDatagram::pair().map_err(PrivsepError::Io)
}

/// Handle to a forked worker. Records the PID so the parent can send
/// it a signal and reap it.
#[derive(Debug)]
pub struct ForkedWorker {
    /// PID of the child process.
    pub pid: Pid,
    /// Short name for log messages (e.g. "capture", "crypto").
    pub name: &'static str,
}

impl ForkedWorker {
    /// Send SIGTERM to the worker, asking it to shut down gracefully.
    pub fn signal_terminate(&self) -> Result<(), PrivsepError> {
        debug!(
            worker = self.name,
            pid = self.pid.as_raw(),
            "sending SIGTERM"
        );
        kill(self.pid, Signal::SIGTERM).map_err(|source| PrivsepError::Syscall {
            syscall: "kill",
            source,
        })
    }

    /// Block until the worker exits and return its wait status.
    pub fn wait(&self) -> Result<WaitStatus, PrivsepError> {
        debug!(worker = self.name, pid = self.pid.as_raw(), "waitpid");
        waitpid(self.pid, None).map_err(|source| PrivsepError::Syscall {
            syscall: "waitpid",
            source,
        })
    }

    /// Terminate and reap. If the signal fails (worker already dead),
    /// still try the waitpid.
    pub fn terminate_and_wait(&self) -> Result<WaitStatus, PrivsepError> {
        if let Err(e) = self.signal_terminate() {
            warn!(worker = self.name, error = %e, "signal_terminate failed; trying waitpid anyway");
        }
        self.wait()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_socketpair_returns_two_usable_sockets() {
        let (a, b) = make_socketpair().unwrap();
        a.send(b"hello").unwrap();
        let mut buf = [0u8; 16];
        let len = b.recv(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
    }

    #[test]
    fn make_socketpair_is_bidirectional() {
        let (a, b) = make_socketpair().unwrap();
        b.send(b"reply").unwrap();
        let mut buf = [0u8; 16];
        let len = a.recv(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"reply");
    }
}
