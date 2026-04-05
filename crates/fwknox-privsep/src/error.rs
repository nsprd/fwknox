// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error type for the fwknox privsep crate.

use thiserror::Error;

/// All errors that can be produced by the fwknox privsep crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PrivsepError {
    /// An `fwknox-proto` operation failed inside a worker.
    #[error("protocol error: {0}")]
    Proto(#[from] fwknox_proto::ProtoError),

    /// `MessagePack` encode failure on an IPC message.
    #[error("ipc encode error: {0}")]
    IpcEncode(String),

    /// `MessagePack` decode failure on an IPC message.
    #[error("ipc decode error: {0}")]
    IpcDecode(String),

    /// An I/O error on the underlying socketpair or UDP socket.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A `nix` system call failed (fork, waitpid, kill, socketpair, ...).
    #[error("system call {syscall} failed: {source}")]
    Syscall {
        /// Name of the syscall that failed.
        syscall: &'static str,
        /// Underlying errno.
        #[source]
        source: nix::errno::Errno,
    },

    /// The IPC peer closed the socket while we were waiting for a message.
    #[error("ipc peer closed")]
    PeerClosed,

    /// A received datagram was truncated because it exceeded the
    /// IPC message limit. The sender's `send_msg` should have rejected
    /// the message before transmission — if this error fires, there
    /// is a version or schema mismatch between sender and receiver.
    #[error("IPC datagram truncated: received {reported} bytes, limit is {limit}")]
    IpcTruncated {
        /// The kernel-reported true size of the incoming datagram.
        reported: usize,
        /// Our receive buffer limit.
        limit: usize,
    },
}
