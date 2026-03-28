// SPDX-License-Identifier: AGPL-3.0-or-later

//! # fwknox-privsep

mod error;
mod fork;
mod ipc;
mod messages;

pub use error::PrivsepError;
pub use fork::{make_socketpair, ForkedWorker};
pub use ipc::{recv_msg, send_msg, MAX_IPC_MSG};
pub use messages::{CaptureMsg, CryptoMsg};
