//! Asynchronous SSH client library for Rust.
//!
//! The entry point for making SSH connections is the [`Client`].
#![allow(clippy::collapsible_if)]
#![allow(clippy::unused_unit)]
#![allow(clippy::unit_arg)]
#![allow(clippy::module_inception)]
#![warn(missing_docs)]

pub use crate::client::{
    AuthFailure, AuthNoneResult, AuthPasswordResult, AuthPasswordPrompt, AuthPubkeyResult,
};
pub use crate::client::{
    Channel, ChannelReceiver, ChannelEvent, ChannelReq, ChannelReply, ChannelConfig,
    DataType, DATA_STANDARD, DATA_STDERR,
};
pub use crate::client::{Client, ClientFuture, ClientConfig, GlobalReq, GlobalReply};
pub use crate::client::{ClientReceiver, ClientEvent, AcceptPubkey, AcceptChannel, AcceptTunnel};
pub use crate::client::{
    Session, SessionReceiver, SessionEvent, SessionResp, ExitSignal,
    PtyRequest, PtyTerminalModes, WindowChange,
};
pub use crate::client::{Tunnel, TunnelReceiver, TunnelEvent};
pub use crate::codec::{PacketEncode, PacketDecode};
pub use crate::error::{Result, Error, AlgoNegotiateError, DisconnectError, ChannelOpenError};

pub use self::cipher::CipherAlgo;
pub use self::kex::KexAlgo;
pub use self::mac::MacAlgo;
pub use self::pubkey::{PubkeyAlgo, Pubkey, Privkey};

pub use bytes;
pub use ecdsa;
pub use ecdsa::elliptic_curve;
pub use ed25519_dalek;
pub use p256;
pub use p384;
pub use pem;
pub use rsa;

pub mod cipher;
mod client;
mod codec;
pub mod codes;
mod error;
pub mod host_file;
pub mod kex;
pub mod keys;
pub mod mac;
pub mod pubkey;
mod util;
