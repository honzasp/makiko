//! SSH client library.
//!
//! The entry point for making SSH connections is the [`Client`].
#![allow(clippy::collapsible_if)]
#![allow(clippy::unused_unit)]
#![allow(clippy::unit_arg)]
#![allow(clippy::module_inception)]
#![warn(missing_docs)]

pub use crate::client::{AuthFailure, AuthNoneResult, AuthPasswordResult, AuthPasswordPrompt};
pub use crate::client::{
    Channel, ChannelReceiver, ChannelEvent, ChannelReq, ChannelReply,
    DataType, DATA_STANDARD, DATA_STDERR,
};
pub use crate::client::{Client, ClientReceiver, ClientFuture, ClientConfig};
pub use crate::client::{ClientEvent, AcceptPubkeySender};
pub use crate::client::{Session, SessionReceiver, SessionEvent, SessionReply, ExitSignal};
pub use crate::codec::{PacketEncode, PacketDecode};
pub use crate::error::{Result, Error, AlgoNegotiateError, DisconnectError, ChannelOpenError};

pub use self::cipher::CipherAlgo;
pub use self::kex::KexAlgo;
pub use self::mac::MacAlgo;
pub use self::pubkey::{PubkeyAlgo, Pubkey};

pub use bytes;

pub mod cipher;
mod client;
mod codec;
pub mod codes;
mod error;
pub mod kex;
pub mod mac;
pub mod pubkey;
mod util;
