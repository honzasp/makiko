//! Message authentication algorithms.
//!
//! The SSH protocol supports many message authentication algorithms (MACs), which are used to
//! provide **integrity** (the attacker cannot modify the messages that we exchange over SSH).
//!
//! The client and the server exchange lists of supported algorithms, and the first algorithm on
//! the client's list that is also supported by the server is used for the connection.
//!
//! # Supported algorithms
//!
//! - "hmac-sha2-256" ([`HMAC_SHA2_256`])
//! - "hmac-sha2-512" ([`HMAC_SHA2_512`])
//! - "hmac-sha1" ([`HMAC_SHA1`])
//! - "hmac-sha2-256-etm@openssh.com" ([`HMAC_SHA2_256_ETM`])
//! - "hmac-sha2-512-etm@openssh.com" ([`HMAC_SHA2_512_ETM`])
//! - "hmac-sha1-etm@openssh.com" ([`HMAC_SHA1_ETM`])
//! - "none" ([`NONE`])
use crate::Result;
use derivative::Derivative;
pub use self::hmac::{
    HMAC_SHA2_256, HMAC_SHA2_512, HMAC_SHA1,
    HMAC_SHA2_256_ETM, HMAC_SHA2_512_ETM, HMAC_SHA1_ETM,
};
pub use self::none::NONE;
pub(crate) use self::none::{INVALID, Empty};

mod none;
mod hmac;

/// Algorithm for authenticating messages.
///
/// See the [module documentation][self] for details.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct MacAlgo {
    /// Name of the algorithm.
    pub name: &'static str,
    pub(crate) tag_len: usize,
    pub(crate) key_len: usize,
    pub(crate) variant: MacAlgoVariant,
    #[derivative(Debug = "ignore")]
    pub(crate) make_mac: fn(key: &[u8]) -> Box<dyn Mac + Send>,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum MacAlgoVariant {
    EncryptAndMac,
    EncryptThenMac,
}

pub(crate) trait Mac {
    fn sign(&mut self, packet_seq: u32, data: &[u8], tag: &mut [u8]);
    fn verify(&mut self, packet_seq: u32, data: &[u8], tag: &[u8]) -> Result<MacVerified>;
}

#[derive(Debug)]
pub(crate) struct MacVerified(());

impl MacVerified {
    pub fn assertion() -> Self {
        Self(())
    }
}
