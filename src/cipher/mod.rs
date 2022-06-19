//! Encryption and decryption algorithms.
//!
//! The SSH protocol supports many symmetric encryption algorithms (ciphers), which are used to
//! provide **confidentiality** (the attacker cannot see the content of the messages that we exchange
//! over SSH).
//!
//! The client and the server exchange lists of supported algorithms, and the first algorithm on
//! the client's list that is also supported by the server is used for the connection.
//!
//! # Supported algorithms
//!
//! - "aes128-ctr" ([`AES128_CTR`])
//! - "aes192-ctr" ([`AES192_CTR`])
//! - "aes256-ctr" ([`AES256_CTR`])
//! - "aes256-cbc" ([`AES256_CBC`])
//! - "none" ([`NONE`])
use crate::Result;
use derivative::Derivative;
pub use self::block::AES256_CBC;
pub use self::none::NONE;
pub use self::stream::{AES128_CTR, AES192_CTR, AES256_CTR};
pub(crate) use self::none::Identity;

mod block;
mod none;
mod stream;

/// Algorithm for encrypting and decrypting messages.
///
/// See the [module documentation][self] for details.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct CipherAlgo {
    /// Name of the algorithm.
    pub name: &'static str,
    pub(crate) block_len: usize,
    pub(crate) key_len: usize,
    pub(crate) iv_len: usize,
    #[derivative(Debug = "ignore")]
    pub(crate) make_encrypt: fn(key: &[u8], iv: &[u8]) -> Box<dyn Encrypt + Send>,
    #[derivative(Debug = "ignore")]
    pub(crate) make_decrypt: fn(key: &[u8], iv: &[u8]) -> Box<dyn Decrypt + Send>,
}

pub(crate) trait Encrypt {
    fn encrypt(&mut self, data: &mut [u8]) -> Result<()>;
}

pub(crate) trait Decrypt {
    fn decrypt(&mut self, data: &mut [u8]) -> Result<()>;
}
