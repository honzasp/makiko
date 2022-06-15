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
//! - "none" ([`NONE`])
use crate::Result;
pub use self::aes::AES128_CTR;
pub use self::none::NONE;
pub(crate) use self::none::Identity;

mod aes;
mod none;

/// Algorithm for encrypting and decrypting messages.
///
/// See the [module documentation][self] for details.
pub struct CipherAlgo {
    /// Name of the algorithm.
    pub name: &'static str,
    pub(crate) block_len: usize,
    pub(crate) key_len: usize,
    pub(crate) iv_len: usize,
    pub(crate) make_encrypt: fn(key: &[u8], iv: &[u8]) -> Box<dyn Encrypt + Send>,
    pub(crate) make_decrypt: fn(key: &[u8], iv: &[u8]) -> Box<dyn Decrypt + Send>,
}

pub(crate) trait Encrypt {
    fn encrypt(&mut self, data: &mut [u8]) -> Result<()>;
}

pub(crate) trait Decrypt {
    fn decrypt(&mut self, data: &mut [u8]) -> Result<()>;
}
