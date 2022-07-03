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
//! - "chacha20-poly1305" ([`CHACHA20_POLY1305`])
//! - "aes128-gcm@openssh.com" ([`AES128_GCM`])
//! - "aes256-gcm@openssh.com" ([`AES256_GCM`])
//! - "aes128-ctr" ([`AES128_CTR`])
//! - "aes192-ctr" ([`AES192_CTR`])
//! - "aes256-ctr" ([`AES256_CTR`])
//! - "aes128-cbc" ([`AES128_CBC`])
//! - "aes192-cbc" ([`AES192_CBC`])
//! - "aes256-cbc" ([`AES256_CBC`])
//! - "none" ([`NONE`])
use crate::Result;
use derivative::Derivative;
pub use self::aes_gcm::{AES128_GCM, AES256_GCM};
pub use self::block::{AES128_CBC, AES192_CBC, AES256_CBC};
pub use self::chacha_poly::CHACHA20_POLY1305;
pub use self::none::NONE;
pub use self::stream::{AES128_CTR, AES192_CTR, AES256_CTR};
pub(crate) use self::none::Identity;
use crate::mac::{Mac, MacVerified};

mod aes_gcm;
mod block;
mod chacha_poly;
mod none;
mod stream;

/// Algorithm for encrypting and decrypting messages.
///
/// See the [module documentation][self] for details.
#[derive(Debug)]
pub struct CipherAlgo {
    /// Name of the algorithm.
    pub name: &'static str,
    pub(crate) block_len: usize,
    pub(crate) key_len: usize,
    pub(crate) iv_len: usize,
    pub(crate) variant: CipherAlgoVariant,
}

#[derive(Debug)]
pub(crate) enum CipherAlgoVariant {
    Standard(StandardCipherAlgo),
    Aead(AeadCipherAlgo),
}

#[derive(Derivative)]
#[derivative(Debug)]
pub(crate) struct StandardCipherAlgo {
    #[derivative(Debug = "ignore")]
    pub(crate) make_encrypt: fn(key: &[u8], iv: &[u8]) -> Box<dyn Encrypt + Send>,
    #[derivative(Debug = "ignore")]
    pub(crate) make_decrypt: fn(key: &[u8], iv: &[u8]) -> Box<dyn Decrypt + Send>,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub(crate) struct AeadCipherAlgo {
    pub(crate) tag_len: usize,
    #[derivative(Debug = "ignore")]
    pub(crate) make_encrypt: fn(key: &[u8], iv: &[u8]) -> Box<dyn AeadEncrypt + Send>,
    #[derivative(Debug = "ignore")]
    pub(crate) make_decrypt: fn(key: &[u8], iv: &[u8]) -> Box<dyn AeadDecrypt + Send>,
}



pub(crate) enum PacketEncrypt {
    EncryptAndMac(Box<dyn Encrypt + Send>, Box<dyn Mac + Send>),
    EncryptThenMac(Box<dyn Encrypt + Send>, Box<dyn Mac + Send>),
    Aead(Box<dyn AeadEncrypt + Send>),
}

pub(crate) enum PacketDecrypt {
    EncryptAndMac(Box<dyn Decrypt + Send>, Box<dyn Mac + Send>),
    EncryptThenMac(Box<dyn Decrypt + Send>, Box<dyn Mac + Send>),
    Aead(Box<dyn AeadDecrypt + Send>),
}

pub(crate) trait Encrypt {
    fn encrypt(&mut self, data: &mut [u8]);
}

pub(crate) trait Decrypt {
    fn decrypt(&mut self, data: &mut [u8]);
}


pub(crate) trait AeadEncrypt {
    fn encrypt_and_sign(&mut self, packet_seq: u64, packet: &mut [u8], tag: &mut [u8]);
}

pub(crate) trait AeadDecrypt {
    fn decrypt_packet_len(&mut self, packet_seq: u64, ciphertext: &[u8], plaintext: &mut [u8]);
    fn decrypt_and_verify(&mut self, packet_seq: u64, packet: &mut [u8], tag: &[u8]) -> Result<MacVerified>;
}



impl CipherAlgoVariant {
    pub fn is_aead(&self) -> bool {
        matches!(self, CipherAlgoVariant::Aead(_))
    }
}
