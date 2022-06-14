use bytes::Bytes;
use std::fmt;
use crate::Result;
pub use self::ed25519::{SSH_ED25519, Ed25519Pubkey};
pub use self::rsa::{SSH_RSA, RsaPubkey};

mod ed25519;
mod rsa;

pub struct PubkeyAlgo {
    pub name: &'static str,
    pub decode_pubkey: fn(pubkey: Bytes) -> Result<Pubkey>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Pubkey {
    Ed25519(Ed25519Pubkey),
    Rsa(RsaPubkey),
}

impl Pubkey {
    pub fn verify(&self, message: &[u8], signature: Bytes) -> Result<SignatureVerified> {
        match self {
            Pubkey::Ed25519(pubkey) => pubkey.verify(message, signature),
            Pubkey::Rsa(pubkey) => pubkey.verify(message, signature),
        }
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Pubkey::Ed25519(pubkey) => fmt::Display::fmt(pubkey, f),
            Pubkey::Rsa(pubkey) => fmt::Display::fmt(pubkey, f),
        }
    }
}

#[derive(Debug)]
pub struct SignatureVerified(());

impl SignatureVerified {
    fn assertion() -> Self { Self(()) }
}
