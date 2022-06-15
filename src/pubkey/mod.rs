//! Public key algorithms.
//!
//! The SSH protocol supports several public key algorithms, which are used to authenticate the
//! server and might also be used to authenticate the client.
//!
//! # Supported algorithms
//!
//! - "ssh-ed25519" ([`SSH_ED25519`], [`Ed25519Pubkey`])
//! - "ssh-rsa" ([`SSH_RSA`], [`RsaPubkey`])
use bytes::Bytes;
use std::fmt;
use crate::Result;
pub use self::ed25519::{SSH_ED25519, Ed25519Pubkey};
pub use self::rsa::{SSH_RSA, RsaPubkey};

mod ed25519;
mod rsa;

/// Algorithm for public key cryptography.
///
/// See the [module documentation][self] for details.
pub struct PubkeyAlgo {
    /// Name of the algorithm.
    pub name: &'static str,
    pub(crate) decode_pubkey: fn(pubkey: Bytes) -> Result<Pubkey>,
}

/// Public key in one of supported formats.
///
/// This enum is marked as `#[non_exhaustive]`, so we might add new variants without breaking
/// backwards compatibility.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Pubkey {
    /// Ed25519 public key.
    Ed25519(Ed25519Pubkey),
    /// RSA public key.
    Rsa(RsaPubkey),
}

impl Pubkey {
    pub(crate) fn verify(&self, message: &[u8], signature: Bytes) -> Result<SignatureVerified> {
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
pub(crate) struct SignatureVerified(());

impl SignatureVerified {
    fn assertion() -> Self { Self(()) }
}
