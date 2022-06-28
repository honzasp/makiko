//! Public key algorithms.
//!
//! The SSH protocol supports several public key algorithms, which are used to authenticate the
//! server and might also be used to authenticate the client.
//!
//! # Supported algorithms
//!
//! - "ssh-ed25519" ([`SSH_ED25519`], uses [`Ed25519Pubkey`] and [`Ed25519Privkey`])
//! - "ssh-rsa" ([`SSH_RSA_SHA1`], uses [`RsaPubkey`] and [`RsaPrivkey`])
//! - "rsa-sha2-256" ([`RSA_SHA2_256`], uses [`RsaPubkey`] and [`RsaPrivkey`])
//! - "rsa-sha2-512" ([`RSA_SHA2_512`], uses [`RsaPubkey`] and [`RsaPrivkey`])
use bytes::Bytes;
use derivative::Derivative;
use std::fmt;
use crate::Result;
pub use self::ed25519::{SSH_ED25519, Ed25519Pubkey, Ed25519Privkey};
pub use self::rsa::{SSH_RSA_SHA1, RSA_SHA2_256, RSA_SHA2_512, RsaPubkey, RsaPrivkey};

mod codec;
mod ed25519;
mod rsa;

/// Algorithm for public key cryptography.
///
/// See the [module documentation][self] for details.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct PubkeyAlgo {
    /// Name of the algorithm.
    pub name: &'static str,
    #[derivative(Debug = "ignore")]
    pub(crate) verify: fn(pubkey: &Pubkey, message: &[u8], signature: Bytes) -> Result<SignatureVerified>,
    #[derivative(Debug = "ignore")]
    pub(crate) sign: fn(privkey: &Privkey, message: &[u8]) -> Result<Bytes>,
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
    pub(crate) fn decode(blob: Bytes) -> Result<Self> {
        codec::decode_pubkey(blob)
    }

    pub(crate) fn encode(&self) -> Bytes {
        codec::encode_pubkey(self)
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



/// Private key (keypair) in one of supported formats.
///
/// This enum is marked as `#[non_exhaustive]`, so we might add new variants without breaking
/// backwards compatibility.
#[derive(Clone)]
#[non_exhaustive]
pub enum Privkey {
    /// Ed25519 private key.
    Ed25519(Ed25519Privkey),
    /// RSA private key.
    Rsa(RsaPrivkey),
}

impl Privkey {
    /// Return the public key associated with this private key.
    pub fn pubkey(&self) -> Pubkey {
        match self {
            Privkey::Ed25519(privkey) => Pubkey::Ed25519(privkey.pubkey()),
            Privkey::Rsa(privkey) => Pubkey::Rsa(privkey.pubkey()),
        }
    }
}
