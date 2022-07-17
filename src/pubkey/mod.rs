//! Public key algorithms.
//!
//! The SSH protocol supports several public key algorithms, which are used to authenticate the
//! server and might also be used to authenticate the client.
//!
//! # Supported algorithms
//!
//! - "ssh-ed25519" ([`SSH_ED25519`], uses [`Ed25519Pubkey`] and [`Ed25519Privkey`])
//! - "ecdsa-sha2-nistp256" ([`ECDSA_SHA2_NISTP256`], uses [`EcdsaPubkey<p256::NistP256>`] and
//! [`EcdsaPrivkey<p256::NistP256>`])
//! - "ecdsa-sha2-nistp384" ([`ECDSA_SHA2_NISTP384`], uses [`EcdsaPubkey<p384::NistP384>`] and
//! [`EcdsaPrivkey<p384::NistP384>`])
//! - "ssh-rsa" ([`SSH_RSA_SHA1`], uses [`RsaPubkey`] and [`RsaPrivkey`])
//! - "rsa-sha2-256" ([`RSA_SHA2_256`], uses [`RsaPubkey`] and [`RsaPrivkey`])
//! - "rsa-sha2-512" ([`RSA_SHA2_512`], uses [`RsaPubkey`] and [`RsaPrivkey`])
use bytes::Bytes;
use derivative::Derivative;
use std::fmt;
use crate::codec::{PacketDecode, PacketEncode};
use crate::error::{Result, Error};
pub use self::ecdsa::{ECDSA_SHA2_NISTP256, ECDSA_SHA2_NISTP384, EcdsaPubkey, EcdsaPrivkey};
pub use self::ed25519::{SSH_ED25519, Ed25519Pubkey, Ed25519Privkey};
pub use self::rsa::{SSH_RSA_SHA1, RSA_SHA2_256, RSA_SHA2_512, RsaPubkey, RsaPrivkey};

mod ecdsa;
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Pubkey {
    /// Ed25519 public key.
    Ed25519(Ed25519Pubkey),
    /// RSA public key.
    Rsa(RsaPubkey),
    /// ECDSA public key on NIST P-256 curve.
    EcdsaP256(EcdsaPubkey<p256::NistP256>),
    /// ECDSA public key on NIST P-384 curve.
    EcdsaP384(EcdsaPubkey<p384::NistP384>),
}

impl Pubkey {
    /// Get best public key algorithms that work with this key.
    ///
    /// Most key types work with just a single public key algorithm, but with RSA keys
    /// ([`Pubkey::Rsa`]), there are multiple algorithms that differ in the hash function. This
    /// method returns only highly secure algorithms, but older servers may not support them.
    pub fn algos_secure(&self) -> &'static [&'static PubkeyAlgo] {
        static ED25519: &[&PubkeyAlgo] = &[&SSH_ED25519];
        static RSA: &[&PubkeyAlgo] = &[&RSA_SHA2_256, &RSA_SHA2_512];
        static ECDSA_P256: &[&PubkeyAlgo] = &[&ECDSA_SHA2_NISTP256];
        static ECDSA_P384: &[&PubkeyAlgo] = &[&ECDSA_SHA2_NISTP384];
        match self {
            Pubkey::Ed25519(_) => ED25519,
            Pubkey::Rsa(_) => RSA,
            Pubkey::EcdsaP256(_) => ECDSA_P256,
            Pubkey::EcdsaP384(_) => ECDSA_P384,
        }
    }

    /// Get all public key algorithms that work with this key.
    ///
    /// Most key types work with just a single public key algorithm, but with RSA keys
    /// ([`Pubkey::Rsa`]), there are multiple algorithms that differ in the hash function. This
    /// method returns all supported algorithms for maximum compatibility.
    pub fn algos_compatible_less_secure(&self) -> &'static [&'static PubkeyAlgo] {
        static RSA: &[&PubkeyAlgo] = &[&RSA_SHA2_256, &RSA_SHA2_512, &SSH_RSA_SHA1];
        match self {
            Pubkey::Rsa(_) => RSA,
            _ => self.algos_secure(),
        }
    }

    /// Decode a public key from SSH wire encoding.
    ///
    /// This is the encoding initially defined by RFC 4253. For keys other than RSA, the encoding
    /// is defined in the RFC that introduces the key type.
    pub fn decode(blob: Bytes) -> Result<Self> {
        decode_pubkey(blob)
    }

    /// Encode a public key into SSH encoding.
    ///
    /// This is the encoding initially defined by RFC 4253. For keys other than RSA, the encoding
    /// is defined in the RFC that introduces the key type.
    ///
    /// You can use this method to calculate a digest of the public key.
    pub fn encode(&self) -> Bytes {
        encode_pubkey(self)
    }

    /// Compute a fingerprint of the public key.
    ///
    /// The fingerprint is in the SHA-256 digest of the public key encoded with base64 (not padded
    /// with `=` characters) and prefixed with `SHA256:` (e.g.
    /// `"SHA256:eaBPG/rqx+IPa0Lc9KHypkG3UxjmUwerwq9CZ/xpPWM"`). If you need another format, use
    /// [`encode()`][Self::encode()] to encode the key into bytes and apply a digest of your
    /// choice.
    pub fn fingerprint(&self) -> String {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(self.encode());
        format!("SHA256:{}", base64::encode_config(digest, base64::STANDARD_NO_PAD))
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Pubkey::Ed25519(pubkey) => fmt::Display::fmt(pubkey, f),
            Pubkey::Rsa(pubkey) => fmt::Display::fmt(pubkey, f),
            Pubkey::EcdsaP256(pubkey) => fmt::Display::fmt(pubkey, f),
            Pubkey::EcdsaP384(pubkey) => fmt::Display::fmt(pubkey, f),
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
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "debug_less_secure", derive(Debug))]
pub enum Privkey {
    /// Ed25519 private key.
    Ed25519(Ed25519Privkey),
    /// RSA private key.
    Rsa(RsaPrivkey),
    /// ECDSA private key on NIST P-256 curve.
    EcdsaP256(EcdsaPrivkey<p256::NistP256>),
    /// ECDSA private key on NIST P-384 curve.
    EcdsaP384(EcdsaPrivkey<p384::NistP384>),
}

impl Privkey {
    /// Return the public key associated with this private key.
    pub fn pubkey(&self) -> Pubkey {
        match self {
            Privkey::Ed25519(privkey) => Pubkey::Ed25519(privkey.pubkey()),
            Privkey::Rsa(privkey) => Pubkey::Rsa(privkey.pubkey()),
            Privkey::EcdsaP256(privkey) => Pubkey::EcdsaP256(privkey.pubkey()),
            Privkey::EcdsaP384(privkey) => Pubkey::EcdsaP384(privkey.pubkey()),
        }
    }

    pub(crate) fn decode(blob: &mut PacketDecode) -> Result<Privkey> {
        decode_privkey(blob)
    }
}



fn decode_pubkey(blob: Bytes) -> Result<Pubkey> {
    let mut blob = PacketDecode::new(blob);
    let format = blob.get_string()?;
    match format.as_str() {
        "ssh-ed25519" => ed25519::decode_pubkey(&mut blob).map(Pubkey::Ed25519),
        "ssh-rsa" => rsa::decode_pubkey(&mut blob).map(Pubkey::Rsa),
        "ecdsa-sha2-nistp256" => ecdsa::decode_pubkey::<p256::NistP256>(&mut blob).map(Pubkey::EcdsaP256),
        "ecdsa-sha2-nistp384" => ecdsa::decode_pubkey::<p384::NistP384>(&mut blob).map(Pubkey::EcdsaP384),
        _ => {
            log::debug!("unknown pubkey format {:?}", format);
            Err(Error::Decode("unknown public key format"))
        },
    }
}

fn encode_pubkey(pubkey: &Pubkey) -> Bytes {
    let mut blob = PacketEncode::new();
    match pubkey {
        Pubkey::Ed25519(pubkey) => ed25519::encode_pubkey(&mut blob, pubkey),
        Pubkey::Rsa(pubkey) => rsa::encode_pubkey(&mut blob, pubkey),
        Pubkey::EcdsaP256(pubkey) => ecdsa::encode_pubkey(&mut blob, pubkey),
        Pubkey::EcdsaP384(pubkey) => ecdsa::encode_pubkey(&mut blob, pubkey),
    }
    blob.finish()
}

fn decode_privkey(blob: &mut PacketDecode) -> Result<Privkey> {
    let format = blob.get_string()?;
    match format.as_str() {
        "ssh-ed25519" => ed25519::decode_privkey(blob).map(Privkey::Ed25519),
        "ssh-rsa" => rsa::decode_privkey(blob).map(Privkey::Rsa),
        "ecdsa-sha2-nistp256" => ecdsa::decode_privkey::<p256::NistP256>(blob).map(Privkey::EcdsaP256),
        "ecdsa-sha2-nistp384" => ecdsa::decode_privkey::<p384::NistP384>(blob).map(Privkey::EcdsaP384),
        _ => {
            log::debug!("unknown privkey format {:?}", format);
            Err(Error::Decode("unknown private key format"))
        },
    }
}
