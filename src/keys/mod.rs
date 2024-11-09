//! Encoding and decoding of keys.

use crate::error::{Result, Error};
use crate::pubkey::{Privkey, Pubkey};
pub use self::openssh::{
    OpensshKeypair, OpensshKeypairNopass,
    decode_openssh_pem_keypair, decode_openssh_binary_keypair,
    decode_openssh_pem_keypair_nopass, decode_openssh_binary_keypair_nopass,
};
pub use self::pkcs1::{
    decode_pkcs1_pem_privkey_nopass, decode_pkcs1_der_privkey,
    decode_pkcs1_pem_pubkey, decode_pkcs1_der_pubkey,
};
pub use self::pkcs8::{
    decode_pkcs8_pem_privkey, decode_pkcs8_der_privkey, decode_pkcs8_encrypted_der_privkey,
    decode_pkcs8_pem_pubkey, decode_pkcs8_der_pubkey,
};

mod openssh;
mod pkcs1;
mod pkcs8;

fn decode_pem(pem_data: &[u8], expected_tag: &'static str) -> Result<Vec<u8>> {
    let pem = pem::parse(pem_data).map_err(Error::Pem)?;
    if pem.tag() != expected_tag {
        return Err(Error::BadPemTag(pem.tag().into(), expected_tag.into()))
    }
    Ok(pem.into_contents())
}

/// Decode a private key from any supported PEM format.
///
/// This function attempts to auto-detect the private key format from the PEM header. We currently
/// support these formats:
///
/// - OpenSSH (`OPENSSH PRIVATE KEY`), see [`decode_openssh_pem_keypair()`].
/// - PKCS#1 (`RSA PRIVATE KEY`), see [`decode_pkcs1_pem_privkey_nopass()`] (encrypted keys are not
/// supported).
/// - PKCS#8 (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`), see [`decode_pkcs8_pem_privkey()`].
///
/// If the key is encrypted, we will try to decrypt it using the provided `passphrase`. If the
/// passphrase is not correct, this function returns [`Error::BadKeyPassphrase`]. You can pass an
/// empty passphrase if the key is not encrypted.
pub fn decode_pem_privkey(pem_data: &[u8], passphrase: &[u8]) -> Result<Privkey> {
    let pem = pem::parse(pem_data).map_err(Error::Pem)?;
    match pem.tag() {
        "OPENSSH PRIVATE KEY" => decode_openssh_binary_keypair(pem.into_contents().into(), passphrase)
            .map(|keypair| keypair.privkey),
        "RSA PRIVATE KEY" => decode_pkcs1_der_privkey(pem.contents()).map(Privkey::Rsa),
        "PRIVATE KEY" => decode_pkcs8_der_privkey(pem.contents()),
        "ENCRYPTED PRIVATE KEY" => decode_pkcs8_encrypted_der_privkey(pem.contents(), passphrase),
        _ => Err(Error::UnknownPemTag(pem.tag().into())),
    }
}

/// Private key decoded without a password.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "debug-less-secure", derive(Debug))]
pub enum DecodedPrivkeyNopass {
    /// Private key that was not encrypted, so we decoded it without a password.
    Privkey(Privkey),
    /// Private key that was encrypted, but the format allows us to read the public key without
    /// decryption.
    Pubkey(Pubkey),
    /// Private key that was encrypted, so we could not decode anything.
    Encrypted,
}

impl DecodedPrivkeyNopass {
    /// Returns the private key, if available.
    pub fn privkey(&self) -> Option<&Privkey> {
        match self {
            Self::Privkey(privkey) => Some(privkey),
            Self::Pubkey(_) | Self::Encrypted => None,
        }
    }

    /// Returns the public key, if available.
    pub fn pubkey(&self) -> Option<Pubkey> {
        match self {
            Self::Privkey(privkey) => Some(privkey.pubkey()),
            Self::Pubkey(pubkey) => Some(pubkey.clone()),
            Self::Encrypted => None,
        }
    }
}

/// Decode a private key from any supported PEM format without a password.
///
/// This function attempts to auto-detect the private key format from the PEM header. If the format
/// is recognized, then one of three options occurs:
///
/// - The key is not encrypted, so we return a [`DecodedPrivkeyNopass::Privkey`] that contains the
/// key.
/// - The private key is encrypted, but the public key is stored unencrypted, so we return a
/// [`DecodedPrivkeyNopass::Pubkey`]. This is only possible with private keys in the OpenSSH
/// format.
/// - The key is encrypted and the public key cannot be decoded, so we return a
/// [`DecodedPrivkeyNopass::Encrypted`].
pub fn decode_pem_privkey_nopass(pem_data: &[u8]) -> Result<DecodedPrivkeyNopass> {
    let pem = pem::parse(pem_data).map_err(Error::Pem)?;
    match pem.tag() {
        "OPENSSH PRIVATE KEY" =>
            decode_openssh_binary_keypair_nopass(pem.into_contents().into()).map(|keypair| {
                match keypair.privkey {
                    Some(privkey) => DecodedPrivkeyNopass::Privkey(privkey),
                    None => DecodedPrivkeyNopass::Pubkey(keypair.pubkey),
                }
            }),
        "RSA PRIVATE KEY" => decode_pkcs1_der_privkey(pem.contents())
            .map(|privkey| DecodedPrivkeyNopass::Privkey(Privkey::Rsa(privkey))),
        "PRIVATE KEY" => decode_pkcs8_der_privkey(pem.contents())
            .map(DecodedPrivkeyNopass::Privkey),
        "ENCRYPTED PRIVATE KEY" => Ok(DecodedPrivkeyNopass::Encrypted),
        _ => Err(Error::UnknownPemTag(pem.tag().into())),
    }
}

/// Decode a public key from any supported PEM format.
///
/// This function attempts to auto-detect the public key format from the PEM header. We currently
/// support these formats:
///
/// - PKCS#1 (`RSA PUBLIC KEY`), see [`decode_pkcs1_pem_pubkey()`].
/// - PKCS#8 (`PUBLIC KEY`), see [`decode_pkcs8_pem_pubkey()`].
pub fn decode_pem_pubkey(pem_data: &[u8]) -> Result<Pubkey> {
    let pem = pem::parse(pem_data).map_err(Error::Pem)?;
    match pem.tag() {
        "RSA PUBLIC KEY" => decode_pkcs1_der_pubkey(pem.contents()).map(Pubkey::Rsa),
        "PUBLIC KEY" => decode_pkcs8_der_pubkey(pem.contents()),
        _ => Err(Error::UnknownPemTag(pem.tag().into())),
    }
}
