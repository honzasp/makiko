use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use crate::error::{Result, Error};
use crate::pubkey::{RsaPrivkey, RsaPubkey};

/// Decode a private RSA key from PKCS#1 PEM format without decryption.
///
/// Files in this format start with `-----BEGIN RSA PRIVATE KEY-----`, followed by base64-encoded
/// DER data (see [`decode_pkcs1_der_privkey()`]).
///
/// Encrypted PKCS#1 keys have a PEM header such as `Proc-Type: 4,ENCRYPTED` after the `-----BEGIN
/// RSA PRIVATE KEY-----` header. At this moment, we do not support such keys.
pub fn decode_pkcs1_pem_privkey_nopass(pem_data: &str) -> Result<RsaPrivkey> {
    let privkey = rsa::RsaPrivateKey::from_pkcs1_pem(pem_data).map_err(Error::Pkcs1)?;
    Ok(RsaPrivkey { privkey })
}

/// Decode a private RSA key from PKCS#1 binary DER format.
///
/// You will rarely encounter the binary DER format in the wild. If you key starts with `-----BEGIN
/// RSA PRIVATE KEY-----`, the DER data is wrapped in PEM format (see
/// [`decode_pkcs1_pem_privkey_nopass()`]).
pub fn decode_pkcs1_der_privkey(der_data: &[u8]) -> Result<RsaPrivkey> {
    let privkey = rsa::RsaPrivateKey::from_pkcs1_der(der_data).map_err(Error::Pkcs1)?;
    Ok(RsaPrivkey { privkey })
}

/// Decode a public RSA key from PKCS#1 PEM format.
///
/// Files in this format start with `-----BEGIN RSA PUBLIC KEY-----`, followed by base64-encoded
/// DER data (see [`decode_pkcs1_der_pubkey()`]).
pub fn decode_pkcs1_pem_pubkey(pem_data: &str) -> Result<RsaPubkey> {
    let pubkey = rsa::RsaPublicKey::from_pkcs1_pem(pem_data).map_err(Error::Pkcs1)?;
    Ok(RsaPubkey { pubkey })
}

/// Decode a public RSA key from PKCS#1 binary DER format.
///
/// You will rarely encounter the binary DER format in the wild. If you key starts with `-----BEGIN
/// RSA PUBLIC KEY-----`, the DER data is wrapped in PEM format (see
/// [`decode_pkcs1_pem_pubkey()`]).
pub fn decode_pkcs1_der_pubkey(der_data: &[u8]) -> Result<RsaPubkey> {
    let pubkey = rsa::RsaPublicKey::from_pkcs1_der(der_data).map_err(Error::Pkcs1)?;
    Ok(RsaPubkey { pubkey })
}
