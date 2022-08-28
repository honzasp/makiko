use ecdsa::elliptic_curve;
use ed25519_dalek::ed25519;
use pkcs8::AssociatedOid as _;
use crate::error::{Result, Error};
use crate::pubkey::Privkey;

/// Decode a private key from PKCS#8 PEM format.
///
/// Files in this format start with `-----BEGIN PRIVATE KEY-----` (unencrypted) or `-----BEGIN
/// ENCRYPTED PRIVATE KEY-----` (encrypted).
///
/// If the key is encrypted, we will try to decrypt it using the provided `passphrase`. If the
/// passphrase is not correct, this function returns [`Error::BadKeyPassphrase`]. You can pass an
/// empty passphrase if the key is not encrypted.
pub fn decode_pkcs8_pem_privkey(pem_data: &[u8], passphrase: &[u8]) -> Result<Privkey> {
    let pem = pem::parse(pem_data).map_err(Error::Pem)?;
    if pem.tag == "PRIVATE KEY" {
        decode_pkcs8_der_privkey(&pem.contents)
    } else if pem.tag == "ENCRYPTED PRIVATE KEY" {
        decode_pkcs8_encrypted_der_privkey(&pem.contents, passphrase)
    } else {
        Err(Error::BadPemTag(pem.tag, "PRIVATE KEY".into()))
    }
}

const RSA_OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const ED25519_OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.3.101.112");

/// Decode an unencrypted private key from PKCS#8 DER (binary) format.
pub fn decode_pkcs8_der_privkey(der_data: &[u8]) -> Result<Privkey> {
    let info = pkcs8::PrivateKeyInfo::try_from(der_data).map_err(Error::Pkcs8)?;
    let algo_oid = info.algorithm.oid;
    if algo_oid == RSA_OID {
        // unfortunately, `rsa` uses an older version of `pkcs8`, so we must re-parse the DER
        let info = rsa::pkcs8::PrivateKeyInfo::try_from(der_data).map_err(Error::Pkcs8Rsa)?;
        let privkey = rsa::RsaPrivateKey::try_from(info).map_err(Error::Pkcs8Rsa)?;
        Ok(Privkey::Rsa(privkey.into()))
    } else if algo_oid == EC_OID {
        let curve_oid = info.algorithm.parameters_oid().map_err(Error::Pkcs8Spki)?;
        if curve_oid == p256::NistP256::OID {
            let privkey = elliptic_curve::SecretKey::<p256::NistP256>::try_from(info).map_err(Error::Pkcs8)?;
            Ok(Privkey::EcdsaP256(privkey.into()))
        } else if curve_oid == p384::NistP384::OID {
            let privkey = elliptic_curve::SecretKey::<p384::NistP384>::try_from(info).map_err(Error::Pkcs8)?;
            Ok(Privkey::EcdsaP384(privkey.into()))
        } else {
            Err(Error::Pkcs8BadCurveOid(curve_oid.to_string()))
        }
    } else if algo_oid == ED25519_OID {
        let keypair_bytes = ed25519::pkcs8::KeypairBytes::try_from(info).map_err(Error::Pkcs8)?;
        let secret = ed25519_dalek::SecretKey::from_bytes(&keypair_bytes.secret_key)
            .map_err(Error::Pkcs8Ed25519)?;
        let public = match keypair_bytes.public_key {
            Some(bytes) => ed25519_dalek::PublicKey::from_bytes(&bytes).map_err(Error::Pkcs8Ed25519)?,
            None => ed25519_dalek::PublicKey::from(&secret),
        };
        Ok(Privkey::Ed25519(ed25519_dalek::Keypair { secret, public }.into()))
    } else {
        Err(Error::Pkcs8BadAlgorithmOid(algo_oid.to_string()))
    }
}

/// Decode an encrypted private key from PKCS#8 DER (binary) format.
pub fn decode_pkcs8_encrypted_der_privkey(der_data: &[u8], passphrase: &[u8]) -> Result<Privkey> {
    let info = pkcs8::EncryptedPrivateKeyInfo::try_from(der_data).map_err(Error::Pkcs8)?;
    let document = info.decrypt(passphrase).map_err(Error::Pkcs8)?;
    decode_pkcs8_der_privkey(document.as_bytes())
}
