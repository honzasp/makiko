use ecdsa::elliptic_curve;
use pkcs8::AssociatedOid as _;
use crate::error::{Result, Error};
use crate::pubkey::{Privkey, Pubkey};

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
    if pem.tag() == "PRIVATE KEY" {
        decode_pkcs8_der_privkey(pem.contents())
    } else if pem.tag() == "ENCRYPTED PRIVATE KEY" {
        decode_pkcs8_encrypted_der_privkey(pem.contents(), passphrase)
    } else {
        Err(Error::BadPemTag(pem.tag().into(), "PRIVATE KEY".into()))
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
        let privkey = rsa::RsaPrivateKey::try_from(info).map_err(Error::Pkcs8)?;
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
        let signing = ed25519_dalek::SigningKey::try_from(info).map_err(Error::Pkcs8)?;
        Ok(Privkey::Ed25519(signing.into()))
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

/// Decode a public key from PKCS#8 PEM format.
///
/// Files in this format start with `-----BEGIN PUBLIC KEY-----`.
pub fn decode_pkcs8_pem_pubkey(pem_data: &[u8]) -> Result<Pubkey> {
    let data = super::decode_pem(pem_data, "PUBLIC KEY")?;
    decode_pkcs8_der_pubkey(&data)
}

/// Decode a public key from PKCS#8 DER (binary) format.
pub fn decode_pkcs8_der_pubkey(der_data: &[u8]) -> Result<Pubkey> {
    let info = pkcs8::SubjectPublicKeyInfo::try_from(der_data).map_err(Error::Pkcs8Spki)?;
    let algo_oid = info.algorithm.oid;
    if algo_oid == RSA_OID {
        let pubkey = rsa::RsaPublicKey::try_from(info).map_err(Error::Pkcs8Spki)?;
        Ok(Pubkey::Rsa(pubkey.into()))
    } else if algo_oid == EC_OID {
        let curve_oid = info.algorithm.parameters_oid().map_err(Error::Pkcs8Spki)?;
        if curve_oid == p256::NistP256::OID {
            let pubkey = elliptic_curve::PublicKey::<p256::NistP256>::try_from(info)
                .map_err(Error::Pkcs8Spki)?;
            Ok(Pubkey::EcdsaP256(pubkey.into()))
        } else if curve_oid == p384::NistP384::OID {
            let pubkey = elliptic_curve::PublicKey::<p384::NistP384>::try_from(info)
                .map_err(Error::Pkcs8Spki)?;
            Ok(Pubkey::EcdsaP384(pubkey.into()))
        } else {
            Err(Error::Pkcs8BadCurveOid(curve_oid.to_string()))
        }
    } else if algo_oid == ED25519_OID {
        let verifying = ed25519_dalek::VerifyingKey::try_from(info).map_err(Error::Pkcs8Spki)?;
        Ok(Pubkey::Ed25519(verifying.into()))
    } else {
        Err(Error::Pkcs8BadAlgorithmOid(algo_oid.to_string()))
    }
}
