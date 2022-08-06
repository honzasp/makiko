//! Encoding and decoding keys.
use bytes::Bytes;
use derivative::Derivative;
use crate::cipher::{self,  CipherAlgoVariant};
use crate::codec::PacketDecode;
use crate::error::{Result, Error};
use crate::pubkey::{Pubkey, Privkey};

/// Keypair (public and private key) in OpenSSH format.
///
/// Note that we do not check that the public key and private key form a valid keypair.
#[derive(Clone, PartialEq, Eq, Derivative)]
#[derivative(Debug)]
pub struct OpensshKeypair {
    /// Public key, always unencrypted.
    pub pubkey: Pubkey,
    /// Private key, may be encrypted in the key file.
    #[cfg_attr(not(feature = "debug_less_secure"), derivative(Debug = "ignore"))]
    pub privkey: Privkey,
    /// Comment, encrypted if and only if the private key is encrypted.
    pub comment: String,
}

/// Keypair in OpenSSH format, decoded without a password.
///
/// We can always decode the public key, which is stored without encryption. The private key will
/// be decoded only if the file was not encrypted.
#[derive(Clone, PartialEq, Eq, Derivative)]
#[derivative(Debug)]
pub struct OpensshKeypairNopass {
    /// Public key, available even without password.
    pub pubkey: Pubkey,
    /// Private key, available only if the key file was not encrypted.
    #[cfg_attr(not(feature = "debug_less_secure"), derivative(Debug = "ignore"))]
    pub privkey: Option<Privkey>,
    /// Comment, available only if the key file was not encrypted.
    pub comment: Option<String>,
}

static PEM_TAG: &str = "OPENSSH PRIVATE KEY";

/// Decode a private key from OpenSSH PEM format.
///
/// Files in this format start with `-----BEGIN OPENSSH PRIVATE KEY-----`, followed by
/// base64-encoded binary data (see [`decode_openssh_binary_keypair()`]).
///
/// If the key is encrypted, we will try to decrypt it using the provided `passphrase`. If the
/// passphrase is not correct, this function returns [`Error::BadKeyPassphrase`]. You can pass an
/// empty passphrase if the key is not encrypted.
///
/// If the key might be encrypted and you need to prompt the user for a password, consider using
/// [`decode_openssh_pem_keypair_nopass()`] to detect whether the password is necessary.
pub fn decode_openssh_pem_keypair(pem_data: &[u8], passphrase: &[u8]) -> Result<OpensshKeypair> {
    let data = super::decode_pem(pem_data, PEM_TAG)?;
    decode_openssh_binary_keypair(data.into(), passphrase)
}

/// Decode a private key from OpenSSH PEM format without decryption.
///
/// Files in this format start with `-----BEGIN OPENSSH PRIVATE KEY-----`, followed by
/// base64-encoded binary data (see [`decode_openssh_binary_keypair()`]).
///
/// If the key is encrypted, the resulting [`OpensshKeypairNopass`] will contain only the public
/// key, which is stored without encryption. The private key is decoded only if it is not
/// encrypted.
///
/// For example, you can use this method together with
/// [`Client::check_pubkey()`][crate::Client::check_pubkey()] to test whether the public key can be
/// used for authentication before prompting the user for password.
pub fn decode_openssh_pem_keypair_nopass(pem_data: &[u8]) -> Result<OpensshKeypairNopass> {
    let data = super::decode_pem(pem_data, PEM_TAG)?;
    decode_openssh_binary_keypair_nopass(data.into())
}

/// Decode a private key from OpenSSH binary format.
///
/// The binary format is described in file `PROTOCOL.key` in the OpenSSH sources, it starts with
/// bytes `"openssh-key-v1\0". In real world, key files are usually in textual PEM format (see
/// [`decode_openssh_pem_keypair()`].
pub fn decode_openssh_binary_keypair(data: Bytes, passphrase: &[u8]) -> Result<OpensshKeypair> {
    let raw = decode_raw(data)?;
    let plaintext = decrypt(&raw, passphrase)?;
    let (privkey, comment) = decode_plaintext(plaintext)?;
    Ok(OpensshKeypair { pubkey: raw.pubkey, privkey, comment })
}

/// Decode a private key from OpenSSH binary format without decryption.
///
/// The binary format is described in file `PROTOCOL.key` in the OpenSSH sources, it starts with
/// bytes `"openssh-key-v1\0". In real world, key files are usually in textual PEM format (see
/// [`decode_openssh_pem_keypair_nopass()`].
///
/// If the key is encrypted, the resulting [`OpensshKeypairNopass`] will contain only the public
/// key, which is stored without encryption. The private key is decoded only if it is not
/// encrypted.
///
/// For example, you can use this method together with
/// [`Client::check_pubkey()`][crate::Client::check_pubkey()] to test whether the public key can be
/// used for authentication before prompting the user for password.
pub fn decode_openssh_binary_keypair_nopass(data: Bytes) -> Result<OpensshKeypairNopass> {
    let raw = decode_raw(data)?;
    let (privkey, comment) =
        if let Ok(plaintext) = decrypt(&raw, &[]) {
            let (privkey, comment) = decode_plaintext(plaintext)?;
            (Some(privkey), Some(comment))
        } else {
            (None, None)
        };
    Ok(OpensshKeypairNopass { pubkey: raw.pubkey, privkey, comment })
}

#[derive(Debug)]
struct RawKeypair {
    cipher_name: String,
    kdf_name: String,
    kdf_options: Bytes,
    pubkey: Pubkey,
    ciphertext: Bytes,
}

fn decode_raw(data: Bytes) -> Result<RawKeypair> {
    let mut data = PacketDecode::new(data);

    let auth_magic = b"openssh-key-v1\0";
    let magic = data.get_raw(auth_magic.len())?;
    if magic.as_ref() != auth_magic.as_ref() {
        return Err(Error::Decode("this does not seem to be an OpenSSH keypair (bad magic bytes)"))
    }

    let cipher_name = data.get_string()?;
    let kdf_name = data.get_string()?;
    let kdf_options = data.get_bytes()?;

    let key_count = data.get_u32()?;
    if key_count != 1 {
        return Err(Error::Decode("this OpenSSH file does not contain exactly one keypair"))
    }

    let pubkey_blob = data.get_bytes()?;
    let pubkey = Pubkey::decode(pubkey_blob)?;

    let ciphertext = data.get_bytes()?;
    Ok(RawKeypair { cipher_name, kdf_name, kdf_options, pubkey, ciphertext })
}

fn decode_plaintext(plaintext: Vec<u8>) -> Result<(Privkey, String)> {
    let mut plaintext = PacketDecode::new(plaintext.into());
    let check_1 = plaintext.get_u32()?;
    let check_2 = plaintext.get_u32()?;
    if check_1 != check_2 {
        return Err(Error::BadKeyPassphrase)
    }
    let privkey = Privkey::decode(&mut plaintext)?;
    let comment = plaintext.get_string()?;

    let padding = plaintext.remaining();
    for (idx, &padding_byte) in padding.iter().enumerate() {
        if padding_byte != (idx + 1) as u8 {
            return Err(Error::Decode("bad padding of OpenSSH keypair"))
        }
    }

    Ok((privkey, comment))
}

fn decrypt(raw: &RawKeypair, passphrase: &[u8]) -> Result<Vec<u8>> {
    let cipher_algo = match cipher::algo_by_name(&raw.cipher_name) {
        Some(algo) => algo,
        None => return Err(Error::Decode("OpenSSH keypair encrypted with an unknown cipher")),
    };

    let mut key_material = vec![0; cipher_algo.key_len + cipher_algo.iv_len];
    if !key_material.is_empty() {
        derive_keys(&raw.kdf_name, &raw.kdf_options, passphrase, &mut key_material)?;
    }
    let key = &key_material[..cipher_algo.key_len];
    let iv = &key_material[cipher_algo.key_len..];

    if raw.ciphertext.len() % cipher_algo.block_len != 0 {
        return Err(Error::Decode("OpenSSH keypair ciphertext is not aligned to cipher block"))
    }

    match &cipher_algo.variant {
        CipherAlgoVariant::Standard(algo) => {
            let mut decrypt = (algo.make_decrypt)(key, iv);
            let mut data = raw.ciphertext.to_vec();
            decrypt.decrypt(&mut data);
            Ok(data)
        },
        CipherAlgoVariant::Aead(_) => {
            // if we ever want to implement this:
            // - for aes-gcm, the associated data is empty (for SSH packets, the associated data is
            // the packet length)
            // - the tag is stored _after_ the ciphertext
            Err(Error::Decode("OpenSSH keypair encoded with an AEAD cipher is not supported"))
        },
    }
}

fn derive_keys(kdf_name: &str, kdf_options: &[u8], passphrase: &[u8], output: &mut [u8]) -> Result<()> {
    if kdf_name != "bcrypt" {
        return Err(Error::Decode("OpenSSH keypair encrypted with an unknown key derivation function"))
    }

    if passphrase.is_empty() {
        return Err(Error::BadKeyPassphrase)
    }

    let mut kdf_options = PacketDecode::new(Bytes::copy_from_slice(kdf_options));
    let salt = kdf_options.get_bytes()?;
    let rounds = kdf_options.get_u32()?;
    bcrypt_pbkdf::bcrypt_pbkdf(passphrase, &salt, rounds, output)
        .map_err(|_| Error::Crypto("invalid parameters for bcrypt_pbkdf key derivation function"))
}
