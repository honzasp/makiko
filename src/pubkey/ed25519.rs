use bytes::Bytes;
use crate::codec::{PacketDecode, PacketEncode};
use crate::error::{Result, Error};
use std::fmt;
use super::{PubkeyAlgo, Pubkey, Privkey, SignatureVerified};

/// "ssh-ed25519" public key algorithm from RFC 8709.
///
/// This algorithm is compatible with [`Ed25519Pubkey`] and [`Ed25519Privkey`].
pub static SSH_ED25519: PubkeyAlgo = PubkeyAlgo {
    name: "ssh-ed25519",
    verify,
    sign,
};

/// Ed25519 public key from RFC 8032.
///
/// This key is compatible with [`SSH_ED25519`]. You can convert it to and from
/// [`ed25519_dalek::VerifyingKey`] using `from()`/`into()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519Pubkey {
    pub(crate) verifying: ed25519_dalek::VerifyingKey,
}

/// Ed25519 keypair from RFC 8032.
///
/// This key is compatible with [`SSH_ED25519`]. You can convert it to and from
/// [`ed25519_dalek::SigningKey`] using `from()`/`into()`.
#[cfg_attr(feature = "debug_less_secure", derive(Debug))]
pub struct Ed25519Privkey {
    pub(crate) signing: ed25519_dalek::SigningKey,
}

impl Ed25519Privkey {
    /// Get the public associated with this private key.
    pub fn pubkey(&self) -> Ed25519Pubkey {
        Ed25519Pubkey { verifying: self.signing.verifying_key() }
    }
}

fn verify(pubkey: &Pubkey, message: &[u8], signature: Bytes) -> Result<SignatureVerified> {
    let Pubkey::Ed25519(pubkey) = pubkey else { return Err(Error::PubkeyFormat) };

    let mut signature = PacketDecode::new(signature);
    if signature.get_string()? != "ssh-ed25519" {
        return Err(Error::Decode("expected signature format 'ssh-ed25519'"))
    }

    let signature_data = signature.get_byte_array::<64>()?;
    let ed_signature = ed25519_dalek::Signature::from(signature_data);

    match pubkey.verifying.verify_strict(message, &ed_signature) {
        Ok(_) => Ok(SignatureVerified::assertion()),
        Err(_) => Err(Error::Signature),
    }
}

fn sign(privkey: &Privkey, message: &[u8]) -> Result<Bytes> {
    let Privkey::Ed25519(privkey) = privkey else { return Err(Error::PrivkeyFormat) };

    use ed25519_dalek::Signer as _;
    let ed_signature = privkey.signing.try_sign(message)
        .map_err(|_| Error::Crypto("could not sign with ed25519"))?;

    let mut signature = PacketEncode::new();
    signature.put_str("ssh-ed25519");
    signature.put_bytes(&ed_signature.to_bytes());
    Ok(signature.finish())
}

pub(super) fn encode_pubkey(blob: &mut PacketEncode, pubkey: &Ed25519Pubkey) {
    blob.put_str("ssh-ed25519");
    blob.put_bytes(pubkey.verifying.as_bytes());
}

pub(super) fn decode_pubkey(blob: &mut PacketDecode) -> Result<Ed25519Pubkey> {
    let pubkey = blob.get_byte_array::<32>()?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&pubkey)
        .map_err(|_| Error::Crypto("ed25519 public key is not valid"))?;
    Ok(Ed25519Pubkey { verifying })
}

pub(super) fn decode_privkey(blob: &mut PacketDecode) -> Result<Ed25519Privkey> {
    let public_bytes = blob.get_byte_array::<32>()?;
    let keypair_bytes = blob.get_byte_array::<64>()?;
    if public_bytes[..] != keypair_bytes[32..] {
        return Err(Error::Decode("ed25519 privkey is not valid (public keys do not match)"));
    }

    let signing = ed25519_dalek::SigningKey::from_keypair_bytes(&keypair_bytes)
        .map_err(|_| Error::Crypto("ed25519 privkey is not valid"))?;
    Ok(Ed25519Privkey { signing })
}


impl From<ed25519_dalek::VerifyingKey> for Ed25519Pubkey {
    fn from(verifying: ed25519_dalek::VerifyingKey) -> Self { Self { verifying } }
}

impl From<Ed25519Pubkey> for ed25519_dalek::VerifyingKey {
    fn from(pubkey: Ed25519Pubkey) -> Self { pubkey.verifying }
}

impl From<ed25519_dalek::SigningKey> for Ed25519Privkey {
    fn from(signing: ed25519_dalek::SigningKey) -> Self { Self { signing } }
}

impl From<Ed25519Privkey> for ed25519_dalek::SigningKey {
    fn from(privkey: Ed25519Privkey) -> Self { privkey.signing }
}

impl fmt::Display for Ed25519Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ed25519 {:x}", Bytes::copy_from_slice(self.verifying.as_bytes()))
    }
}

impl PartialEq for Ed25519Privkey {
    fn eq(&self, other: &Self) -> bool {
        self.signing.to_keypair_bytes() == other.signing.to_keypair_bytes()
    }
}
impl Eq for Ed25519Privkey {}

impl Clone for Ed25519Privkey {
    fn clone(&self) -> Self {
        Self { signing: ed25519_dalek::SigningKey::from_keypair_bytes(&self.signing.to_keypair_bytes()).unwrap() }
    }
}
