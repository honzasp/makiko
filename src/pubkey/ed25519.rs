use bytes::Bytes;
use crate::codec::PacketDecode;
use crate::error::{Result, Error};
use ed25519_dalek as ed25519;
use std::fmt;
use super::{PubkeyAlgo, Pubkey, SignatureVerified};

/// "ssh-ed25519" public key algorithm from RFC 8709.
pub static SSH_ED25519: PubkeyAlgo = PubkeyAlgo {
    name: "ssh-ed25519",
    decode_pubkey: |pubkey| Ed25519Pubkey::decode(pubkey).map(Pubkey::Ed25519),
};

/// Ed25519 public key from RFC 8032.
#[derive(Debug, Clone)]
pub struct Ed25519Pubkey {
    pubkey: ed25519::PublicKey,
}

impl Ed25519Pubkey {
    pub(crate) fn decode(pubkey: Bytes) -> Result<Ed25519Pubkey> {
        let mut pubkey = PacketDecode::new(pubkey);
        if pubkey.get_string()? != "ssh-ed25519" {
            return Err(Error::Decode("expected pubkey format 'ssh-ed25519'"))
        }
        let pubkey_data = pubkey.get_bytes()?;
        let pubkey = ed25519::PublicKey::from_bytes(&pubkey_data)
            .map_err(|_| Error::Crypto("ed25519 pubkey is not valid"))?;
        Ok(Ed25519Pubkey { pubkey })
    }

    pub(crate) fn verify(&self, message: &[u8], signature: Bytes) -> Result<SignatureVerified> {
        let mut signature = PacketDecode::new(signature);
        if signature.get_string()? != "ssh-ed25519" {
            return Err(Error::Decode("expected signature format 'ssh-ed25519'"))
        }

        let signature_data = signature.get_byte_array::<64>()?;
        let ed_signature = ed25519::Signature::from(signature_data);

        match self.pubkey.verify_strict(message, &ed_signature) {
            Ok(_) => Ok(SignatureVerified::assertion()),
            Err(_) => Err(Error::Signature),
        }
    }
}

impl fmt::Display for Ed25519Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ed25519 {:x}", Bytes::copy_from_slice(self.pubkey.as_bytes()))
    }
}
