use bytes::Bytes;
use crate::codec::PacketDecode;
use crate::error::{Result, Error};
use ring::signature::{ED25519, VerificationAlgorithm as _};
use std::fmt;
use super::{PubkeyAlgo, Pubkey, SignatureVerified};

pub static SSH_ED25519: PubkeyAlgo = PubkeyAlgo {
    name: "ssh-ed25519",
    decode_pubkey: |pubkey| Ed25519Pubkey::decode(pubkey).map(Pubkey::Ed25519),
};

#[derive(Debug, Clone)]
pub struct Ed25519Pubkey {
    pubkey: Vec<u8>,
}

impl Ed25519Pubkey {
    pub fn decode(pubkey: Bytes) -> Result<Ed25519Pubkey> {
        let mut pubkey = PacketDecode::new(pubkey);
        if pubkey.get_string()? != "ssh-ed25519" {
            return Err(Error::Decode("expected pubkey format 'ssh-ed25519'"))
        }
        let pubkey_data = pubkey.get_bytes()?.as_ref().into();
        Ok(Ed25519Pubkey { pubkey: pubkey_data })
    }

    pub fn verify(&self, message: &[u8], signature: Bytes) -> Result<SignatureVerified> {
        let mut signature = PacketDecode::new(signature);
        if signature.get_string()? != "ssh-ed25519" {
            return Err(Error::Decode("expected signature format 'ssh-ed25519'"))
        }

        let signature_data = signature.get_bytes()?;

        match ED25519.verify(
            AsRef::<[u8]>::as_ref(&self.pubkey).into(),
            message.into(),
            signature_data.as_ref().into(),
        ) {
            Ok(_) => Ok(SignatureVerified::assertion()),
            Err(_) => Err(Error::Signature),
        }
    }
}

impl fmt::Display for Ed25519Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ed25519 {:x}", Bytes::copy_from_slice(&self.pubkey))
    }
}
