use bytes::Bytes;
use crate::codec::PacketDecode;
use crate::error::{Result, Error};
use rsa::{PublicKey as _, PublicKeyParts as _};
use sha1::Digest as _;
use std::fmt;
use super::{PubkeyAlgo, Pubkey, SignatureVerified};

/// "ssh-rsa" public key algorithm from RFC 4253.
pub static SSH_RSA: PubkeyAlgo = PubkeyAlgo {
    name: "ssh-rsa",
    decode_pubkey: |pubkey| RsaPubkey::decode(pubkey).map(Pubkey::Rsa),
};

/// RSA public key.
#[derive(Debug, Clone)]
pub struct RsaPubkey {
    pubkey: rsa::RsaPublicKey,
}

impl RsaPubkey {
    pub(crate) fn decode(pubkey: Bytes) -> Result<RsaPubkey> {
        let mut pubkey = PacketDecode::new(pubkey);
        if pubkey.get_string()? != "ssh-rsa" {
            return Err(Error::Decode("expected pubkey format 'ssh-rsa'"))
        }

        let e_be = pubkey.get_bytes()?;
        let n_be = pubkey.get_bytes()?;
        let e = rsa::BigUint::from_bytes_be(&e_be);
        let n = rsa::BigUint::from_bytes_be(&n_be);
        let rsa_pubkey = rsa::RsaPublicKey::new(n, e)
            .map_err(|_| Error::Decode("decoded ssh-rsa pubkey is invalid"))?;

        Ok(RsaPubkey { pubkey: rsa_pubkey })
    }

    pub(crate) fn verify(&self, message: &[u8], signature: Bytes) -> Result<SignatureVerified> {
        let mut signature = PacketDecode::new(signature);
        if signature.get_string()? != "ssh-rsa" {
            return Err(Error::Decode("expected signature format 'ssh-rsa'"))
        }

        let signature_data = signature.get_bytes()?;

        let mut hasher = sha1::Sha1::new();
        hasher.update(message);
        let hashed = hasher.finalize();

        let padding = rsa::PaddingScheme::PKCS1v15Sign { hash: Some(rsa::Hash::SHA1) };
        match self.pubkey.verify(padding, hashed.as_slice(), &signature_data) {
            Ok(_) => Ok(SignatureVerified::assertion()),
            Err(_) => Err(Error::Signature),
        }
    }
}

impl fmt::Display for RsaPubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "rsa n {:x}, e {}", self.pubkey.n(), self.pubkey.e())
    }
}
