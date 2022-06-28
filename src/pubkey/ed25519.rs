use bytes::Bytes;
use guard::guard;
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
/// This key is compatible with [`SSH_ED25519`].
#[derive(Debug, Clone)]
pub struct Ed25519Pubkey {
    pub(crate) pubkey: ed25519_dalek::PublicKey,
}

/// Ed25519 keypair from RFC 8032.
///
/// This key is compatible with [`SSH_ED25519`].
pub struct Ed25519Privkey {
    pub(crate) keypair: ed25519_dalek::Keypair,
}

impl Ed25519Privkey {
    /// Get the public associated with this private key.
    pub fn pubkey(&self) -> Ed25519Pubkey {
        Ed25519Pubkey { pubkey: self.keypair.public }
    }
}

fn verify(pubkey: &Pubkey, message: &[u8], signature: Bytes) -> Result<SignatureVerified> {
    guard!{let Pubkey::Ed25519(pubkey) = pubkey else { return Err(Error::PubkeyFormat) }};

    let mut signature = PacketDecode::new(signature);
    if signature.get_string()? != "ssh-ed25519" {
        return Err(Error::Decode("expected signature format 'ssh-ed25519'"))
    }

    let signature_data = signature.get_byte_array::<64>()?;
    let ed_signature = ed25519_dalek::Signature::from(signature_data);

    match pubkey.pubkey.verify_strict(message, &ed_signature) {
        Ok(_) => Ok(SignatureVerified::assertion()),
        Err(_) => Err(Error::Signature),
    }
}

fn sign(privkey: &Privkey, message: &[u8]) -> Result<Bytes> {
    guard!{let Privkey::Ed25519(privkey) = privkey else { return Err(Error::PrivkeyFormat) }};

    use ed25519_dalek::Signer as _;
    let ed_signature = privkey.keypair.try_sign(message)
        .map_err(|_| Error::Crypto("could not sign with ed25519"))?;

    let mut signature = PacketEncode::new();
    signature.put_str("ssh-ed25519");
    signature.put_bytes(&ed_signature.to_bytes());
    Ok(signature.finish())
}

impl From<ed25519_dalek::PublicKey> for Ed25519Pubkey {
    fn from(pubkey: ed25519_dalek::PublicKey) -> Self {
        Self { pubkey }
    }
}

impl From<ed25519_dalek::Keypair> for Ed25519Privkey {
    fn from(keypair: ed25519_dalek::Keypair) -> Self {
        Self { keypair }
    }
}

impl fmt::Display for Ed25519Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ed25519 {:x}", Bytes::copy_from_slice(self.pubkey.as_bytes()))
    }
}

impl Clone for Ed25519Privkey {
    fn clone(&self) -> Self {
        Self { keypair: ed25519_dalek::Keypair::from_bytes(&self.keypair.to_bytes()).unwrap() }
    }
}
