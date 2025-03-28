use bytes::Bytes;
use rsa::pkcs8;
use sha1::digest;
use std::fmt;
use crate::codec::{PacketDecode, PacketEncode};
use crate::error::{Result, Error};
use super::{PubkeyAlgo, Pubkey, Privkey, SignatureVerified};

/// "ssh-rsa" public key algorithm using SHA-1 from RFC 4253.
///
/// This algorithm is compatible with [`RsaPubkey`] and [`RsaPrivkey`].
pub static SSH_RSA_SHA1: PubkeyAlgo = PubkeyAlgo {
    name: "ssh-rsa",
    verify: verify::<sha1::Sha1>,
    sign: sign::<sha1::Sha1>,
};

/// "rsa-sha2-256" public key algorithm from RFC 8332.
///
/// This algorithm is compatible with [`RsaPubkey`] and [`RsaPrivkey`].
pub static RSA_SHA2_256: PubkeyAlgo = PubkeyAlgo {
    name: "rsa-sha2-256",
    verify: verify::<sha2::Sha256>,
    sign: sign::<sha2::Sha256>,
};

/// "rsa-sha2-512" public key algorithm from RFC 8332.
///
/// This algorithm is compatible with [`RsaPubkey`] and [`RsaPrivkey`].
pub static RSA_SHA2_512: PubkeyAlgo = PubkeyAlgo {
    name: "rsa-sha2-512",
    verify: verify::<sha2::Sha512>,
    sign: sign::<sha2::Sha512>,
};


/// RSA public key.
///
/// This key is compatible with [`SSH_RSA_SHA1`], [`RSA_SHA2_256`] and [`RSA_SHA2_512`]. You can
/// convert it to and from [`rsa::RsaPublicKey`] using `from()`/`into()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPubkey {
    pub(crate) pubkey: rsa::RsaPublicKey,
}

/// RSA whole key (private and public parts).
///
/// This key is compatible with [`SSH_RSA_SHA1`], [`RSA_SHA2_256`] and [`RSA_SHA2_512`]. You can
/// convert it to and from [`rsa::RsaPrivateKey`] using `from()`/`into()`.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "debug-less-secure", derive(Debug))]
pub struct RsaPrivkey {
    pub(crate) privkey: rsa::RsaPrivateKey,
}

impl RsaPrivkey {
    /// Return the public key associated with this private key.
    pub fn pubkey(&self) -> RsaPubkey {
        RsaPubkey { pubkey: self.privkey.to_public_key() }
    }
}

fn verify<H: RsaHash>(pubkey: &Pubkey, message: &[u8], signature_blob: Bytes) -> Result<SignatureVerified> {
    let Pubkey::Rsa(pubkey) = pubkey else { return Err(Error::PubkeyFormat) };

    let mut signature_blob = PacketDecode::new(signature_blob);
    if signature_blob.get_string()? != H::ALGO_NAME {
        return Err(Error::Decode("unexpected signature format"))
    }

    let signature = signature_blob.get_bytes()?;

    let mut hasher = H::new();
    hasher.update(message);
    let hashed = hasher.finalize();

    let scheme = rsa::pkcs1v15::Pkcs1v15Sign::new::<H>();
    match pubkey.pubkey.verify(scheme, hashed.as_slice(), &signature) {
        Ok(_) => Ok(SignatureVerified::assertion()),
        Err(_) => Err(Error::Signature),
    }
}

fn sign<H: RsaHash>(privkey: &Privkey, message: &[u8]) -> Result<Bytes> {
    let Privkey::Rsa(privkey) = privkey else { return Err(Error::PrivkeyFormat) };

    let mut hasher = H::new();
    hasher.update(message);
    let hashed = hasher.finalize();

    let scheme = rsa::pkcs1v15::Pkcs1v15Sign::new::<H>();
    let signature = privkey.privkey.sign(scheme, hashed.as_slice())
        .map_err(|_| Error::Crypto("could not sign with RSA"))?;

    let mut signature_blob = PacketEncode::new();
    signature_blob.put_str(H::ALGO_NAME);
    signature_blob.put_bytes(&signature);
    Ok(signature_blob.finish())
}

pub(super) fn encode_pubkey(blob: &mut PacketEncode, pubkey: &RsaPubkey) {
    use rsa::traits::PublicKeyParts as _;
    blob.put_str("ssh-rsa");
    blob.put_biguint(pubkey.pubkey.e());
    blob.put_biguint(pubkey.pubkey.n());
}

pub(super) fn decode_pubkey(blob: &mut PacketDecode) -> Result<RsaPubkey> {
    let e = blob.get_biguint()?;
    let n = blob.get_biguint()?;
    let pubkey = rsa::RsaPublicKey::new(n, e)
        .map_err(|_| Error::Decode("decoded ssh-rsa pubkey is invalid"))?;

    Ok(RsaPubkey { pubkey })
}

pub(super) fn decode_privkey(blob: &mut PacketDecode) -> Result<RsaPrivkey> {
    let n = blob.get_biguint()?;
    let e = blob.get_biguint()?;
    let d = blob.get_biguint()?;
    let _iqmp = blob.get_biguint()?;
    let p = blob.get_biguint()?;
    let q = blob.get_biguint()?;
    let privkey = rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .map_err(|_| Error::Decode("decoded ssh-rsa privkey is invalid"))?;
    Ok(RsaPrivkey { privkey })
}



trait RsaHash: digest::Digest + pkcs8::AssociatedOid {
    const ALGO_NAME: &'static str;
}

impl RsaHash for sha1::Sha1 {
    const ALGO_NAME: &'static str = "ssh-rsa";
}

impl RsaHash for sha2::Sha256 {
    const ALGO_NAME: &'static str = "rsa-sha2-256";
}

impl RsaHash for sha2::Sha512 {
    const ALGO_NAME: &'static str = "rsa-sha2-512";
}

impl From<rsa::RsaPublicKey> for RsaPubkey {
    fn from(pubkey: rsa::RsaPublicKey) -> Self { Self { pubkey } }
}

impl From<RsaPubkey> for rsa::RsaPublicKey {
    fn from(pubkey: RsaPubkey) -> Self { pubkey.pubkey }
}

impl From<rsa::RsaPrivateKey> for RsaPrivkey {
    fn from(privkey: rsa::RsaPrivateKey) -> Self { Self { privkey } }
}

impl From<RsaPrivkey> for rsa::RsaPrivateKey {
    fn from(privkey: RsaPrivkey) -> Self { privkey.privkey }
}

impl fmt::Display for RsaPubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use rsa::traits::PublicKeyParts as _;
        write!(f, "rsa n {:x}, e {}", self.pubkey.n(), self.pubkey.e())
    }
}
