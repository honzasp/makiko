use bytes::Bytes;
use crate::codec::{PacketDecode, PacketEncode};
use crate::error::{Result, Error};
use super::{Pubkey, RsaPubkey, Ed25519Pubkey};

pub fn decode_pubkey(blob: Bytes) -> Result<Pubkey> {
    let mut blob = PacketDecode::new(blob);
    let format = blob.get_string()?;
    match format.as_str() {
        "ssh-ed25519" => decode_ed25519(&mut blob).map(Pubkey::Ed25519),
        "ssh-rsa" => decode_rsa(&mut blob).map(Pubkey::Rsa),
        _ => Err(Error::Decode("unknown public key format")),
    }
}

fn decode_ed25519(blob: &mut PacketDecode) -> Result<Ed25519Pubkey> {
    let pubkey = blob.get_bytes()?;
    let pubkey = ed25519_dalek::PublicKey::from_bytes(&pubkey)
        .map_err(|_| Error::Crypto("ed25519 pubkey is not valid"))?;
    Ok(Ed25519Pubkey { pubkey })
}


fn decode_rsa(blob: &mut PacketDecode) -> Result<RsaPubkey> {
    let e = blob.get_biguint()?;
    let n = blob.get_biguint()?;
    let pubkey = rsa::RsaPublicKey::new(n, e)
        .map_err(|_| Error::Decode("decoded ssh-rsa pubkey is invalid"))?;

    Ok(RsaPubkey { pubkey })
}


pub fn encode_pubkey(pubkey: &Pubkey) -> Bytes {
    let mut blob = PacketEncode::new();
    match pubkey {
        Pubkey::Ed25519(pubkey) => encode_ed25519(&mut blob, pubkey),
        Pubkey::Rsa(pubkey) => encode_rsa(&mut blob, pubkey),
    }
    blob.finish()
}

fn encode_ed25519(blob: &mut PacketEncode, pubkey: &Ed25519Pubkey) {
    blob.put_str("ssh-ed25519");
    blob.put_bytes(pubkey.pubkey.as_bytes());
}

fn encode_rsa(blob: &mut PacketEncode, pubkey: &RsaPubkey) {
    use rsa::PublicKeyParts as _;
    blob.put_str("ssh-rsa");
    blob.put_biguint(pubkey.pubkey.e());
    blob.put_biguint(pubkey.pubkey.n());
}
