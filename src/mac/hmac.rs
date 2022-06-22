use cipher::{KeySizeUser, KeyInit};
use hmac::{digest, Hmac};
use std::marker::PhantomData;
use crate::error::{Result, Error};
use super::{MacAlgo, Mac, MacVerified};

/// "hmac-sha2-256" MAC from RFC 6668.
pub static HMAC_SHA2_256: MacAlgo = MacAlgo {
    name: "hmac-sha2-256",
    tag_len: 32,
    key_len: 32,
    make_mac: |key| Box::new(HmacMac::<Hmac<sha2::Sha256>>::new(key)),
};

/// "hmac-sha2-512" MAC from RFC 6668.
pub static HMAC_SHA2_512: MacAlgo = MacAlgo {
    name: "hmac-sha2-512",
    tag_len: 64,
    key_len: 64,
    make_mac: |key| Box::new(HmacMac::<Hmac<sha2::Sha512>>::new(key)),
};

/// "hmac-sha1" MAC from RFC 4253.
pub static HMAC_SHA1: MacAlgo = MacAlgo {
    name: "hmac-sha1",
    tag_len: 20,
    key_len: 20,
    make_mac: |key| Box::new(HmacMac::<Hmac<sha1::Sha1>>::new(key)),
};


struct HmacMac<M> {
    key: Vec<u8>,
    _phantom: PhantomData<M>,
}

impl<M: digest::Mac + KeySizeUser> HmacMac<M> {
    fn new(key: &[u8]) -> HmacMac<M> {
        HmacMac { key: key.into(), _phantom: PhantomData }
    }
}

impl<M: digest::Mac + KeySizeUser + KeyInit> Mac for HmacMac<M> {
    fn sign(&mut self, packet_seq: u32, plaintext: &[u8], tag: &mut [u8]) {
        let mut digest = <M as digest::Mac>::new_from_slice(&self.key).unwrap();
        digest.update(&packet_seq.to_be_bytes());
        digest.update(plaintext);
        tag.copy_from_slice(&digest.finalize().into_bytes());
    }

    fn verify(&mut self, packet_seq: u32, plaintext: &[u8], tag: &[u8]) -> Result<MacVerified> {
        let mut digest = <M as digest::Mac>::new_from_slice(&self.key).unwrap();
        digest.update(&packet_seq.to_be_bytes());
        digest.update(plaintext);
        match digest.verify_slice(tag) {
            Ok(_) => Ok(MacVerified::assertion()),
            Err(_) => Err(Error::Mac),
        }
    }
}
