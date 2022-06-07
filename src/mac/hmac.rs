use ring::hmac;
use ring::constant_time::verify_slices_are_equal;
use crate::error::{Result, Error};
use super::{MacAlgo, Mac, MacVerified};

pub static HMAC_SHA2_256: MacAlgo = MacAlgo {
    name: "hmac-sha2-256",
    tag_len: 32,
    key_len: 32,
    make_mac: |key| Box::new(HmacMac { key: hmac::Key::new(hmac::HMAC_SHA256, key) }),
};

#[derive(Debug)]
struct HmacMac {
    key: hmac::Key,
}

impl Mac for HmacMac {
    fn sign(&mut self, packet_seq: u32, plaintext: &[u8], tag: &mut [u8]) -> Result<()> {
        let computed_tag = compute_tag(&self.key, packet_seq, plaintext);
        tag.copy_from_slice(computed_tag.as_ref());
        Ok(())
    }

    fn verify(&mut self, packet_seq: u32, plaintext: &[u8], tag: &[u8]) -> Result<MacVerified> {
        let computed_tag = compute_tag(&self.key, packet_seq, plaintext);
        match verify_slices_are_equal(tag, computed_tag.as_ref()) {
            Ok(_) => Ok(MacVerified::assertion()),
            Err(_) => Err(Error::Mac),
        }
    }
}

fn compute_tag(key: &hmac::Key, packet_seq: u32, plaintext: &[u8]) -> hmac::Tag {
    let mut ctx = hmac::Context::with_key(key);
    ctx.update(&packet_seq.to_be_bytes());
    ctx.update(plaintext);
    ctx.sign()
}
