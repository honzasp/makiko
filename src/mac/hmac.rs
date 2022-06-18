use digest::{CtOutput, Mac as _};
use generic_array::GenericArray;
use hmac::Hmac;
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use crate::error::{Result, Error};
use super::{MacAlgo, Mac, MacVerified};

/// "hmac-sha2-256" MAC from RFC 6668.
pub static HMAC_SHA2_256: MacAlgo = MacAlgo {
    name: "hmac-sha2-256",
    tag_len: 32,
    key_len: 32,
    make_mac: |key| Box::new(HmacSha256Mac { key: key.to_vec() }),
};

#[derive(Debug)]
struct HmacSha256Mac {
    key: Vec<u8>,
}

impl Mac for HmacSha256Mac {
    fn sign(&mut self, packet_seq: u32, plaintext: &[u8], tag: &mut [u8]) -> Result<()> {
        let computed_tag = compute_hmac_sha256_tag(&self.key, packet_seq, plaintext);
        tag.copy_from_slice(&computed_tag.into_bytes());
        Ok(())
    }

    fn verify(&mut self, packet_seq: u32, plaintext: &[u8], tag: &[u8]) -> Result<MacVerified> {
        let computed_tag = compute_hmac_sha256_tag(&self.key, packet_seq, plaintext);
        let expected_tag = GenericArray::clone_from_slice(tag).into();
        if computed_tag.ct_eq(&expected_tag).into() {
            Ok(MacVerified::assertion())
        } else {
            Err(Error::Mac)
        }
    }
}

type HmacSha256 = Hmac<Sha256>;

fn compute_hmac_sha256_tag(key: &[u8], packet_seq: u32, plaintext: &[u8]) -> CtOutput<HmacSha256> {
    let mut mac = HmacSha256::new_from_slice(key).expect("bad hmac key size");
    mac.update(&packet_seq.to_be_bytes());
    mac.update(plaintext);
    mac.finalize()
}
