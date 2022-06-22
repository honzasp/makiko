use crate::Result;
use super::{Mac, MacAlgo, MacAlgoVariant, MacVerified};

/// "none" MAC (no message authentication).
pub static NONE: MacAlgo = MacAlgo {
    name: "none",
    tag_len: 0,
    key_len: 0,
    variant: MacAlgoVariant::EncryptAndMac,
    make_mac: |_key: &[u8]| Box::new(Empty),
};

/// invalid MAC (panics if used)
pub static INVALID: MacAlgo = MacAlgo {
    name: "invalid",
    tag_len: 0,
    key_len: 0,
    variant: MacAlgoVariant::EncryptAndMac,
    make_mac: |_key| panic!("trying to use 'invalid' mac"),
};

#[derive(Debug)]
pub struct Empty;

impl Mac for Empty {
    fn sign(&mut self, _packet_seq: u32, _data: &[u8], tag: &mut [u8]) {
        assert!(tag.is_empty());
    }

    fn verify(&mut self, _packet_seq: u32, _data: &[u8], tag: &[u8]) -> Result<MacVerified> {
        assert!(tag.is_empty());
        Ok(MacVerified::assertion())
    }
}
