use crate::Result;
pub use self::hmac::HMAC_SHA2_256;
pub use self::none::{Empty, NONE};

mod none;
mod hmac;

pub struct MacAlgo {
    pub name: &'static str,
    pub tag_len: usize,
    pub key_len: usize,
    pub make_mac: fn(key: &[u8]) -> Box<dyn Mac + Send>,
}

pub trait Mac {
    fn sign(&mut self, packet_seq: u32, plaintext: &[u8], tag: &mut [u8]) -> Result<()>;
    fn verify(&mut self, packet_seq: u32, plaintext: &[u8], tag: &[u8]) -> Result<MacVerified>;
}

#[derive(Debug)]
pub struct MacVerified(());

impl MacVerified {
    pub fn assertion() -> Self {
        Self(())
    }
}
