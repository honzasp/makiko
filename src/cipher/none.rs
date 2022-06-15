use crate::Result;
use super::{CipherAlgo, Encrypt, Decrypt};

/// "none" cipher (no encryption).
pub static NONE: CipherAlgo = CipherAlgo {
    name: "none",
    block_len: 8,
    key_len: 0,
    iv_len: 0,
    make_encrypt: |_key, _iv| Box::new(Identity),
    make_decrypt: |_key, _iv| Box::new(Identity),
};

#[derive(Debug)]
pub struct Identity;

impl Encrypt for Identity {
    fn encrypt(&mut self, _data: &mut [u8]) -> Result<()> {
        Ok(())
    }
}

impl Decrypt for Identity {
    fn decrypt(&mut self, _data: &mut [u8]) -> Result<()> {
        Ok(())
    }
}
