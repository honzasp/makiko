use crate::Result;
pub use self::aes::AES128_CTR;
pub use self::none::{Identity, NONE};

mod aes;
mod none;

pub struct CipherAlgo {
    pub name: &'static str,
    pub block_len: usize,
    pub key_len: usize,
    pub iv_len: usize,
    pub make_encrypt: fn(key: &[u8], iv: &[u8]) -> Box<dyn Encrypt + Send>,
    pub make_decrypt: fn(key: &[u8], iv: &[u8]) -> Box<dyn Decrypt + Send>,
}

pub trait Encrypt {
    fn encrypt(&mut self, data: &mut [u8]) -> Result<()>;
}

pub trait Decrypt {
    fn decrypt(&mut self, data: &mut [u8]) -> Result<()>;
}
