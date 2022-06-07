use cipher::{InnerIvInit as _, KeyInit as _, StreamCipher as _};
use crate::Result;
use super::{CipherAlgo, Encrypt, Decrypt};

pub static AES128_CTR: CipherAlgo = CipherAlgo {
    name: "aes128-ctr",
    block_len: 16,
    key_len: 16,
    iv_len: 16,
    make_encrypt: |key, iv| Box::new(Aes128Ctr::new(key, iv)),
    make_decrypt: |key, iv| Box::new(Aes128Ctr::new(key, iv)),
};

struct Aes128Ctr {
    cipher: ctr::Ctr128BE<aes::Aes128>,
}

impl Aes128Ctr {
    fn new(key: &[u8], iv: &[u8]) -> Self {
        let aes = aes::Aes128::new_from_slice(key).expect("invalid key length for aes128-ctr");
        let ctr = ctr::CtrCore::inner_iv_slice_init(aes, iv).expect("invalid iv length for aes128-ctr");
        let cipher = cipher::StreamCipherCoreWrapper::from_core(ctr);
        Self { cipher }
    }
}

impl Encrypt for Aes128Ctr {
    fn encrypt(&mut self, data: &mut [u8]) -> Result<()> {
        Ok(self.cipher.apply_keystream(data))
    }
}

impl Decrypt for Aes128Ctr {
    fn decrypt(&mut self, data: &mut [u8]) -> Result<()> {
        Ok(self.cipher.apply_keystream(data))
    }
}
