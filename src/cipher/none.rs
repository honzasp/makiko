use super::{CipherAlgo, CipherAlgoVariant, StandardCipherAlgo, Encrypt, Decrypt};

/// "none" cipher (no encryption).
pub static NONE: CipherAlgo = CipherAlgo {
    name: "none",
    block_len: 8,
    key_len: 0,
    iv_len: 0,
    variant: CipherAlgoVariant::Standard(StandardCipherAlgo {
        make_encrypt: |_key, _iv| Box::new(Identity),
        make_decrypt: |_key, _iv| Box::new(Identity),
    }),
};

#[derive(Debug)]
pub struct Identity;

impl Encrypt for Identity {
    fn encrypt(&mut self, _data: &mut [u8]) {}
}

impl Decrypt for Identity {
    fn decrypt(&mut self, _data: &mut [u8]) {}
}
