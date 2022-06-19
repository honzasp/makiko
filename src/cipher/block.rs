use cipher::{BlockEncryptMut, BlockDecryptMut, KeyInit as _, InnerIvInit as _};
use cipher::inout::InOutBuf;
use crate::Result;
use super::{CipherAlgo, Encrypt, Decrypt};

/// "aes256-cbc" cipher from RFC 4253.
pub static AES256_CBC: CipherAlgo = CipherAlgo {
    name: "aes256-cbc",
    block_len: 16,
    key_len: 32,
    iv_len: 16,
    make_encrypt: |key, iv| Box::new(new_aes256_cbc_enc(key, iv)),
    make_decrypt: |key, iv| Box::new(new_aes256_cbc_dec(key, iv)),
};

struct BlockEncrypt<T> {
    encrypt: T,
}

struct BlockDecrypt<T> {
    decrypt: T,
}

fn new_aes256_cbc_enc(key: &[u8], iv: &[u8]) -> BlockEncrypt<cbc::Encryptor<aes::Aes256>> {
    let aes = aes::Aes256::new_from_slice(key).expect("invalid key length for aes256-cbc");
    let encrypt = cbc::Encryptor::inner_iv_slice_init(aes, iv).expect("invalid iv length for aes256-cbc");
    BlockEncrypt { encrypt }
}

fn new_aes256_cbc_dec(key: &[u8], iv: &[u8]) -> BlockDecrypt<cbc::Decryptor<aes::Aes256>> {
    let aes = aes::Aes256::new_from_slice(key).expect("invalid key length for aes256-cbc");
    let decrypt = cbc::Decryptor::inner_iv_slice_init(aes, iv).expect("invalid iv length for aes256-cbc");
    BlockDecrypt { decrypt }
}


impl<T: BlockEncryptMut> Encrypt for BlockEncrypt<T> {
    fn encrypt(&mut self, data: &mut [u8]) -> Result<()> {
        let (blocks, tail) = InOutBuf::from(data).into_chunks();
        debug_assert!(tail.is_empty(), "plaintext is not aligned to block");
        Ok(self.encrypt.encrypt_blocks_inout_mut(blocks))
    }
}

impl<T: BlockDecryptMut> Decrypt for BlockDecrypt<T> {
    fn decrypt(&mut self, data: &mut [u8]) -> Result<()> {
        let (blocks, tail) = InOutBuf::from(data).into_chunks();
        debug_assert!(tail.is_empty(), "ciphertext is not aligned to block");
        Ok(self.decrypt.decrypt_blocks_inout_mut(blocks))
    }
}
