use cipher::{BlockEncryptMut, BlockDecryptMut, BlockCipher, KeyInit, InnerIvInit as _};
use cipher::inout::InOutBuf;
use crate::Result;
use super::{CipherAlgo, Encrypt, Decrypt};

/// "aes128-cbc" cipher from RFC 4253.
pub static AES128_CBC: CipherAlgo = CipherAlgo {
    name: "aes128-cbc",
    block_len: 16,
    key_len: 16,
    iv_len: 16,
    make_encrypt: |key, iv| Box::new(new_cbc_enc::<aes::Aes128>(key, iv)),
    make_decrypt: |key, iv| Box::new(new_cbc_dec::<aes::Aes128>(key, iv)),
};

/// "aes192-cbc" cipher from RFC 4253.
pub static AES192_CBC: CipherAlgo = CipherAlgo {
    name: "aes192-cbc",
    block_len: 16,
    key_len: 24,
    iv_len: 16,
    make_encrypt: |key, iv| Box::new(new_cbc_enc::<aes::Aes192>(key, iv)),
    make_decrypt: |key, iv| Box::new(new_cbc_dec::<aes::Aes192>(key, iv)),
};

/// "aes256-cbc" cipher from RFC 4253.
pub static AES256_CBC: CipherAlgo = CipherAlgo {
    name: "aes256-cbc",
    block_len: 16,
    key_len: 32,
    iv_len: 16,
    make_encrypt: |key, iv| Box::new(new_cbc_enc::<aes::Aes256>(key, iv)),
    make_decrypt: |key, iv| Box::new(new_cbc_dec::<aes::Aes256>(key, iv)),
};

struct BlockEncrypt<T> {
    encrypt: T,
}

struct BlockDecrypt<T> {
    decrypt: T,
}

fn new_cbc_enc<C>(key: &[u8], iv: &[u8]) -> BlockEncrypt<cbc::Encryptor<C>> 
    where C: BlockCipher + cipher::BlockEncrypt + KeyInit
{
    let cipher = C::new_from_slice(key).expect("invalid key length for block cipher");
    let encrypt = cbc::Encryptor::inner_iv_slice_init(cipher, iv).expect("invalid iv length for cbc");
    BlockEncrypt { encrypt }
}

fn new_cbc_dec<C>(key: &[u8], iv: &[u8]) -> BlockDecrypt<cbc::Decryptor<C>>
    where C: BlockCipher + cipher::BlockDecrypt + KeyInit
{
    let cipher = C::new_from_slice(key).expect("invalid key length for block cipher");
    let decrypt = cbc::Decryptor::inner_iv_slice_init(cipher, iv).expect("invalid iv length for cbc");
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
