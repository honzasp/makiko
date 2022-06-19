use cipher::{InnerIvInit as _, KeyInit as _, StreamCipher as _, BlockSizeUser, StreamCipherCore};
use cipher::consts::U256;
use typenum::{IsLess, Le, NonZero};
use crate::Result;
use super::{CipherAlgo, Encrypt, Decrypt};

/// "aes128-ctr" cipher from RFC 4344.
pub static AES128_CTR: CipherAlgo = CipherAlgo {
    name: "aes128-ctr",
    block_len: 16,
    key_len: 16,
    iv_len: 16,
    make_encrypt: |key, iv| Box::new(new_aes128_ctr(key, iv)),
    make_decrypt: |key, iv| Box::new(new_aes128_ctr(key, iv)),
};

/// "aes192-ctr" cipher from RFC 4344.
pub static AES192_CTR: CipherAlgo = CipherAlgo {
    name: "aes192-ctr",
    block_len: 16,
    key_len: 24,
    iv_len: 16,
    make_encrypt: |key, iv| Box::new(new_aes192_ctr(key, iv)),
    make_decrypt: |key, iv| Box::new(new_aes192_ctr(key, iv)),
};

/// "aes256-ctr" cipher from RFC 4344.
pub static AES256_CTR: CipherAlgo = CipherAlgo {
    name: "aes256-ctr",
    block_len: 16,
    key_len: 32,
    iv_len: 16,
    make_encrypt: |key, iv| Box::new(new_aes256_ctr(key, iv)),
    make_decrypt: |key, iv| Box::new(new_aes256_ctr(key, iv)),
};

struct StreamCipher<T: BlockSizeUser>
    where T::BlockSize: IsLess<U256>,
          Le<T::BlockSize, U256>: NonZero
{
    cipher: cipher::StreamCipherCoreWrapper<T>,
}

fn new_aes128_ctr(key: &[u8], iv: &[u8]) -> StreamCipher<ctr::CtrCore<aes::Aes128, ctr::flavors::Ctr128BE>> {
    let aes = aes::Aes128::new_from_slice(key).expect("invalid key length for aes128-ctr");
    let ctr = ctr::CtrCore::inner_iv_slice_init(aes, iv).expect("invalid iv length for aes128-ctr");
    let cipher = cipher::StreamCipherCoreWrapper::from_core(ctr);
    StreamCipher { cipher }
}

fn new_aes192_ctr(key: &[u8], iv: &[u8]) -> StreamCipher<ctr::CtrCore<aes::Aes192, ctr::flavors::Ctr128BE>> {
    let aes = aes::Aes192::new_from_slice(key).expect("invalid key length for aes192-ctr");
    let ctr = ctr::CtrCore::inner_iv_slice_init(aes, iv).expect("invalid iv length for aes192-ctr");
    let cipher = cipher::StreamCipherCoreWrapper::from_core(ctr);
    StreamCipher { cipher }
}

fn new_aes256_ctr(key: &[u8], iv: &[u8]) -> StreamCipher<ctr::CtrCore<aes::Aes256, ctr::flavors::Ctr128BE>> {
    let aes = aes::Aes256::new_from_slice(key).expect("invalid key length for aes256-ctr");
    let ctr = ctr::CtrCore::inner_iv_slice_init(aes, iv).expect("invalid iv length for aes256-ctr");
    let cipher = cipher::StreamCipherCoreWrapper::from_core(ctr);
    StreamCipher { cipher }
}


impl<T: BlockSizeUser> Encrypt for StreamCipher<T> 
    where T::BlockSize: IsLess<U256>,
          Le<T::BlockSize, U256>: NonZero,
          T: StreamCipherCore,
{
    fn encrypt(&mut self, data: &mut [u8]) -> Result<()> {
        Ok(self.cipher.apply_keystream(data))
    }
}

impl<T: BlockSizeUser> Decrypt for StreamCipher<T>
    where T::BlockSize: IsLess<U256>,
          Le<T::BlockSize, U256>: NonZero,
          T: StreamCipherCore,
{
    fn decrypt(&mut self, data: &mut [u8]) -> Result<()> {
        Ok(self.cipher.apply_keystream(data))
    }
}
