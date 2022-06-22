use cipher::{
    InnerIvInit as _, KeyInit, BlockSizeUser, BlockCipher,
    BlockEncrypt, StreamCipher as _, StreamCipherCore,
};
use cipher::consts::U256;
use typenum::{IsLess, Le, NonZero};
use super::{CipherAlgo, CipherAlgoVariant, StandardCipherAlgo, Encrypt, Decrypt};

/// "aes128-ctr" cipher from RFC 4344.
pub static AES128_CTR: CipherAlgo = CipherAlgo {
    name: "aes128-ctr",
    block_len: 16,
    key_len: 16,
    iv_len: 16,
    variant: CipherAlgoVariant::Standard(StandardCipherAlgo {
        make_encrypt: |key, iv| Box::new(new_ctr::<aes::Aes128>(key, iv)),
        make_decrypt: |key, iv| Box::new(new_ctr::<aes::Aes128>(key, iv)),
    }),
};

/// "aes192-ctr" cipher from RFC 4344.
pub static AES192_CTR: CipherAlgo = CipherAlgo {
    name: "aes192-ctr",
    block_len: 16,
    key_len: 24,
    iv_len: 16,
    variant: CipherAlgoVariant::Standard(StandardCipherAlgo {
        make_encrypt: |key, iv| Box::new(new_ctr::<aes::Aes192>(key, iv)),
        make_decrypt: |key, iv| Box::new(new_ctr::<aes::Aes192>(key, iv)),
    }),
};

/// "aes256-ctr" cipher from RFC 4344.
pub static AES256_CTR: CipherAlgo = CipherAlgo {
    name: "aes256-ctr",
    block_len: 16,
    key_len: 32,
    iv_len: 16,
    variant: CipherAlgoVariant::Standard(StandardCipherAlgo {
        make_encrypt: |key, iv| Box::new(new_ctr::<aes::Aes256>(key, iv)),
        make_decrypt: |key, iv| Box::new(new_ctr::<aes::Aes256>(key, iv)),
    }),
};

struct StreamCipher<T: BlockSizeUser>
    where T::BlockSize: IsLess<U256>,
          Le<T::BlockSize, U256>: NonZero
{
    cipher: cipher::StreamCipherCoreWrapper<T>,
}

fn new_ctr<C>(key: &[u8], iv: &[u8]) -> StreamCipher<ctr::CtrCore<C, ctr::flavors::Ctr128BE>> 
    where C: BlockCipher + BlockEncrypt + KeyInit + BlockSizeUser,
          C::BlockSize: IsLess<U256>,
          Le<C::BlockSize, U256>: NonZero,
          ctr::flavors::Ctr128BE: ctr::CtrFlavor<C::BlockSize>,
{
    let cipher = C::new_from_slice(key).expect("invalid key length for ctr cipher");
    let ctr = ctr::CtrCore::inner_iv_slice_init(cipher, iv).expect("invalid iv length for ctr");
    StreamCipher { cipher: cipher::StreamCipherCoreWrapper::from_core(ctr) }
}

impl<T: BlockSizeUser> Encrypt for StreamCipher<T> 
    where T::BlockSize: IsLess<U256>,
          Le<T::BlockSize, U256>: NonZero,
          T: StreamCipherCore,
{
    fn encrypt(&mut self, data: &mut [u8]) {
        debug_assert!(data.len() % T::block_size() == 0);
        self.cipher.apply_keystream(data)
    }
}

impl<T: BlockSizeUser> Decrypt for StreamCipher<T>
    where T::BlockSize: IsLess<U256>,
          Le<T::BlockSize, U256>: NonZero,
          T: StreamCipherCore,
{
    fn decrypt(&mut self, data: &mut [u8]) {
        debug_assert!(data.len() % T::block_size() == 0);
        self.cipher.apply_keystream(data)
    }
}
