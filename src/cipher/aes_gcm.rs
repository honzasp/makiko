use aes_gcm::aead::{AeadInPlace as _};
use aes_gcm::aes::cipher::{BlockCipher, BlockEncrypt, KeyInit};
use aes_gcm::aes::cipher::generic_array::GenericArray;
use aes_gcm::aes::cipher::generic_array::sequence::Concat as _;
use aes_gcm::aes::cipher::typenum::{U12, U16};
use crate::{Result, Error};
use crate::mac::MacVerified;
use super::{CipherAlgo, CipherAlgoVariant, AeadCipherAlgo, AeadEncrypt, AeadDecrypt};

/// "aes128-gcm@openssh.com" cipher described in RFC 5647 and slightly modified by OpenSSH.
///
/// This is an AEAD cipher that does not use an additional [mac algorithm][crate::mac].
pub static AES128_GCM: CipherAlgo = CipherAlgo {
    name: "aes128-gcm@openssh.com",
    block_len: 16,
    key_len: 16,
    iv_len: 12,
    variant: CipherAlgoVariant::Aead(AeadCipherAlgo {
        tag_len: 16,
        make_encrypt: |key, iv| Box::new(new_aes_gcm::<aes::Aes128>(key, iv)),
        make_decrypt: |key, iv| Box::new(new_aes_gcm::<aes::Aes128>(key, iv)),
    }),
};

/// "aes256-gcm@openssh.com" cipher described in RFC 5647 and slightly modified by OpenSSH.
///
/// This is an AEAD cipher that does not use an additional [mac algorithm][crate::mac].
pub static AES256_GCM: CipherAlgo = CipherAlgo {
    name: "aes256-gcm@openssh.com",
    block_len: 16,
    key_len: 32,
    iv_len: 12,
    variant: CipherAlgoVariant::Aead(AeadCipherAlgo {
        tag_len: 16,
        make_encrypt: |key, iv| Box::new(new_aes_gcm::<aes::Aes256>(key, iv)),
        make_decrypt: |key, iv| Box::new(new_aes_gcm::<aes::Aes256>(key, iv)),
    }),
};


struct AesGcmCipher<Aes> {
    aes_gcm: aes_gcm::AesGcm<Aes, U12>,
    iv_fixed: u32,
    iv_counter: u64,
}

fn new_aes_gcm<Aes>(key: &[u8], iv: &[u8]) -> AesGcmCipher<Aes>
    where Aes: KeyInit + BlockCipher<BlockSize = U16> + BlockEncrypt,
{
    let aes_gcm = aes_gcm::AesGcm::new_from_slice(key).unwrap();
    let iv_fixed = u32::from_be_bytes(iv[0..4].try_into().unwrap());
    let iv_counter = u64::from_be_bytes(iv[4..12].try_into().unwrap());
    AesGcmCipher { aes_gcm, iv_fixed, iv_counter }
}

impl<Aes> AeadEncrypt for AesGcmCipher<Aes>
    where Aes: BlockCipher<BlockSize = U16> + BlockEncrypt,
{
    fn encrypt_and_sign(&mut self, _packet_seq: u64, packet: &mut [u8], tag: &mut [u8]) {
        let nonce = increment_iv(self);
        let (packet_len, packet_rest) = packet.split_at_mut(4);
        let aes_gcm_tag = self.aes_gcm.encrypt_in_place_detached(&nonce, packet_len, packet_rest).unwrap();
        tag.copy_from_slice(&aes_gcm_tag);
    }
}

impl<Aes> AeadDecrypt for AesGcmCipher<Aes>
    where Aes: BlockCipher<BlockSize = U16> + BlockEncrypt,
{
    fn decrypt_packet_len(&mut self, _packet_seq: u64, ciphertext: &[u8], plaintext: &mut [u8]) {
        plaintext.copy_from_slice(ciphertext);
    }

    fn decrypt_and_verify(&mut self, _packet_seq: u64, packet: &mut [u8], tag: &[u8]) -> Result<MacVerified> {
        let aes_gcm_tag = *GenericArray::from_slice(tag);
        let nonce = increment_iv(self);
        let (packet_len, packet_rest) = packet.split_at_mut(4);
        match self.aes_gcm.decrypt_in_place_detached(&nonce, packet_len, packet_rest, &aes_gcm_tag) {
            Ok(_) => Ok(MacVerified::assertion()),
            Err(_) => Err(Error::Mac),
        }
    }
}

fn increment_iv<Aes>(cipher: &mut AesGcmCipher<Aes>) -> GenericArray<u8, U12> {
    let iv_fixed = GenericArray::from(cipher.iv_fixed.to_be_bytes());
    let iv_counter = GenericArray::from(cipher.iv_counter.to_be_bytes());
    cipher.iv_counter = cipher.iv_counter.wrapping_add(1);
    iv_fixed.concat(iv_counter)
}
