use cipher::{KeyIvInit as _, StreamCipherCore as _};
use cipher::generic_array::GenericArray;
use cipher::inout::InOutBuf;
use poly1305::universal_hash::{NewUniversalHash as _};
use subtle::ConstantTimeEq as _;
use crate::{Result, Error};
use crate::mac::MacVerified;
use super::{CipherAlgo, CipherAlgoVariant, AeadCipherAlgo, AeadEncrypt, AeadDecrypt};

/// "chacha20-poly1305@openssh.com" cipher as introduced by OpenSSH.
///
/// This is an AEAD cipher that does not use an additional [mac algorithm][crate::mac].
pub static CHACHA20_POLY1305: CipherAlgo = CipherAlgo {
    name: "chacha20-poly1305@openssh.com",
    block_len: 8,
    key_len: 64,
    iv_len: 0,
    variant: CipherAlgoVariant::Aead(AeadCipherAlgo {
        tag_len: 16,
        make_encrypt: |key, _| Box::new(new_chacha_poly(key)),
        make_decrypt: |key, _| Box::new(new_chacha_poly(key)),
    }),
};


struct ChachaPolyCipher {
    key_1: chacha20::Key,
    key_2: chacha20::Key,
}

fn new_chacha_poly(key: &[u8]) -> ChachaPolyCipher {
    // note that key 1 is made from the *higher* half of `key`!
    let key_1 = *chacha20::Key::from_slice(&key[32..]);
    let key_2 = *chacha20::Key::from_slice(&key[..32]);
    ChachaPolyCipher { key_1, key_2 }
}

impl AeadEncrypt for ChachaPolyCipher {
    fn encrypt_and_sign(&mut self, packet_seq: u64, packet: &mut [u8], tag: &mut [u8]) {
        let nonce = chacha20::LegacyNonce::from(packet_seq.to_be_bytes());

        let chacha_1 = chacha20::ChaCha20LegacyCore::new(&self.key_1, &nonce);
        chacha_1.apply_keystream_partial(InOutBuf::from(&mut packet[..4]));

        let mut chacha_2 = chacha20::ChaCha20LegacyCore::new(&self.key_2, &nonce);
        let mut poly_key_block = [0; 64].into();
        chacha_2.write_keystream_block(&mut poly_key_block);
        chacha_2.apply_keystream_partial(InOutBuf::from(&mut packet[4..]));

        let poly_key = poly1305::Key::from_slice(&poly_key_block[..32]);
        let poly = poly1305::Poly1305::new(poly_key);
        let poly_tag = poly.compute_unpadded(packet);
        tag.copy_from_slice(&poly_tag.into_bytes());
    }
}

impl AeadDecrypt for ChachaPolyCipher {
    fn decrypt_packet_len(&mut self, packet_seq: u64, ciphertext: &[u8], plaintext: &mut [u8]) {
        let nonce = chacha20::LegacyNonce::from(packet_seq.to_be_bytes());
        let chacha_1 = chacha20::ChaCha20LegacyCore::new(&self.key_1, &nonce);
        chacha_1.apply_keystream_partial(InOutBuf::new(ciphertext, plaintext).unwrap());
    }

    fn decrypt_and_verify(&mut self, packet_seq: u64, packet: &mut [u8], tag: &[u8]) -> Result<MacVerified> {
        let nonce = chacha20::LegacyNonce::from(packet_seq.to_be_bytes());

        let mut chacha_2 = chacha20::ChaCha20LegacyCore::new(&self.key_2, &nonce);
        let mut poly_key_block = [0; 64].into();
        chacha_2.write_keystream_block(&mut poly_key_block);

        let poly_key = poly1305::Key::from_slice(&poly_key_block[..32]);
        let poly = poly1305::Poly1305::new(poly_key);
        let poly_tag = poly.compute_unpadded(packet);
        let verified =
            if poly_tag.ct_eq(&poly1305::Tag::new(*GenericArray::from_slice(tag))).into() {
                MacVerified::assertion()
            } else {
                return Err(Error::Mac)
            };

        chacha_2.apply_keystream_partial(InOutBuf::from(&mut packet[4..]));
        Ok(verified)
    }
}

