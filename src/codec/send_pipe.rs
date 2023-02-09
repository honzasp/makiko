use bytes::{Buf as _, BufMut as _, BytesMut};
use rand::{RngCore as _, SeedableRng as _};
use rand_chacha::ChaCha8Rng;
use crate::{Error, Result};
use crate::cipher::{self, PacketEncrypt};
use crate::mac;
use crate::util::CryptoRngCore;

pub(crate) struct SendPipe {
    buf: BytesMut,
    encrypt: PacketEncrypt,
    block_len: usize,
    tag_len: usize,
    packet_seq: u64,
    padding_rng: ChaCha8Rng,
    sent_bytes: u64,
}

impl SendPipe {
    pub fn new(rng: &mut dyn CryptoRngCore) -> Result<SendPipe> {
        let padding_rng = ChaCha8Rng::from_rng(rng.as_rngcore())
            .map_err(|_| Error::Random("could not generate seed for padding generator"))?;
        Ok(SendPipe {
            buf: BytesMut::new(),
            encrypt: PacketEncrypt::EncryptAndMac(Box::new(cipher::Identity), Box::new(mac::Empty)),
            block_len: 8,
            tag_len: 0,
            packet_seq: 0,
            padding_rng,
            sent_bytes: 0,
        })
    }

    pub fn feed_ident(&mut self, ident: &[u8]) {
        // RFC 4253, section 4.2
        self.buf.reserve(ident.len() + 2);
        self.buf.put_slice(ident);
        self.buf.put_slice(&b"\r\n"[..]);
    }

    pub fn feed_packet(&mut self, payload: &[u8]) -> u32 {
        log::trace!("feed packet {}, len {}, seq {}",
            payload.first().cloned().unwrap_or(0), payload.len(), self.packet_seq);

        let include_len = match self.encrypt {
            PacketEncrypt::EncryptAndMac(_, _) => true,
            PacketEncrypt::EncryptThenMac(_, _) => false,
            PacketEncrypt::Aead(_) => false,
        };
        let padding_len = calculate_padding_len(payload.len(), self.block_len, include_len);

        // RFC 4253, section 6
        //
        // packet layout:
        // 4 bytes: `packet_len = 1 + payload_len + padding_len` (u32 big endian)
        // 1 byte: padding_len (u8)
        // `payload_len` bytes: payload
        // `padding_len` bytes: random padding
        // `tag_len` bytes: mac tag

        let packet_begin = self.buf.len();
        self.buf.reserve(5 + payload.len() + padding_len + self.tag_len);
        self.buf.put_u32((1 + payload.len() + padding_len) as u32);
        self.buf.put_u8(padding_len as u8);
        self.buf.put_slice(payload);
        self.buf.put_bytes(0, padding_len + self.tag_len);

        let packet = &mut self.buf[packet_begin..];
        self.padding_rng.fill_bytes(&mut packet[5 + payload.len()..][..padding_len]);

        let (plaintext, tag) = packet.split_at_mut(5 + payload.len() + padding_len);
        match self.encrypt {
            PacketEncrypt::EncryptAndMac(ref mut encrypt, ref mut mac) => {
                mac.sign(self.packet_seq as u32, plaintext, tag);
                encrypt.encrypt(plaintext);
            },
            PacketEncrypt::EncryptThenMac(ref mut encrypt, ref mut mac) => {
                encrypt.encrypt(&mut plaintext[4..]);
                let ciphertext = plaintext;
                mac.sign(self.packet_seq as u32, ciphertext, tag);
            },
            PacketEncrypt::Aead(ref mut aead) => {
                aead.encrypt_and_sign(self.packet_seq, plaintext, tag);
            },
        }

        let packet_len = self.buf.len() - packet_begin;
        self.sent_bytes += packet_len as u64;

        let packet_seq = self.packet_seq as u32;
        self.packet_seq += 1;
        packet_seq
    }

    pub fn set_encrypt(&mut self, encrypt: PacketEncrypt, block_len: usize, tag_len: usize) {
        self.encrypt = encrypt;
        self.block_len = block_len;
        self.tag_len = tag_len;
    }

    pub fn peek_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn consume_bytes(&mut self, len: usize) {
        self.buf.advance(len);
    }

    pub fn sent_bytes(&self) -> u64 {
        self.sent_bytes
    }
}

fn calculate_padding_len(payload_len: usize, block_len: usize, include_len: bool) -> usize {
    // RFC 4253, section 6
    let header_len = if include_len { 5 } else { 1 };
    let min_padded_len = header_len + payload_len + 4;
    let padded_len = (min_padded_len + block_len - 1) / block_len * block_len;
    padded_len - payload_len - header_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_send() {
        fn assert_is_send<T: Send>() {}
        assert_is_send::<SendPipe>()
    }

    #[test]
    fn test_calculate_padding_len() {
        for &block_len in &[1, 2, 4, 8, 16, 32] {
            for payload_len in 0..100 {
                let padding_len = calculate_padding_len(payload_len, block_len, true);
                assert_eq!((5 + payload_len + padding_len) % block_len, 0);
                assert!(padding_len >= 4);

                let padding_len = calculate_padding_len(payload_len, block_len, false);
                assert_eq!((1 + payload_len + padding_len) % block_len, 0);
                assert!(padding_len >= 4);
            }
        }
    }
}
