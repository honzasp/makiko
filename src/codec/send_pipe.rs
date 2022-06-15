use bytes::{BufMut as _, BytesMut};
use rand::{RngCore as _, SeedableRng as _};
use rand_chacha::ChaCha8Rng;
use ring::rand::SecureRandom;
use crate::{Error, Result};
use crate::cipher::{self, Encrypt};
use crate::mac::{self, Mac};

pub(crate) struct SendPipe {
    buf: BytesMut,
    encrypt: Box<dyn Encrypt + Send>,
    block_len: usize,
    mac: Box<dyn Mac + Send>,
    tag_len: usize,
    packet_seq: u32,
    padding_rng: ChaCha8Rng,
}

impl SendPipe {
    pub fn new(rng: &dyn SecureRandom) -> Result<SendPipe> {
        let padding_rng_seed = ring::rand::generate(rng)
            .map_err(|_| Error::Random("could not generate seed for padding generator"))?;
        Ok(SendPipe {
            buf: BytesMut::new(),
            encrypt: Box::new(cipher::Identity),
            block_len: 8,
            mac: Box::new(mac::Empty),
            tag_len: 0,
            packet_seq: 0,
            padding_rng: ChaCha8Rng::from_seed(padding_rng_seed.expose()),
        })
    }

    pub fn feed_ident(&mut self, ident: &[u8]) {
        // RFC 4253, section 4.2
        self.buf.reserve(ident.len() + 2);
        self.buf.put_slice(ident);
        self.buf.put_slice(&b"\r\n"[..]);
    }

    pub fn feed_packet(&mut self, payload: &[u8]) -> Result<()> {
        let padding_len = calculate_padding_len(payload.len(), self.block_len);

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

        {
            let packet = &mut self.buf[packet_begin..];
            self.padding_rng.fill_bytes(&mut packet[5 + payload.len()..][..padding_len]);

            let (plaintext, tag) = packet.split_at_mut(5 + payload.len() + padding_len);
            self.mac.sign(self.packet_seq, plaintext, tag)?;

            self.encrypt.encrypt(plaintext)?;
        }

        self.packet_seq = self.packet_seq.wrapping_add(1);

        Ok(())
    }

    pub fn set_cipher(&mut self, encrypt: Box<dyn Encrypt + Send>, block_len: usize) {
        self.encrypt = encrypt;
        self.block_len = block_len;
    }

    pub fn set_mac(&mut self, mac: Box<dyn Mac + Send>, tag_len: usize) {
        self.mac = mac;
        self.tag_len = tag_len;
    }

    pub fn peek_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn consume_bytes(&mut self, len: usize) {
        let _ = self.buf.split_to(len);
    }
}

fn calculate_padding_len(payload_len: usize, block_len: usize) -> usize {
    // RFC 4253, section 6
    let header_len = 5;
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
                let padding_len = calculate_padding_len(payload_len, block_len);
                assert_eq!((5 + payload_len + padding_len) % block_len, 0);
                assert!(padding_len >= 4);
            }
        }
    }
}
