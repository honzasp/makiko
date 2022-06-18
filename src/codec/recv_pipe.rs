use bytes::{Bytes, BytesMut};
use crate::{Error, Result};
use crate::cipher::{self, Decrypt};
use crate::mac::{self, Mac, MacVerified};

pub(crate) struct RecvPipe {
    buf: BytesMut,
    state: State,
    decrypt: Box<dyn Decrypt + Send>,
    block_len: usize,
    mac: Box<dyn Mac + Send>,
    tag_len: usize,
    packet_seq: u32,
}

#[derive(Debug, Copy, Clone)]
enum State {
    Ready,
    ScanningLine { pos: usize },
    DecryptedFirst { packet_len: usize },
}

#[derive(Debug)]
pub struct RecvPacket {
    pub payload: Bytes,
    pub packet_seq: u32,
}

impl RecvPipe {
    pub fn new() -> RecvPipe {
        RecvPipe {
            buf: BytesMut::new(),
            state: State::Ready,
            decrypt: Box::new(cipher::Identity),
            block_len: 8,
            mac: Box::new(mac::Empty),
            tag_len: 0,
            packet_seq: 0,
        }
    }

    pub fn feed_buf(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    pub fn consume_ident(&mut self) -> Result<Option<Bytes>> {
        // RFC 4253, section 4.2
        loop {
            let line = match self.consume_line()? {
                Some(line) => line,
                None => return Ok(None),
            };

            if line.starts_with(&b"SSH-"[..]) {
                if line.len() > 255 {
                    return Err(Error::Protocol("received identification string is too long"))
                }
                return Ok(Some(line));
            }
        }
    }

    fn consume_line(&mut self) -> Result<Option<Bytes>> {
        let mut pos = match self.state {
            State::Ready => 0,
            State::ScanningLine { pos } => pos,
            State::DecryptedFirst { .. } =>
                panic!("called consume_ident() after consume_packet() returned None"),
        };

        let mut line_len = None;
        loop {
            if pos >= self.buf.len() {
                break
            } else if self.buf[pos] == b'\r' {
                if pos + 1 >= self.buf.len() {
                    break
                } else if self.buf[pos + 1] == b'\n' {
                    line_len = Some(pos);
                    pos += 2;
                    break;
                }
            } else if self.buf[pos] == b'\n' {
                line_len = Some(pos);
                pos += 1;
                break;
            }

            pos += 1;
        }

        if let Some(line_len) = line_len {
            self.state = State::Ready;
            let mut line = self.buf.split_to(pos).freeze();
            line.truncate(line_len);
            Ok(Some(line))
        } else {
            self.state = State::ScanningLine { pos };
            Ok(None)
        }
    }

    pub fn consume_packet(&mut self) -> Result<Option<RecvPacket>> {
        // RFC 4253, section 6
        if self.buf.len() < self.block_len {
            return Ok(None)
        }

        let packet_len = match self.state {
            State::Ready => {
                self.decrypt.decrypt(&mut self.buf[..self.block_len])?;

                let packet_len = u32::from_be_bytes(self.buf[..4].try_into().unwrap()) as usize;
                let padding_len = self.buf[4] as usize;
                if packet_len > 1024*1024 {
                    return Err(Error::Protocol("invalid packet length (too long, probably invalid)"));
                } else if packet_len < 5 {
                    return Err(Error::Protocol("invalid packet length (too short)"));
                } else if packet_len < 1 + padding_len {
                    return Err(Error::Protocol("invalid packet length (too short for given padding)"));
                } else if (packet_len + 4) % self.block_len != 0 {
                    return Err(Error::Protocol("invalid packet length (not aligned to cipher block length)"));
                }

                log::trace!("decrypted packet len {}", packet_len);
                self.state = State::DecryptedFirst { packet_len };
                packet_len
            },
            State::DecryptedFirst { packet_len } =>
                packet_len,
            State::ScanningLine { .. } =>
                panic!("called consume_packet() after consume_ident() returned None"),
        };

        if self.buf.len() < 4 + packet_len + self.tag_len {
            log::trace!("received only {} bytes", self.buf.len());
            return Ok(None)
        }

        let mut packet = self.buf.split_to(4 + packet_len + self.tag_len);
        self.decrypt.decrypt(&mut packet[self.block_len..(4 + packet_len)])?;
        let packet = packet.freeze();

        let _verified: MacVerified = {
            let plaintext = &packet[..(4 + packet_len)];
            let tag = &packet[(4 + packet_len)..][..self.tag_len];
            self.mac.verify(self.packet_seq, plaintext, tag)?
        };

        let packet_seq = self.packet_seq;
        self.packet_seq = packet_seq.wrapping_add(1);

        let padding_len = packet[4] as usize;
        let payload_len = packet_len - padding_len - 1;
        let payload = packet.slice(5..(5 + payload_len));

        self.state = State::Ready;
        Ok(Some(RecvPacket { payload, packet_seq }))
    }

    pub fn set_cipher(&mut self, decrypt: Box<dyn Decrypt + Send>, block_len: usize) {
        self.decrypt = decrypt;
        self.block_len = block_len;
    }

    pub fn set_mac(&mut self, mac: Box<dyn Mac + Send>, tag_len: usize) {
        self.mac = mac;
        self.tag_len = tag_len;
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng as _, RngCore, SeedableRng as _};
    use super::*;

    #[test]
    fn test_is_send() {
        fn assert_is_send<T: Send>() {}
        assert_is_send::<RecvPipe>()
    }

    fn make_rng() -> Box<dyn RngCore> {
        Box::new(rand_chacha::ChaCha8Rng::seed_from_u64(42))
    }

    fn b<D: AsRef<[u8]> + ?Sized>(data: &D) -> Bytes {
        Bytes::copy_from_slice(data.as_ref())
    }

    fn check_feeding<F0, F1, F2>(
        data: &[u8],
        mut check_prepare: F0,
        mut check_before: F1,
        mut check_after: F2,
    )
        where F0: FnMut(&mut RecvPipe),
              F1: FnMut(&mut RecvPipe),
              F2: FnMut(&mut RecvPipe),
    {
        let mut rng = make_rng();
        for iter in 0..100 {
            let mut data = data;
            let mut pipe = RecvPipe::new();
            check_prepare(&mut pipe);

            while !data.is_empty() {
                check_before(&mut pipe);
                let feed_len = if iter == 0 { 1 } else { rng.gen_range(0, data.len()) + 1 };
                pipe.feed_buf().extend_from_slice(&data[..feed_len]);
                data = &data[feed_len..];
            }

            check_after(&mut pipe);
        }
    }


    fn check_ident<D: AsRef<[u8]>>(data: &D, ident: Option<Bytes>) {
        check_feeding(
            data.as_ref(),
            |_| (), 
            |pipe| assert_eq!(pipe.consume_ident().unwrap(), None),
            |pipe| assert_eq!(pipe.consume_ident().unwrap(), ident.clone()),
        );
    }

    #[test]
    fn test_consume_ident() {
        // ident line terminated with \r\n preceded with some garbage lines
        check_ident(
            b"spam and eggs\nfoo bar\r\nSSH-2.0-dummy\r\n",
            Some(b("SSH-2.0-dummy")),
        );

        // it is ok to end a line with just \n
        check_ident(
            b"spam and eggs\r\nSSH-2.0-dummy\n",
            Some(b("SSH-2.0-dummy")),
        );

        // \r without \n is not a valid line termination
        check_ident(
            b"spam and eggs\r\nSSH-2.0-dummy\rfoo",
            None,
        );
    }


    fn check_packet<D: AsRef<[u8]>>(data: &D, payload: Bytes) {
        check_feeding(
            data.as_ref(),
            |_| (),
            |pipe| assert!(pipe.consume_packet().unwrap().is_none()),
            |pipe| assert_eq!(pipe.consume_packet().unwrap().unwrap().payload, payload),
        );
    }

    fn check_packet_err<D: AsRef<[u8]>>(data: &D, expected_msg: &str) {
        check_feeding(
            data.as_ref(),
            |_| (),
            |pipe| assert!(pipe.consume_packet().unwrap().is_none()),
            |pipe| {
                match pipe.consume_packet() {
                    Err(Error::Protocol(msg)) => assert!(msg.contains(expected_msg)),
                    Err(err) => panic!("unexpected error {:?}", err),
                    Ok(_) => panic!("expected an error"),
                }
            },
        );
    }

    #[test]
    fn test_consume_packet() {
        // packet with 3 bytes of payload and 8 bytes of padding
        check_packet(
            b"\x00\x00\x00\x0c\x08foo01234567",
            b("foo"),
        );

        // packet with 0 bytes of payload and 11 bytes of padding
        check_packet(
            b"\x00\x00\x00\x0c\x0b0123456789a",
            b(""),
        );

        // packet with excessive length
        check_packet_err(
            b"\xde\xad\xbe\xef\x00zzz",
            "too long, probably invalid",
        );

        // packet that is too short
        check_packet_err(
            b"\x00\x00\x00\x03\x00zzz",
            "too short",
        );

        // packet that is too short for given padding length of 32
        check_packet_err(
            b"\x00\x00\x00\x0c\x20zzz",
            "too short for given padding",
        );

        // packet with 3 bytes of payload and 4 bytes of padding, not aligned to 8 byte block
        check_packet_err(
            b"\x00\x00\x00\x08\x04zzz",
            "not aligned",
        );
    }


    fn check_packet_mac<D: AsRef<[u8]>>(data: &D, tag: Bytes) {
        struct DummyMac {
            expected_plaintext: Bytes,
            expected_tag: Bytes,
            verify: bool,
        }

        impl Mac for DummyMac {
            fn sign(&mut self, _: u32, _: &[u8], _: &mut [u8]) -> Result<()> {
                panic!("called Mac::sign()")
            }

            fn verify(&mut self, packet_seq: u32, plaintext: &[u8], tag: &[u8]) -> Result<MacVerified> {
                assert_eq!(packet_seq, 0);
                assert_eq!(plaintext, self.expected_plaintext.as_ref());
                assert_eq!(tag, self.expected_tag.as_ref());
                if self.verify {
                    Ok(MacVerified::assertion())
                } else {
                    Err(Error::Mac)
                }
            }
        }

        let data = data.as_ref();
        let plaintext = Bytes::copy_from_slice(&data[..data.len() - tag.len()]);
        for &verify in &[true, false] {
            check_feeding(
                data.as_ref(),
                |pipe| {
                    let mac = DummyMac {
                        expected_plaintext: plaintext.clone(),
                        expected_tag: tag.clone(),
                        verify,
                    };
                    pipe.set_mac(Box::new(mac), tag.len());
                },
                |pipe| {
                    assert!(pipe.consume_packet().unwrap().is_none());
                },
                |pipe| {
                    if verify {
                        assert!(pipe.consume_packet().is_ok());
                    } else {
                        assert!(pipe.consume_packet().is_err());
                    }
                },
            );
        }
    }

    #[test]
    fn test_consume_packet_mac() {
        check_packet_mac(
            b"\x00\x00\x00\x0c\x08foo01234567magicmac",
            b(b"magicmac"),
        );
    }
}
