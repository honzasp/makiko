use bytes::{Buf as _, Bytes};
use num_bigint_dig::BigUint;
use std::str;
use crate::{Error, Result};

/// Decoding of SSH packets and other payloads (low level API).
///
/// The format of SSH payloads is described in RFC 4251, section 5. This struct just wraps a
/// [`Bytes`] instance.
#[derive(Debug)]
pub struct PacketDecode {
    orig_buf: Bytes,
    buf: Bytes,
}

impl PacketDecode {
    /// Wraps the bytes into [`PacketDecode`].
    pub fn new(buf: Bytes) -> PacketDecode {
        PacketDecode { orig_buf: buf.clone(), buf }
    }

    /// Decode a `byte`.
    pub fn get_u8(&mut self) -> Result<u8> {
        self.ensure(1)?;
        Ok(self.buf.get_u8())
    }

    /// Decode a `boolean`.
    pub fn get_bool(&mut self) -> Result<bool> {
        self.get_u8().map(|x| x != 0)
    }

    /// Decode a `uint32`.
    pub fn get_u32(&mut self) -> Result<u32> {
        self.ensure(4)?;
        Ok(self.buf.get_u32())
    }

    /// Decode a `string`.
    pub fn get_bytes(&mut self) -> Result<Bytes> {
        let len = self.get_u32()? as usize;
        self.ensure(len)?;
        Ok(self.buf.split_to(len))
    }

    /// Decode a `string` with fixed length.
    pub fn get_byte_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.get_bytes()?;
        if bytes.len() != N {
            return Err(Error::Decode("wrong size of `string`"))
        }

        let mut array = [0; N];
        array.copy_from_slice(&bytes);
        Ok(array)
    }

    /// Decode a `string` in UTF-8.
    pub fn get_string(&mut self) -> Result<String> {
        self.get_bytes().and_then(|x| decode_string(&x))
    }

    /// Decode a `name-list`.
    pub fn get_name_list(&mut self) -> Result<Vec<String>> {
        let list = self.get_string()?;
        if list.is_empty() {
            return Ok(Vec::new())
        }
        Ok(list.split(|x| x == ',').map(|x| x.into()).collect())
    }

    /// Decode a `mpint` as [`BigUint`].
    pub fn get_biguint(&mut self) -> Result<BigUint> {
        self.get_bytes().map(|x| BigUint::from_bytes_be(&x))
    }

    /// Decode a `mpint` as a scalar in unsigned big endian with given length.
    pub fn get_scalar(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut bytes = self.get_bytes()?;
        while bytes.get(0) == Some(&0) {
            bytes.advance(1);
        }

        if bytes.len() > len {
            return Err(Error::Decode("decoded number is too long"));
        }

        let mut digits_be = vec![0; len];
        digits_be[len - bytes.len()..].copy_from_slice(&bytes);
    Ok(digits_be)
    }

    /// Skip `len` bytes.
    pub fn skip(&mut self, len: usize) -> Result<()> {
        self.ensure(len)?;
        Ok(self.buf.advance(len))
    }

    /// Read `len` bytes directly from the buffer.
    pub fn get_raw(&mut self, len: usize) -> Result<Bytes> {
        self.ensure(len)?;
        Ok(self.buf.split_to(len))
    }

    fn ensure(&self, min_remaining: usize) -> Result<()> {
        if min_remaining <= self.buf.remaining() {
            Ok(())
        } else {
            Err(Error::Decode("unexpected end of packet"))
        }
    }

    /// Return a slice of the original bytes given to [`PacketDecode::new()`].
    pub fn as_original_bytes(&self) -> &[u8] {
        &self.orig_buf
    }

    /// Return the remaining undecoded bytes.
    pub fn remaining(&self) -> Bytes {
        self.buf.clone()
    }

    /// Return the number of remainin undecoded bytes.
    pub fn remaining_len(&self) -> usize {
        self.buf.len()
    }
}

fn decode_string(bytes: &[u8]) -> Result<String> {
    match str::from_utf8(bytes) {
        Ok(string) => Ok(string.into()),
        Err(_) => Err(Error::Decode("string is not valid utf-8")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode<D: AsRef<[u8]> + ?Sized>(data: &D) -> PacketDecode {
        PacketDecode::new(b(data))
    }

    fn b<D: AsRef<[u8]> + ?Sized>(data: &D) -> Bytes {
        Bytes::copy_from_slice(data.as_ref())
    }

    #[test]
    fn test_get_uint32() {
        let mut d = decode(&[0,0,0,42, 0xde,0xad,0xbe,0xef]);
        assert_eq!(d.get_u32().unwrap(), 42);
        assert_eq!(d.get_u32().unwrap(), 0xdeadbeef);

        let mut d = decode(&[0xde,0xad]);
        assert!(d.get_u32().is_err());
    }

    #[test]
    fn test_get_bytes() {
        let mut d = decode(&[0,0,0,2, 10,20]);
        assert_eq!(d.get_bytes().unwrap().as_ref(), &[10,20]);

        let mut d = decode(&[0,0,2]);
        assert!(d.get_bytes().is_err());

        let mut d = decode(&[0,0,0,8, 10,20,30]);
        assert!(d.get_bytes().is_err());
    }

    #[test]
    fn test_get_name_list() {
        let mut d = decode(&b"\x00\x00\x00\x00"[..]);
        assert_eq!(d.get_name_list().unwrap(), Vec::<Bytes>::new());

        let mut d = decode(&b"\x00\x00\x00\x04zlib"[..]);
        assert_eq!(d.get_name_list().unwrap(), vec![b("zlib")]);

        let mut d = decode(&b"\x00\x00\x00\x09zlib,none"[..]);
        assert_eq!(d.get_name_list().unwrap(), vec![b("zlib"), b("none")]);

        let mut d = decode(&b"\x00\x00\x00\x05zlib,"[..]);
        assert_eq!(d.get_name_list().unwrap(), vec![b("zlib"), b("")]);

        let mut d = decode(&b"\x00\x00\x00\x05,zlib"[..]);
        assert_eq!(d.get_name_list().unwrap(), vec![b(""), b("zlib")]);
    }
}
