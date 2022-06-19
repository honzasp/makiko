use bytes::{BufMut as _, Bytes, BytesMut};
use num_bigint::BigUint;

/// Encoding of SSH packets and other payloads (low level API).
///
/// The format is described in RFC 4251, section 5. This struct just wraps a [`BytesMut`] instance.
#[derive(Debug, Clone)]
pub struct PacketEncode {
    buf: BytesMut,
}

impl PacketEncode {
    /// Creates an empty [`PacketEncode`].
    pub fn new() -> PacketEncode {
        PacketEncode { buf: BytesMut::new() }
    }

    /// Encode a `byte`.
    pub fn put_u8(&mut self, value: u8) {
        self.buf.put_u8(value);
    }

    /// Encode a `boolean`.
    pub fn put_bool(&mut self, value: bool) {
        self.buf.put_u8(value as u8);
    }

    /// Encode a `uint32`.
    pub fn put_u32(&mut self, value: u32) {
        self.buf.put_u32(value);
    }

    /// Encode a `string`.
    pub fn put_bytes(&mut self, value: &[u8]) {
        self.buf.reserve(4 + value.len());
        self.buf.put_u32(value.len().try_into().expect("string too long"));
        self.buf.put_slice(value);
    }

    /// Encode a `string` in UTF-8.
    pub fn put_str(&mut self, value: &str) {
        self.put_bytes(value.as_bytes())
    }

    /// Encode a `name-list`.
    pub fn put_name_list(&mut self, names: &[&str]) {
        if names.is_empty() {
            self.buf.put_u32(0);
            return;
        }

        let names_len = names.iter().map(|name| name.len()).sum::<usize>() + names.len() - 1;
        self.buf.reserve(4 + names_len);
        self.buf.put_u32(names_len.try_into().expect("name list too long"));

        for (i, name) in names.iter().enumerate() {
            if i != 0 {
                self.buf.put_u8(b',');
            }
            self.buf.put_slice(name.as_bytes());
        }
    }

    /// Encode a `mpint` from a [`BigUint`].
    pub fn put_biguint(&mut self, value: &BigUint) {
        let bytes_vec = value.to_bytes_be();
        let mut bytes = bytes_vec.as_slice();

        while !bytes.is_empty() && bytes[0] == 0 {
            bytes = &bytes[1..];
        }

        if !bytes.is_empty() && bytes[0] >= 0x80 {
            self.buf.put_u32(bytes.len() as u32 + 1);
            self.buf.put_u8(0);
            self.buf.put_slice(bytes);
        } else {
            self.buf.put_u32(bytes.len() as u32);
            self.buf.put_slice(bytes);
        }
    }

    /// Append raw bytes to the buffer.
    pub fn put_raw(&mut self, data: &[u8]) {
        self.buf.put_slice(data);
    }

    /// Unwraps the internal bytes.
    pub fn into_bytes(self) -> BytesMut {
        self.buf
    }

    /// Unwraps and freezes the internal bytes.
    pub fn finish(self) -> Bytes {
        self.buf.freeze()
    }
}

impl Default for PacketEncode {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        let e = PacketEncode::new();
        assert!(e.finish().is_empty());
    }

    #[test]
    fn test_put_uint32() {
        let mut e = PacketEncode::new();
        e.put_u32(10);
        e.put_u32(0xdeadbeef);
        assert_eq!(e.finish().as_ref(), &[0,0,0,10, 0xde,0xad,0xbe,0xef]);
    }

    #[test]
    fn test_put_string() {
        let mut e = PacketEncode::new();
        e.put_bytes(&[]);
        e.put_bytes(&[10, 20, 30]);
        assert_eq!(e.finish().as_ref(), &[0,0,0,0, 0,0,0,3,10,20,30]);
    }

    #[test]
    fn test_put_name_list() {
        fn check(value: &[&str], expected_bytes: &[u8]) {
            let mut e = PacketEncode::new();
            e.put_name_list(value);
            assert_eq!(e.finish().as_ref(), expected_bytes);
        }

        check(&[], &[0,0,0,0]);
        check(&["foo"], &[0,0,0,3, b'f',b'o',b'o']);
        check(&["foo", "bar"], &[0,0,0,7, b'f',b'o',b'o', b',', b'b',b'a',b'r']);
    }

    #[test]
    fn test_put_biguint() {
        fn check(value_be: &[u8], expected_bytes: &[u8]) {
            let mut e = PacketEncode::new();
            e.put_biguint(&BigUint::from_bytes_be(value_be));
            assert_eq!(e.finish().as_ref(), expected_bytes);
        }

        check(&[], &[0,0,0,0]);
        check(&[42], &[0,0,0,1, 42]);
        check(&[10, 20, 30], &[0,0,0,3, 10, 20, 30]);

        check(&[127, 20, 30], &[0,0,0,3, 127, 20, 30]);
        check(&[128, 20, 30], &[0,0,0,4, 0, 128, 20, 30]);

        check(&[0], &[0,0,0,0]);
        check(&[0, 20, 30], &[0,0,0,2, 20, 30]);
        check(&[0, 0, 0, 20, 30], &[0,0,0,2, 20, 30]);
        check(&[0, 200, 30], &[0,0,0,3, 0, 200, 30]);
        check(&[0, 0, 0, 200, 30], &[0,0,0,3, 0, 200, 30]);
    }
}
