use bytes::{BufMut as _, Bytes, BytesMut};

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

    /// Encode a `mpint`.
    ///
    /// The integer `value` is represented as unsigned, big-endian slice of bytes.
    pub fn put_mpint_uint_be(&mut self, mut value: &[u8]) {
        // NOTE: this code is not constant time, so we leak some information about `value` via
        // timing. However, the length of the encoded representation is not constant either, so
        // timing is not our main problem!

        while !value.is_empty() && value[0] == 0 {
            value = &value[1..];
        }

        if !value.is_empty() && value[0] >= 0x80 {
            self.buf.put_u32(value.len() as u32 + 1);
            self.buf.put_u8(0);
            self.buf.put_slice(value);
        } else {
            self.buf.put_u32(value.len() as u32);
            self.buf.put_slice(value);
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
        e.put_uint32(10);
        e.put_uint32(0xdeadbeef);
        assert_eq!(e.finish().as_ref(), &[0,0,0,10, 0xde,0xad,0xbe,0xef]);
    }

    #[test]
    fn test_put_string() {
        let mut e = PacketEncode::new();
        e.put_string(&[]);
        e.put_string(&[10, 20, 30]);
        assert_eq!(e.finish().as_ref(), &[0,0,0,0, 0,0,0,3,10,20,30]);
    }

    #[test]
    fn test_put_name_list() {
        let mut e = PacketEncode::new();
        e.put_name_list(&[]);
        assert_eq!(e.finish().as_ref(), &[0,0,0,0]);

        let mut e = PacketEncode::new();
        e.put_name_list(&["foo"]);
        assert_eq!(e.finish().as_ref(), &[0,0,0,3, b'f',b'o',b'o']);

        let mut e = PacketEncode::new();
        e.put_name_list(&["foo", "bar"]);
        assert_eq!(e.finish().as_ref(), &[0,0,0,7, b'f',b'o',b'o', b',', b'b',b'a',b'r']);
    }
}
