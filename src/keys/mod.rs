//! Encoding and decoding of keys.

use crate::error::{Result, Error};
pub use self::openssh::{
    OpensshKeypair, OpensshKeypairNopass,
    decode_openssh_pem_keypair, decode_openssh_binary_keypair,
    decode_openssh_pem_keypair_nopass, decode_openssh_binary_keypair_nopass,
};
pub use self::pkcs1::{
    decode_pkcs1_pem_privkey_nopass, decode_pkcs1_der_privkey,
    decode_pkcs1_pem_pubkey, decode_pkcs1_der_pubkey,
};
pub use self::pkcs8::{
    decode_pkcs8_pem_privkey, decode_pkcs8_der_privkey, decode_pkcs8_encrypted_der_privkey,
};

mod openssh;
mod pkcs1;
mod pkcs8;

fn decode_pem(pem_data: &[u8], expected_tag: &'static str) -> Result<Vec<u8>> {
    let pem = pem::parse(pem_data).map_err(Error::Pem)?;
    if pem.tag != expected_tag {
        return Err(Error::BadPemTag(pem.tag, expected_tag.into()))
    }
    Ok(pem.contents)
}
