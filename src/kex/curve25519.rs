use bytes::Bytes;
use num_bigint_dig::BigUint;
use sha2::digest::Digest as _;
use std::task::Poll;
use crate::codec::{PacketDecode, PacketEncode};
use crate::codes::msg;
use crate::error::{Error, Result};
use crate::util::CryptoRngCore;
use super::{KexAlgo, KexInput, KexOutput, Kex};

/// "curve25519-sha256" key exchange from RFC 8731.
pub static CURVE25519_SHA256: KexAlgo = KexAlgo {
    name: "curve25519-sha256",
    make_kex: |rng| Ok(Box::new(init_kex(rng)?)),
};

/// "curve25519-sha256@libssh.org" key exchange (same as ["curve25519-sha256"][CURVE25519_SHA256]).
///
/// The Curve25519 key exchange method was first introduced as a libssh extension (hence the
/// "@libssh.org"). Only later was it standardized in RFC 8731 as "curve25519-sha256" (without the
/// "@" suffix).
pub static CURVE25519_SHA256_LIBSSH: KexAlgo = KexAlgo {
    name: "curve25519-sha256@libssh.org",
    make_kex: |rng| Ok(Box::new(init_kex(rng)?)),
};


struct Curve25519Kex {
    our_eph_privkey: Option<x25519_dalek::EphemeralSecret>,
    our_eph_pubkey: x25519_dalek::PublicKey,
    ecdh_init_sent: bool,
    ecdh_reply: Option<EcdhReply>,
}

#[derive(Debug)]
struct EcdhReply {
    server_pubkey: Bytes,
    server_eph_pubkey: x25519_dalek::PublicKey,
    server_exchange_hash_sign: Bytes,
}

fn init_kex(_rng: &mut dyn CryptoRngCore) -> Result<Curve25519Kex> {
    // x25519-dalek depends on rand 0.7 and also requires an owned rng, so there is no way that we
    // could pass `&mut dyn CryptoRngCore` to `EphemeralSecret::new()`
    let our_eph_privkey = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let our_eph_pubkey = x25519_dalek::PublicKey::from(&our_eph_privkey);
    log::debug!("initialized curve25519 kex");
    Ok(Curve25519Kex {
        our_eph_privkey: Some(our_eph_privkey),
        our_eph_pubkey,
        ecdh_init_sent: false,
        ecdh_reply: None,
    })
}

impl Kex for Curve25519Kex {
    fn recv_packet(&mut self, msg_id: u8, payload: &mut PacketDecode) -> Result<()> {
        match msg_id {
            msg::KEX_ECDH_REPLY => recv_ecdh_reply(self, payload),
            _ => Err(Error::PacketNotImplemented(msg_id)),
        }
    }

    fn send_packet(&mut self) -> Result<Option<Bytes>> {
        if !self.ecdh_init_sent {
            let payload = send_ecdh_init(self)?;
            self.ecdh_init_sent = true;
            return Ok(Some(payload))
        }
        Ok(None)
    }

    fn poll(&mut self, input: KexInput) -> Poll<Result<KexOutput>> {
        if self.our_eph_privkey.is_some() && self.ecdh_reply.is_some() {
            return Poll::Ready(exchange(self, input))
        }
        Poll::Pending
    }

    fn compute_hash(&self, data: &[u8]) -> Vec<u8> {
        compute_hash(data)
    }
}

fn send_ecdh_init(kex: &mut Curve25519Kex) -> Result<Bytes> {
    // RFC 5656, section 4
    let mut payload = PacketEncode::new();
    payload.put_u8(msg::KEX_ECDH_INIT);
    payload.put_bytes(kex.our_eph_pubkey.as_bytes());
    log::debug!("sending SSH_MSG_KEX_ECDH_INIT");
    Ok(payload.finish())
}

fn recv_ecdh_reply(kex: &mut Curve25519Kex, payload: &mut PacketDecode) -> Result<()> {
    if kex.ecdh_reply.is_some() {
        return Err(Error::Protocol("received duplicate SSH_MSG_KEX_ECDH_REPLY"))
    }

    // RFC 5656, section 4 and RFC 8731, section 3.1
    let server_pubkey = payload.get_bytes()?;
    let server_eph_pubkey = payload.get_byte_array::<32>()?;
    let server_exchange_hash_sign = payload.get_bytes()?;

    let server_pubkey = Bytes::copy_from_slice(&server_pubkey);
    let server_eph_pubkey = x25519_dalek::PublicKey::from(server_eph_pubkey);
    let server_exchange_hash_sign = Bytes::copy_from_slice(&server_exchange_hash_sign);
    kex.ecdh_reply = Some(EcdhReply { server_pubkey, server_eph_pubkey, server_exchange_hash_sign });
    log::debug!("received SSH_MSG_KEX_ECDH_REPLY");

    Ok(())
}

fn exchange(kex: &mut Curve25519Kex, input: KexInput) -> Result<KexOutput> {
    let our_eph_privkey = kex.our_eph_privkey.take().unwrap();
    let ecdh_reply = kex.ecdh_reply.take().unwrap();
    let EcdhReply { server_pubkey, server_eph_pubkey, server_exchange_hash_sign } = ecdh_reply;

    let shared_secret = our_eph_privkey.diffie_hellman(&server_eph_pubkey);
    let shared_secret = BigUint::from_bytes_be(shared_secret.as_bytes());

    let mut exchange_data = PacketEncode::new();
    exchange_data.put_bytes(input.client_ident);
    exchange_data.put_bytes(input.server_ident);
    exchange_data.put_bytes(input.client_kex_init);
    exchange_data.put_bytes(input.server_kex_init);
    exchange_data.put_bytes(&server_pubkey);
    exchange_data.put_bytes(kex.our_eph_pubkey.as_bytes());
    exchange_data.put_bytes(server_eph_pubkey.as_bytes());
    exchange_data.put_biguint(&shared_secret);
    let exchange_hash = compute_hash(&exchange_data.finish());

    Ok(KexOutput { shared_secret, exchange_hash, server_pubkey, server_exchange_hash_sign })
}

fn compute_hash(data: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(data).to_vec()
}
