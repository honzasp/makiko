use bytes::Bytes;
use ring::agreement::{
    EphemeralPrivateKey, PublicKey as EphemeralPublicKey,
    UnparsedPublicKey as UnparsedEphemeralPublicKey, X25519, agree_ephemeral,
};
use ring::digest::{SHA256, digest};
use ring::rand::SecureRandom;
use std::task::Poll;
use crate::codec::{PacketDecode, PacketEncode};
use crate::error::{Error, Result};
use crate::numbers::msg;
use super::{KexAlgo, KexInput, KexOutput, Kex};

pub static CURVE25519_SHA256: KexAlgo = KexAlgo {
    name: "curve25519-sha256",
    make_kex: |rng| Ok(Box::new(init_kex(rng)?)),
};

#[derive(Debug)]
struct Curve25519Kex {
    our_eph_privkey: Option<EphemeralPrivateKey>,
    our_eph_pubkey: EphemeralPublicKey,
    ecdh_init_sent: bool,
    ecdh_reply: Option<EcdhReply>,
}

#[derive(Debug)]
struct EcdhReply {
    server_pubkey: Bytes,
    server_eph_pubkey: UnparsedEphemeralPublicKey<Vec<u8>>,
    server_exchange_hash_sign: Bytes,
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

fn init_kex(rng: &mut dyn SecureRandom) -> Result<Curve25519Kex> {
    let our_eph_privkey = EphemeralPrivateKey::generate(&X25519, rng)
        .map_err(|_| Error::Crypto("could not generate X25519 ephemeral private key"))?;
    let our_eph_pubkey = our_eph_privkey.compute_public_key()
        .map_err(|_| Error::Crypto("could not compute X25519 ephemeral public key"))?;
    log::debug!("initialized curve25519 kex");
    Ok(Curve25519Kex {
        our_eph_privkey: Some(our_eph_privkey),
        our_eph_pubkey,
        ecdh_init_sent: false,
        ecdh_reply: None,
    })
}

fn send_ecdh_init(kex: &mut Curve25519Kex) -> Result<Bytes> {
    // RFC 5656, section 4
    let mut payload = PacketEncode::new();
    payload.put_u8(msg::KEX_ECDH_INIT);
    payload.put_bytes(kex.our_eph_pubkey.as_ref());
    log::debug!("sending SSH_MSG_KEX_ECDH_INIT");
    Ok(payload.finish())
}

fn recv_ecdh_reply(kex: &mut Curve25519Kex, payload: &mut PacketDecode) -> Result<()> {
    if kex.ecdh_reply.is_some() {
        return Err(Error::Protocol("received duplicate SSH_MSG_KEX_ECDH_REPLY"))
    }

    // RFC 5656, section 4 and RFC 8731, section 3.1
    let server_pubkey = payload.get_bytes()?;
    let server_eph_pubkey = payload.get_bytes()?;
    let server_exchange_hash_sign = payload.get_bytes()?;

    let server_pubkey = Bytes::copy_from_slice(&server_pubkey);
    let server_eph_pubkey = UnparsedEphemeralPublicKey::new(&X25519, server_eph_pubkey.as_ref().into());
    let server_exchange_hash_sign = Bytes::copy_from_slice(&server_exchange_hash_sign);
    kex.ecdh_reply = Some(EcdhReply { server_pubkey, server_eph_pubkey, server_exchange_hash_sign });
    log::debug!("received SSH_MSG_KEX_ECDH_REPLY");

    Ok(())
}

fn exchange(kex: &mut Curve25519Kex, input: KexInput) -> Result<KexOutput> {
    let our_eph_privkey = kex.our_eph_privkey.take().unwrap();
    let ecdh_reply = kex.ecdh_reply.take().unwrap();
    let EcdhReply { server_pubkey, server_eph_pubkey, server_exchange_hash_sign } = ecdh_reply;

    let shared_secret_be: Vec<u8> = agree_ephemeral(
        our_eph_privkey, &server_eph_pubkey,
        Error::Crypto("could not perform X25519 key agreement"),
        |secret| Ok(secret.into()),
    )?;

    let mut exchange_data = PacketEncode::new();
    exchange_data.put_bytes(input.client_ident);
    exchange_data.put_bytes(input.server_ident);
    exchange_data.put_bytes(input.client_kex_init);
    exchange_data.put_bytes(input.server_kex_init);
    exchange_data.put_bytes(&server_pubkey);
    exchange_data.put_bytes(kex.our_eph_pubkey.as_ref());
    exchange_data.put_bytes(server_eph_pubkey.bytes().as_ref());
    exchange_data.put_mpint_uint_be(&shared_secret_be);
    let exchange_hash = compute_hash(&exchange_data.finish());

    Ok(KexOutput { shared_secret_be, exchange_hash, server_pubkey, server_exchange_hash_sign })
}

fn compute_hash(data: &[u8]) -> Vec<u8> {
    digest(&SHA256, data).as_ref().into()
}
