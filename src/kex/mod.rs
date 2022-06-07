use bytes::Bytes;
use ring::rand::SecureRandom;
use std::task::Poll;
use crate::Result;
use crate::codec::PacketDecode;
pub use self::curve25519::CURVE25519_SHA256;

mod curve25519;

pub struct KexAlgo {
    pub name: &'static str,
    pub make_kex: fn(rng: &mut dyn SecureRandom) -> Result<Box<dyn Kex + Send>>,
}

#[derive(Debug)]
pub struct KexInput<'a> {
    pub client_ident: &'a [u8],
    pub server_ident: &'a [u8],
    pub client_kex_init: &'a [u8],
    pub server_kex_init: &'a [u8],
}

pub struct KexOutput {
    pub shared_secret_be: Vec<u8>,
    pub exchange_hash: Vec<u8>,
    pub server_pubkey: Bytes,
    pub server_exchange_hash_sign: Bytes,
}

pub trait Kex {
    fn recv_packet(&mut self, msg_id: u8, payload: &mut PacketDecode) -> Result<()>;
    fn send_packet(&mut self) -> Result<Option<Bytes>>;
    fn poll(&mut self, input: KexInput) -> Poll<Result<KexOutput>>;
    fn compute_hash(&self, data: &[u8]) -> Vec<u8>;
}
