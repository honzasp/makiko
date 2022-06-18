//! Key exchange algorithms.
//!
//! The SSH protocol supports several key exchange (kex) algorithms, which are used to establish
//! the one-time keys used for message [encryption][crate::cipher] and
//! [authentication][crate::mac].
//!
//! The client and the server exchange lists of supported algorithms, and the first algorithm on
//! the client's list that is also supported by the server is used for the connection.
//!
//! # Supported algorithms
//!
//! - "curve25519-sha256" / "curve25519-sha256@libssh.com" ([`CURVE25519_SHA256`] /
//! [`CURVE25519_SHA256_LIBSSH`])
use bytes::Bytes;
use derivative::Derivative;
use std::task::Poll;
use crate::Result;
use crate::codec::PacketDecode;
use crate::util::CryptoRngCore;
pub use self::curve25519::{CURVE25519_SHA256, CURVE25519_SHA256_LIBSSH};

mod curve25519;

/// Algorithm for key exchange.
///
/// See the [module documentation][self] for details.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct KexAlgo {
    /// Name of the algorithm.
    pub name: &'static str,
    #[derivative(Debug = "ignore")]
    pub(crate) make_kex: fn(rng: &mut dyn CryptoRngCore) -> Result<Box<dyn Kex + Send>>,
}

#[derive(Debug)]
pub(crate) struct KexInput<'a> {
    pub client_ident: &'a [u8],
    pub server_ident: &'a [u8],
    pub client_kex_init: &'a [u8],
    pub server_kex_init: &'a [u8],
}

pub(crate) struct KexOutput {
    pub shared_secret_be: Vec<u8>,
    pub exchange_hash: Vec<u8>,
    pub server_pubkey: Bytes,
    pub server_exchange_hash_sign: Bytes,
}

pub(crate) trait Kex {
    fn recv_packet(&mut self, msg_id: u8, payload: &mut PacketDecode) -> Result<()>;
    fn send_packet(&mut self) -> Result<Option<Bytes>>;
    fn poll(&mut self, input: KexInput) -> Poll<Result<KexOutput>>;
    fn compute_hash(&self, data: &[u8]) -> Vec<u8>;
}
