use bytes::Bytes;
use digest::Digest as _;
use num_bigint::{BigUint, RandBigInt as _};
use sha1::Sha1;
use std::task::Poll;
use crate::codec::{PacketDecode, PacketEncode};
use crate::codes::msg;
use crate::error::{Error, Result};
use crate::util::CryptoRngCore;
use super::{KexAlgo, KexInput, KexOutput, Kex};

/// "diffie-hellman-group14-sha1" key exchange from RFC 4253.
pub static DIFFIE_HELLMAN_GROUP14_SHA1: KexAlgo = KexAlgo {
    name: "diffie-hellman-group14-sha1",
    make_kex: |rng| Ok(Box::new(init_kex(Group::group_14(), rng)?)),
};

#[derive(Debug)]
struct Group {
    g: BigUint,
    p: BigUint,
    p_minus_1: BigUint,
}

#[derive(Debug)]
struct DiffieHellmanKex {
    group: Group,
    our_eph_privkey: BigUint,
    our_eph_pubkey: BigUint,
    kexdh_init_sent: bool,
    kexdh_reply: Option<KexdhReply>,
}

#[derive(Debug)]
struct KexdhReply {
    server_pubkey: Bytes,
    server_eph_pubkey: BigUint,
    server_exchange_hash_sign: Bytes,
}

fn init_kex(group: Group, rng: &mut dyn CryptoRngCore) -> Result<DiffieHellmanKex> {
    let our_eph_privkey = rng.as_rngcore().gen_biguint_range(&BigUint::from(1u32), &group.p_minus_1);
    let our_eph_pubkey = (group.g).modpow(&our_eph_privkey, &group.p);
    Ok(DiffieHellmanKex {
        group, our_eph_privkey, our_eph_pubkey,
        kexdh_init_sent: false,
        kexdh_reply: None,
    })
}

impl Kex for DiffieHellmanKex {
    fn recv_packet(&mut self, msg_id: u8, payload: &mut PacketDecode) -> Result<()> {
        match msg_id {
            msg::KEXDH_REPLY => recv_kexdh_reply(self, payload),
            _ => Err(Error::PacketNotImplemented(msg_id)),
        }
    }

    fn send_packet(&mut self) -> Result<Option<Bytes>> {
        if !self.kexdh_init_sent {
            let payload = send_kexdh_init(self)?;
            self.kexdh_init_sent = true;
            return Ok(Some(payload))
        }
        Ok(None)
    }

    fn poll(&mut self, input: KexInput) -> Poll<Result<KexOutput>> {
        if self.kexdh_reply.is_some() {
            return Poll::Ready(exchange(self, input))
        }
        Poll::Pending
    }

    fn compute_hash(&self, data: &[u8]) -> Vec<u8> {
        compute_hash(data)
    }
}

fn send_kexdh_init(kex: &mut DiffieHellmanKex) -> Result<Bytes> {
    // RFC 4253, section 8
    let mut payload = PacketEncode::new();
    payload.put_u8(msg::KEXDH_INIT);
    payload.put_biguint(&kex.our_eph_pubkey);
    log::debug!("sending SSH_MSG_KEXDH_INIT");
    Ok(payload.finish())
}

fn recv_kexdh_reply(kex: &mut DiffieHellmanKex, payload: &mut PacketDecode) -> Result<()> {
    if kex.kexdh_reply.is_some() {
        return Err(Error::Protocol("received duplicate SSH_MSG_KEXDH_REPLY"))
    }

    // RFC 4253, section 8
    let server_pubkey = payload.get_bytes()?;
    let server_eph_pubkey = payload.get_biguint()?;
    let server_exchange_hash_sign = payload.get_bytes()?;

    // RFC 8268, section 4
    if server_eph_pubkey <= BigUint::from(1u32) || server_eph_pubkey >= kex.group.p_minus_1 {
        return Err(Error::Protocol("server sent invalid Diffie-Hellman ephemeral public key"))
    }

    let server_pubkey = Bytes::copy_from_slice(&server_pubkey);
    let server_exchange_hash_sign = Bytes::copy_from_slice(&server_exchange_hash_sign);
    kex.kexdh_reply = Some(KexdhReply { server_pubkey, server_eph_pubkey, server_exchange_hash_sign });
    log::debug!("received SSH_MSG_KEXDH_REPLY");

    Ok(())
}

fn exchange(kex: &mut DiffieHellmanKex, input: KexInput) -> Result<KexOutput> {
    let kexdh_reply = kex.kexdh_reply.take().unwrap();
    let KexdhReply { server_pubkey, server_eph_pubkey, server_exchange_hash_sign } = kexdh_reply;

    let shared_secret = (server_eph_pubkey).modpow(&kex.our_eph_privkey, &kex.group.p);

    let mut exchange_data = PacketEncode::new();
    exchange_data.put_bytes(input.client_ident);
    exchange_data.put_bytes(input.server_ident);
    exchange_data.put_bytes(input.client_kex_init);
    exchange_data.put_bytes(input.server_kex_init);
    exchange_data.put_bytes(&server_pubkey);
    exchange_data.put_biguint(&kex.our_eph_pubkey);
    exchange_data.put_biguint(&server_eph_pubkey);
    exchange_data.put_biguint(&shared_secret);
    let exchange_hash = compute_hash(&exchange_data.finish());

    Ok(KexOutput { shared_secret, exchange_hash, server_pubkey, server_exchange_hash_sign })
}

fn compute_hash(data: &[u8]) -> Vec<u8> {
    Sha1::digest(data).to_vec()
}

impl Group {
    fn group_14() -> Group {
        // RFC 3526, section 3
        let g = BigUint::from(2u32);
        let p = BigUint::parse_bytes(concat![
            "FFFFFFFF", "FFFFFFFF", "C90FDAA2", "2168C234", "C4C6628B", "80DC1CD1",
            "29024E08", "8A67CC74", "020BBEA6", "3B139B22", "514A0879", "8E3404DD",
            "EF9519B3", "CD3A431B", "302B0A6D", "F25F1437", "4FE1356D", "6D51C245",
            "E485B576", "625E7EC6", "F44C42E9", "A637ED6B", "0BFF5CB6", "F406B7ED",
            "EE386BFB", "5A899FA5", "AE9F2411", "7C4B1FE6", "49286651", "ECE45B3D",
            "C2007CB8", "A163BF05", "98DA4836", "1C55D39A", "69163FA8", "FD24CF5F",
            "83655D23", "DCA3AD96", "1C62F356", "208552BB", "9ED52907", "7096966D",
            "670C354E", "4ABC9804", "F1746C08", "CA18217C", "32905E46", "2E36CE3B",
            "E39E772C", "180E8603", "9B2783A2", "EC07A28F", "B5C55DF0", "6F4C52C9",
            "DE2BCBF6", "95581718", "3995497C", "EA956AE5", "15D22618", "98FA0510",
            "15728E5A", "8AACAA68", "FFFFFFFF", "FFFFFFFF",
        ].as_bytes(), 16).unwrap();
        let p_minus_1 = &p - BigUint::from(1u32);
        Group { g, p, p_minus_1 }
    }
}
