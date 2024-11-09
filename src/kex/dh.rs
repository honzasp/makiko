use bytes::Bytes;
use derivative::Derivative;
use hex_literal::hex;
use num_bigint_dig::{BigUint, RandBigInt as _};
use std::task::Poll;
use crate::codec::{PacketDecode, PacketEncode};
use crate::codes::msg;
use crate::error::{Error, Result};
use crate::util::CryptoRngCore;
use super::{KexAlgo, KexInput, KexOutput, Kex};

/// "diffie-hellman-group14-sha1" key exchange from RFC 4253.
pub static DIFFIE_HELLMAN_GROUP14_SHA1: KexAlgo = KexAlgo {
    name: "diffie-hellman-group14-sha1",
    make_kex: |rng| Ok(Box::new(init_kex(Group::group_14(), compute_hash_sha1, rng)?)),
};

/// "diffie-hellman-group14-sha256" key exchange from RFC 8268.
pub static DIFFIE_HELLMAN_GROUP14_SHA256: KexAlgo = KexAlgo {
    name: "diffie-hellman-group14-sha256",
    make_kex: |rng| Ok(Box::new(init_kex(Group::group_14(), compute_hash_sha256, rng)?)),
};

/// "diffie-hellman-group16-sha512" key exchange from RFC 8268.
pub static DIFFIE_HELLMAN_GROUP16_SHA512: KexAlgo = KexAlgo {
    name: "diffie-hellman-group16-sha512",
    make_kex: |rng| Ok(Box::new(init_kex(Group::group_16(), compute_hash_sha512, rng)?)),
};

/// "diffie-hellman-group18-sha512" key exchange from RFC 8268.
pub static DIFFIE_HELLMAN_GROUP18_SHA512: KexAlgo = KexAlgo {
    name: "diffie-hellman-group18-sha512",
    make_kex: |rng| Ok(Box::new(init_kex(Group::group_18(), compute_hash_sha512, rng)?)),
};

/// "diffie-hellman-group1-sha1" key exchange from RFC 4253, which SHOULD NOT be implemented
/// according to RFC 9142 and is available only with feature `insecure-crypto`.
///
/// Note that the name refers to "group1", but in fact the key exchange uses group 2.
#[cfg(feature = "insecure-crypto")]
pub static DIFFIE_HELLMAN_GROUP1_SHA1: KexAlgo = KexAlgo {
    name: "diffie-hellman-group1-sha1",
    make_kex: |rng| Ok(Box::new(init_kex(Group::group_2(), compute_hash_sha1, rng)?)),
};


#[derive(Debug)]
struct Group {
    g: BigUint,
    p: BigUint,
    p_minus_1: BigUint,
}

#[derive(Derivative)]
#[derivative(Debug)]
struct DiffieHellmanKex {
    group: Group,
    #[derivative(Debug = "ignore")]
    compute_hash: fn(&[u8]) -> Vec<u8>,
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

fn init_kex(
    group: Group,
    compute_hash: fn(&[u8]) -> Vec<u8>,
    rng: &mut dyn CryptoRngCore,
) -> Result<DiffieHellmanKex> {
    let our_eph_privkey = rng.as_rngcore().gen_biguint_range(&BigUint::from(1u32), &group.p_minus_1);
    let our_eph_pubkey = (group.g).modpow(&our_eph_privkey, &group.p);
    Ok(DiffieHellmanKex {
        group, compute_hash, our_eph_privkey, our_eph_pubkey,
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
        (self.compute_hash)(data)
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
    let exchange_hash = (kex.compute_hash)(&exchange_data.finish());

    Ok(KexOutput { shared_secret, exchange_hash, server_pubkey, server_exchange_hash_sign })
}

fn compute_hash_sha1(data: &[u8]) -> Vec<u8> {
    use sha1::digest::Digest as _;
    sha1::Sha1::digest(data).to_vec()
}

fn compute_hash_sha256(data: &[u8]) -> Vec<u8> {
    use sha2::digest::Digest as _;
    sha2::Sha256::digest(data).to_vec()
}

fn compute_hash_sha512(data: &[u8]) -> Vec<u8> {
    use sha2::digest::Digest as _;
    sha2::Sha512::digest(data).to_vec()
}

impl Group {
    #[cfg(feature = "insecure-crypto")]
    fn group_2() -> Group {
        // RFC 2409, section 6.2
        let g = BigUint::from(2u32);
        let p = BigUint::from_bytes_be(&hex!(
            "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
            "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
            "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
            "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
            "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE65381"
            "FFFFFFFF" "FFFFFFFF"
        ));
        let p_minus_1 = &p - BigUint::from(1u32);
        Group { g, p, p_minus_1 }
    }

    fn group_14() -> Group {
        // RFC 3526, section 3
        let g = BigUint::from(2u32);
        let p = BigUint::from_bytes_be(&hex!(
            "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
            "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
            "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
            "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
            "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
            "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
            "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
            "670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
            "E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
            "DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
            "15728E5A" "8AACAA68" "FFFFFFFF" "FFFFFFFF"
        ));
        let p_minus_1 = &p - BigUint::from(1u32);
        Group { g, p, p_minus_1 }
    }

    fn group_16() -> Group {
        // RFC 3526, section 5
        let g = BigUint::from(2u32);
        let p = BigUint::from_bytes_be(&hex!(
            "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
            "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
            "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
            "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
            "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
            "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
            "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
            "670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
            "E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
            "DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
            "15728E5A" "8AAAC42D" "AD33170D" "04507A33" "A85521AB" "DF1CBA64"
            "ECFB8504" "58DBEF0A" "8AEA7157" "5D060C7D" "B3970F85" "A6E1E4C7"
            "ABF5AE8C" "DB0933D7" "1E8C94E0" "4A25619D" "CEE3D226" "1AD2EE6B"
            "F12FFA06" "D98A0864" "D8760273" "3EC86A64" "521F2B18" "177B200C"
            "BBE11757" "7A615D6C" "770988C0" "BAD946E2" "08E24FA0" "74E5AB31"
            "43DB5BFC" "E0FD108E" "4B82D120" "A9210801" "1A723C12" "A787E6D7"
            "88719A10" "BDBA5B26" "99C32718" "6AF4E23C" "1A946834" "B6150BDA"
            "2583E9CA" "2AD44CE8" "DBBBC2DB" "04DE8EF9" "2E8EFC14" "1FBECAA6"
            "287C5947" "4E6BC05D" "99B2964F" "A090C3A2" "233BA186" "515BE7ED"
            "1F612970" "CEE2D7AF" "B81BDD76" "2170481C" "D0069127" "D5B05AA9"
            "93B4EA98" "8D8FDDC1" "86FFB7DC" "90A6C08F" "4DF435C9" "34063199"
            "FFFFFFFF" "FFFFFFFF"
        ));
        let p_minus_1 = &p - BigUint::from(1u32);
        Group { g, p, p_minus_1 }
    }

    fn group_18() -> Group {
        // RFC 3526, section 7
        let g = BigUint::from(2u32);
        let p = BigUint::from_bytes_be(&hex!(
            "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
            "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
            "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
            "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
            "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
            "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
            "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
            "670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
            "E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
            "DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
            "15728E5A" "8AAAC42D" "AD33170D" "04507A33" "A85521AB" "DF1CBA64"
            "ECFB8504" "58DBEF0A" "8AEA7157" "5D060C7D" "B3970F85" "A6E1E4C7"
            "ABF5AE8C" "DB0933D7" "1E8C94E0" "4A25619D" "CEE3D226" "1AD2EE6B"
            "F12FFA06" "D98A0864" "D8760273" "3EC86A64" "521F2B18" "177B200C"
            "BBE11757" "7A615D6C" "770988C0" "BAD946E2" "08E24FA0" "74E5AB31"
            "43DB5BFC" "E0FD108E" "4B82D120" "A9210801" "1A723C12" "A787E6D7"
            "88719A10" "BDBA5B26" "99C32718" "6AF4E23C" "1A946834" "B6150BDA"
            "2583E9CA" "2AD44CE8" "DBBBC2DB" "04DE8EF9" "2E8EFC14" "1FBECAA6"
            "287C5947" "4E6BC05D" "99B2964F" "A090C3A2" "233BA186" "515BE7ED"
            "1F612970" "CEE2D7AF" "B81BDD76" "2170481C" "D0069127" "D5B05AA9"
            "93B4EA98" "8D8FDDC1" "86FFB7DC" "90A6C08F" "4DF435C9" "34028492"
            "36C3FAB4" "D27C7026" "C1D4DCB2" "602646DE" "C9751E76" "3DBA37BD"
            "F8FF9406" "AD9E530E" "E5DB382F" "413001AE" "B06A53ED" "9027D831"
            "179727B0" "865A8918" "DA3EDBEB" "CF9B14ED" "44CE6CBA" "CED4BB1B"
            "DB7F1447" "E6CC254B" "33205151" "2BD7AF42" "6FB8F401" "378CD2BF"
            "5983CA01" "C64B92EC" "F032EA15" "D1721D03" "F482D7CE" "6E74FEF6"
            "D55E702F" "46980C82" "B5A84031" "900B1C9E" "59E7C97F" "BEC7E8F3"
            "23A97A7E" "36CC88BE" "0F1D45B7" "FF585AC5" "4BD407B2" "2B4154AA"
            "CC8F6D7E" "BF48E1D8" "14CC5ED2" "0F8037E0" "A79715EE" "F29BE328"
            "06A1D58B" "B7C5DA76" "F550AA3D" "8A1FBFF0" "EB19CCB1" "A313D55C"
            "DA56C9EC" "2EF29632" "387FE8D7" "6E3C0468" "043E8F66" "3F4860EE"
            "12BF2D5B" "0B7474D6" "E694F91E" "6DBE1159" "74A3926F" "12FEE5E4"
            "38777CB6" "A932DF8C" "D8BEC4D0" "73B931BA" "3BC832B6" "8D9DD300"
            "741FA7BF" "8AFC47ED" "2576F693" "6BA42466" "3AAB639C" "5AE4F568"
            "3423B474" "2BF1C978" "238F16CB" "E39D652D" "E3FDB8BE" "FC848AD9"
            "22222E04" "A4037C07" "13EB57A8" "1A23F0C7" "3473FC64" "6CEA306B"
            "4BCBC886" "2F8385DD" "FA9D4B7F" "A2C087E8" "79683303" "ED5BDD3A"
            "062B3CF5" "B3A278A6" "6D2A13F8" "3F44F82D" "DF310EE0" "74AB6A36"
            "4597E899" "A0255DC1" "64F31CC5" "0846851D" "F9AB4819" "5DED7EA1"
            "B1D510BD" "7EE74D73" "FAF36BC3" "1ECFA268" "359046F4" "EB879F92"
            "4009438B" "481C6CD7" "889A002E" "D5EE382B" "C9190DA6" "FC026E47"
            "9558E447" "5677E9AA" "9E3050E2" "765694DF" "C81F56E8" "80B96E71"
            "60C980DD" "98EDD3DF" "FFFFFFFF" "FFFFFFFF"
        ));
        let p_minus_1 = &p - BigUint::from(1u32);
        Group { g, p, p_minus_1 }
    }
}
