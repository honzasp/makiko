use bytes::Bytes;
use std::future::Future as _;
use std::pin::Pin;
use std::task::Context;
use tokio::sync::oneshot;
use crate::error::{Error, Result, AlgoNegotiateError};
use crate::cipher::{self, CipherAlgo};
use crate::codec::{PacketEncode, PacketDecode};
use crate::codes::msg;
use crate::kex::{self, Kex, KexAlgo, KexInput, KexOutput};
use crate::mac::{self, MacAlgo};
use crate::pubkey::{self, PubkeyAlgo, SignatureVerified};
use super::client_event::{ClientEvent, AcceptPubkeySender, PubkeyAccepted};
use super::client_state::ClientState;
use super::pump::Pump;
use super::recv::ResultRecvState;

#[derive(Default)]
pub(super) struct NegotiateState {
    state: State,
    our_kex_init: Option<OurKexInit>,
    their_kex_init: Option<TheirKexInit>,
    algos: Option<Algos>,
    kex: Option<Box<dyn Kex + Send>>,
    kex_output: Option<KexOutput>,
    signature_verified: Option<SignatureVerified>,
    pubkey_event: Option<ClientEvent>,
    accept_rx: Option<oneshot::Receiver<Result<PubkeyAccepted>>>,
    pubkey_accepted: Option<PubkeyAccepted>,
    new_keys_sent: bool,
    new_keys_recvd: bool,
}

#[derive(Debug, Copy, Clone)]
enum State {
    Idle,
    KexInit,
    Kex,
    AcceptPubkey,
    NewKeys,
    Done,
}

struct OurKexInit {
    payload: Bytes,
    kex_algos: Vec<&'static KexAlgo>,
    server_pubkey_algos: Vec<&'static PubkeyAlgo>,
    cipher_algos_cts: Vec<&'static CipherAlgo>,
    cipher_algos_stc: Vec<&'static CipherAlgo>,
    mac_algos_cts: Vec<&'static MacAlgo>,
    mac_algos_stc: Vec<&'static MacAlgo>,
}

#[derive(Debug)]
struct TheirKexInit {
    payload: Bytes,
    kex_algos: Vec<String>,
    server_pubkey_algos: Vec<String>,
    cipher_algos_cts: Vec<String>,
    cipher_algos_stc: Vec<String>,
    mac_algos_cts: Vec<String>,
    mac_algos_stc: Vec<String>,
}

struct Algos {
    kex: &'static KexAlgo,
    server_pubkey: &'static PubkeyAlgo,
    cipher_cts: &'static CipherAlgo,
    cipher_stc: &'static CipherAlgo,
    mac_cts: &'static MacAlgo,
    mac_stc: &'static MacAlgo,
}

pub(super) fn init_negotiate() -> NegotiateState {
    NegotiateState { state: State::KexInit, .. NegotiateState::default() }
}

impl Default for State {
    fn default() -> Self { State::Idle }
}

pub(super) fn pump_negotiate(st: &mut ClientState, cx: &mut Context) -> Result<Pump> {
    match st.negotiate_st.state {
        State::Idle => {},
        State::KexInit => {
            if st.negotiate_st.our_kex_init.is_none() {
                st.negotiate_st.our_kex_init = Some(send_kex_init(st)?);
            }

            if st.negotiate_st.our_kex_init.is_some() && st.negotiate_st.their_kex_init.is_some() {
                st.negotiate_st.algos = Some(negotiate_algos(st)?);
                let kex_algo = st.negotiate_st.algos.as_ref().unwrap().kex;
                st.negotiate_st.kex = Some((kex_algo.make_kex)(&mut *st.rng)?);
                st.negotiate_st.state = State::Kex;
                return Ok(Pump::Progress)
            }
        },
        State::Kex => {
            if let Some(payload) = st.negotiate_st.kex.as_mut().unwrap().send_packet()? {
                st.codec.send_pipe.feed_packet(&payload)?;
                return Ok(Pump::Progress)
            }

            let kex_input = KexInput {
                client_ident: &st.our_ident,
                server_ident: st.their_ident.as_ref().unwrap(),
                client_kex_init: &st.negotiate_st.our_kex_init.as_ref().unwrap().payload,
                server_kex_init: &st.negotiate_st.their_kex_init.as_ref().unwrap().payload,
            };
            let kex_output = pump_ready!(st.negotiate_st.kex.as_mut().unwrap().poll(kex_input))?;
            log::debug!("finished kex");

            if st.session_id.is_none() {
                st.session_id = Some(kex_output.exchange_hash.clone());
            }

            let pubkey_algo = st.negotiate_st.algos.as_ref().unwrap().server_pubkey;
            let pubkey = (pubkey_algo.decode_pubkey)(kex_output.server_pubkey.clone())?;
            log::debug!("server pubkey {}", pubkey);

            let signature_verified = pubkey.verify(
                &kex_output.exchange_hash, kex_output.server_exchange_hash_sign.clone())?;
            st.negotiate_st.signature_verified = Some(signature_verified);
            st.negotiate_st.kex_output = Some(kex_output);

            let (accept_tx, accept_rx) = oneshot::channel();
            let accept_tx = AcceptPubkeySender { accept_tx };
            st.negotiate_st.pubkey_event = Some(ClientEvent::ServerPubkey(pubkey, accept_tx));
            st.negotiate_st.accept_rx = Some(accept_rx);
            st.negotiate_st.state = State::AcceptPubkey;
            return Ok(Pump::Progress)
        },
        State::AcceptPubkey => {
            if st.negotiate_st.pubkey_event.is_some() {
                let reserve_res = pump_ready!(st.event_tx.poll_reserve(cx));
                let pubkey_event = st.negotiate_st.pubkey_event.take().unwrap();
                if reserve_res.is_ok() {
                    let _ = st.event_tx.send_item(pubkey_event);
                }
            }

            let accepted = pump_ready!(Pin::new(st.negotiate_st.accept_rx.as_mut().unwrap()).poll(cx))
                .map_err(|err| Error::PubkeyAccept(Box::new(err)))??;
            log::debug!("server pubkey was accepted");
            st.negotiate_st.pubkey_accepted = Some(accepted);
            st.negotiate_st.state = State::NewKeys;
            return Ok(Pump::Progress)
        },
        State::NewKeys => {
            assert!(st.negotiate_st.signature_verified.is_some());
            assert!(st.negotiate_st.pubkey_accepted.is_some());

            if !st.negotiate_st.new_keys_sent {
                send_new_keys(st)?;
                st.negotiate_st.new_keys_sent = true;
                return Ok(Pump::Progress)
            }

            if st.negotiate_st.new_keys_sent && st.negotiate_st.new_keys_recvd {
                st.negotiate_st.state = State::Done;
                return Ok(Pump::Progress)
            }
        },
        State::Done => {
            st.negotiate_st = Box::new(NegotiateState::default());
            return Ok(Pump::Progress)
        },
    }
    Ok(Pump::Pending)
}

pub(super) fn recv_negotiate_packet(
    st: &mut ClientState,
    msg_id: u8,
    payload: &mut PacketDecode,
) -> ResultRecvState {
    match msg_id {
        msg::KEXINIT => recv_kex_init(st, payload),
        msg::NEWKEYS => recv_new_keys(st, payload),
        _ => Err(Error::PacketNotImplemented(msg_id)),
    }
}

pub(super) fn recv_kex_packet(
    st: &mut ClientState,
    msg_id: u8,
    payload: &mut PacketDecode,
) -> ResultRecvState {
    if let Some(kex) = st.negotiate_st.kex.as_mut() {
        kex.recv_packet(msg_id, payload)?;
        Ok(None)
    } else {
        Err(Error::Protocol("received unexpected kex message"))
    }
}

fn send_kex_init(st: &mut ClientState) -> Result<OurKexInit> {
    let kex_algos = vec![&kex::CURVE25519_SHA256];
    let server_pubkey_algos = vec![&pubkey::SSH_ED25519, &pubkey::SSH_RSA];
    let cipher_algos = vec![&cipher::AES128_CTR];
    let mac_algos = vec![&mac::HMAC_SHA2_256];

    let mut cookie = [0; 16];
    st.rng.fill(&mut cookie).map_err(|_| Error::Random("could not generate random cookie"))?;

    fn get_algo_names<A: NamedAlgo>(algos: &[&A]) -> Vec<&'static str> {
        algos.iter().map(|algo| algo.name()).collect()
    }

    // RFC 4253, section 7.1
    let mut payload = PacketEncode::new();
    payload.put_u8(msg::KEXINIT);
    payload.put_raw(&cookie);
    payload.put_name_list(&get_algo_names(&kex_algos));
    payload.put_name_list(&get_algo_names(&server_pubkey_algos));
    payload.put_name_list(&get_algo_names(&cipher_algos));
    payload.put_name_list(&get_algo_names(&cipher_algos));
    payload.put_name_list(&get_algo_names(&mac_algos));
    payload.put_name_list(&get_algo_names(&mac_algos));
    payload.put_name_list(&["none"]);
    payload.put_name_list(&["none"]);
    payload.put_name_list(&[]);
    payload.put_name_list(&[]);
    payload.put_bool(false);
    payload.put_u32(0);
    let payload = payload.finish();
    st.codec.send_pipe.feed_packet(&payload)?;

    log::debug!("sending SSH_MSG_KEXINIT");

    Ok(OurKexInit {
        payload,
        kex_algos,
        server_pubkey_algos,
        cipher_algos_cts: cipher_algos.clone(),
        cipher_algos_stc: cipher_algos,
        mac_algos_cts: mac_algos.clone(),
        mac_algos_stc: mac_algos,
    })
}

fn recv_kex_init(st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    // RFC 4253, section 7.1
    payload.skip(16)?; // cookie
    let kex_algos = payload.get_name_list()?; // kex_algorithms
    let server_pubkey_algos = payload.get_name_list()?; // server_host_key_algorithms
    let cipher_algos_cts = payload.get_name_list()?; // encryption_algorithms_client_to_server
    let cipher_algos_stc = payload.get_name_list()?; // encryption_algorithms_server_to_client
    let mac_algos_cts = payload.get_name_list()?; // mac_algorithms_client_to_server
    let mac_algos_stc = payload.get_name_list()?; // mac_algorithms_server_to_client
    payload.get_name_list()?; // compression_algorithms_client_to_server
    payload.get_name_list()?; // compression_algorithms_server_to_client
    payload.get_name_list()?; // languages_client_to_server
    payload.get_name_list()?; // languages_server_to_client
    let first_kex_packet_follows = payload.get_bool()?; // first_kex_packet_follows
    payload.get_u32()?; // reserved

    if first_kex_packet_follows {
        return Err(Error::Protocol("received SSH_MSG_KEXINIT with first_kex_packet_follows set"))
    }

    let kex_init = TheirKexInit {
        payload: Bytes::copy_from_slice(payload.as_original_bytes()),
        kex_algos,
        server_pubkey_algos,
        cipher_algos_cts,
        cipher_algos_stc,
        mac_algos_cts,
        mac_algos_stc,
    };
    log::debug!("received SSH_MSG_KEXINIT: {:?}", kex_init);

    match st.negotiate_st.state {
        State::Idle | State::KexInit if st.negotiate_st.their_kex_init.is_none() => {
            st.negotiate_st.their_kex_init = Some(kex_init);
            st.negotiate_st.state = State::KexInit;
            Ok(None)
        },
        _ => Err(Error::Protocol("received SSH_MSG_KEXINIT during negotiation")),
    }
}

fn negotiate_algos(st: &ClientState) -> Result<Algos> {
    fn negotiate_algo<A: NamedAlgo>(
        our_algos: &[&'static A],
        their_algos: &[String],
        name: &'static str,
    ) -> Result<&'static A> {
        for our_algo in our_algos.iter() {
            for their_algo in their_algos.iter() {
                if our_algo.name() == their_algo.as_str() {
                    log::debug!("negotiated algo {:?} for {}", their_algo, name);
                    return Ok(our_algo)
                }
            }
        }

        Err(Error::AlgoNegotiate(AlgoNegotiateError {
            algo_name: name.into(),
            our_algos: our_algos.iter().map(|a| a.name().into()).collect(),
            their_algos: their_algos.into(),
        }))
    }

    let our = st.negotiate_st.our_kex_init.as_ref().unwrap();
    let their = st.negotiate_st.their_kex_init.as_ref().unwrap();

    let kex = negotiate_algo(&our.kex_algos, &their.kex_algos, "key exchange")?;
    let server_pubkey = negotiate_algo(
        &our.server_pubkey_algos, &their.server_pubkey_algos, "server public key")?;
    let cipher_cts = negotiate_algo(
        &our.cipher_algos_cts, &their.cipher_algos_cts, "cipher client-to-server")?;
    let cipher_stc = negotiate_algo(
        &our.cipher_algos_stc, &their.cipher_algos_stc, "cipher server-to-client")?;
    let mac_cts = negotiate_algo(
        &our.mac_algos_cts, &their.mac_algos_cts, "mac client-to-server")?;
    let mac_stc = negotiate_algo(
        &our.mac_algos_stc, &their.mac_algos_stc, "mac server-to-client")?;

    Ok(Algos { kex, server_pubkey, cipher_cts, cipher_stc, mac_cts, mac_stc })
}

trait NamedAlgo { fn name(&self) -> &'static str; }
impl NamedAlgo for KexAlgo { fn name(&self) -> &'static str { self.name } }
impl NamedAlgo for CipherAlgo { fn name(&self) -> &'static str { self.name } }
impl NamedAlgo for MacAlgo { fn name(&self) -> &'static str { self.name } }
impl NamedAlgo for PubkeyAlgo { fn name(&self) -> &'static str { self.name } }

fn recv_new_keys(st: &mut ClientState, _payload: &mut PacketDecode) -> ResultRecvState {
    match st.negotiate_st.state {
        State::Kex | State::AcceptPubkey | State::NewKeys => {
            if st.negotiate_st.new_keys_recvd {
                return Err(Error::Protocol("received SSH_MSG_NEWKEYS twice"))
            }
        },
        _ => return Err(Error::Protocol("received unexpected SSH_MSG_NEWKEYS")),
    }

    let algos = st.negotiate_st.algos.as_ref().unwrap();

    let cipher_algo = algos.cipher_stc;
    let cipher_key = derive_key(st, b'D', cipher_algo.key_len)?;
    let cipher_iv = derive_key(st, b'B', cipher_algo.iv_len)?;
    let decrypt = (cipher_algo.make_decrypt)(&cipher_key, &cipher_iv);
    st.codec.recv_pipe.set_cipher(decrypt, cipher_algo.block_len);

    let mac_algo = algos.mac_stc;
    let mac_key = derive_key(st, b'F', mac_algo.key_len)?;
    let mac = (mac_algo.make_mac)(&mac_key);
    st.codec.recv_pipe.set_mac(mac, mac_algo.tag_len);

    log::debug!("received SSH_MSG_NEWKEYS and applied new keys");
    st.negotiate_st.new_keys_recvd = true;
    Ok(None)
}

fn send_new_keys(st: &mut ClientState) -> Result<()> {
    let algos = st.negotiate_st.algos.as_ref().unwrap();

    let cipher_algo = algos.cipher_cts;
    let cipher_key = derive_key(st, b'C', cipher_algo.key_len)?;
    let cipher_iv = derive_key(st, b'A', cipher_algo.iv_len)?;
    let encrypt = (cipher_algo.make_encrypt)(&cipher_key, &cipher_iv);

    let mac_algo = algos.mac_cts;
    let mac_key = derive_key(st, b'E', mac_algo.key_len)?;
    let mac = (mac_algo.make_mac)(&mac_key);

    let mut payload = PacketEncode::new();
    payload.put_u8(msg::NEWKEYS);
    st.codec.send_pipe.feed_packet(&payload.finish())?;

    st.codec.send_pipe.set_cipher(encrypt, cipher_algo.block_len);
    st.codec.send_pipe.set_mac(mac, mac_algo.tag_len);
    log::debug!("sent SSH_MSG_NEWKEYS and applied new keys");

    Ok(())
}

fn derive_key(st: &ClientState, key_type: u8, key_len: usize) -> Result<Vec<u8>> {
    // RFC 4253, section 7.2

    let kex = st.negotiate_st.kex.as_deref().unwrap();
    let kex_output = st.negotiate_st.kex_output.as_ref().unwrap();
    let session_id = st.session_id.as_ref().unwrap();

    let mut to_hash_prefix = PacketEncode::new();
    to_hash_prefix.put_mpint_uint_be(&kex_output.shared_secret_be);
    to_hash_prefix.put_raw(&kex_output.exchange_hash);
    
    let mut key = {
        let mut to_hash = to_hash_prefix.clone();
        to_hash.put_u8(key_type);
        to_hash.put_raw(session_id);
        kex.compute_hash(&to_hash.finish())
    };

    while key.len() < key_len {
        let mut to_hash = to_hash_prefix.clone();
        to_hash.put_raw(&key);
        key.extend_from_slice(&kex.compute_hash(&to_hash.finish()));
    }

    key.truncate(key_len);
    Ok(key)
}

pub(super) fn is_ready(st: &ClientState) -> bool {
    matches!(st.negotiate_st.state, State::Idle)
}
