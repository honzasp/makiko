use crate::codec::{PacketEncode, PacketDecode};
use crate::codes::msg;
use super::client_state::ClientState;
use super::recv::ResultRecvState;

#[derive(Debug, Default)]
pub(super) struct TheirExtInfo {
    pub auth_pubkey_algo_names: Option<Vec<String>>,
}

pub(super) fn send_ext_info(st: &mut ClientState) {
    // no extensions at the moment!
    let mut payload = PacketEncode::new();
    payload.put_u8(msg::EXT_INFO);
    payload.put_u32(0);
    st.codec.send_pipe.feed_packet(&payload.finish());
    log::debug!("sending SSH_MSG_EXT_INFO");
}

pub(super) fn recv_ext_info(st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    let ext_count = payload.get_u32()?;
    log::debug!("received SSH_MSG_EXT_INFO with {} extensions", ext_count);

    let mut ext_info = TheirExtInfo::default();
    for _ in 0..ext_count {
        let ext_name = payload.get_string()?;
        if ext_name == "server-sig-algs" {
            ext_info.auth_pubkey_algo_names = Some(payload.get_name_list()?);
        } else {
            payload.get_bytes()?;
        }

        log::debug!("received extension {:?}", ext_name);
    }

    st.their_ext_info = ext_info;
    Ok(None)
}
