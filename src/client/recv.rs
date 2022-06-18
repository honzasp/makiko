use futures_core::ready;
use std::task::{Context, Poll};
use crate::codec::{PacketDecode, PacketEncode, RecvPacket};
use crate::codes::msg;
use crate::error::{Error, Result, DisconnectError};
use super::{auth, conn, negotiate};
use super::client_event::{ClientEvent, DebugMsg};
use super::client_state::ClientState;
use super::pump::Pump;

pub(super) trait RecvState {
    fn poll(&mut self, st: &mut ClientState, cx: &mut Context) -> Poll<Result<()>>;
}

pub(super) type ResultRecvState = Result<Option<Box<dyn RecvState + Send>>>;

pub(super) fn pump_recv(st: &mut ClientState, cx: &mut Context) -> Result<Pump> {
    match st.recv_st.take() {
        Some(mut recv_st) => match recv_st.poll(st, cx) {
            Poll::Ready(Ok(())) => Ok(Pump::Progress),
            Poll::Ready(Err(err)) => Err(err),
            Poll::Pending => {
                st.recv_st = Some(recv_st);
                Ok(Pump::Pending)
            },
        },
        None => Ok(Pump::Pending),
    }
}


pub(super) fn recv_packet(st: &mut ClientState, packet: RecvPacket) -> ResultRecvState {
    let mut payload = PacketDecode::new(packet.payload.clone());
    match recv_packet_dispatch(st, &mut payload) {
        Ok(recv_state) => Ok(recv_state),
        Err(Error::PacketNotImplemented(msg_id)) => not_implemented(st, msg_id, &packet),
        Err(err) => Err(err),
    }
}

fn recv_packet_dispatch(st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    let msg_id = payload.get_u8()?;
    log::trace!("received packet {}", msg_id);
    match msg_id {
        msg::DISCONNECT => recv_disconnect(st, payload),
        msg::DEBUG => recv_debug(st, payload),
        msg::UNIMPLEMENTED => recv_unimplemented(st, payload),
        msg::SERVICE_ACCEPT => recv_service_accept(st, payload),
        msg::IGNORE => Ok(None),
        20..=29 => negotiate::recv_negotiate_packet(st, msg_id, payload),
        30..=49 => negotiate::recv_kex_packet(st, msg_id, payload),
        50..=59 => auth::recv_auth_packet(st, msg_id, payload),
        60..=79 => auth::recv_auth_method_packet(st, msg_id, payload),
        80..=127 => conn::recv_conn_packet(st, msg_id, payload),
        _ => Err(Error::PacketNotImplemented(msg_id)),
    }
}

fn recv_disconnect(_: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    let disconnect = DisconnectError {
        reason_code: payload.get_u32()?,
        description: payload.get_string()?,
        description_lang: payload.get_string()?,
    };
    log::debug!("received SSH_MSG_DISCONNECT: {:?}", disconnect);
    Err(Error::PeerDisconnected(disconnect))
}

fn recv_debug(_st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    let debug_msg = DebugMsg {
        always_display: payload.get_bool()?,
        message: payload.get_string()?,
        message_lang: payload.get_string()?,
    };
    send_event(ClientEvent::DebugMsg(debug_msg))
}

fn recv_unimplemented(_st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    let packet_seq = payload.get_u32()?;
    log::debug!("received SSH_MSG_UNIMPLEMENTED for packet seq {}", packet_seq);
    Ok(None)
}

fn recv_service_accept(st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    let service_name = payload.get_string()?;

    if service_name.as_str() == "ssh-userauth" {
        auth::recv_service_accept(st)
    } else {
        log::debug!("received SSH_MSG_SERVICE_ACCEPT for unknown service {:?}", service_name);
        Ok(None)
    }
}

pub(super) fn send_event(event: ClientEvent) -> ResultRecvState {
    struct SendEventState {
        event: Option<ClientEvent>,
    }

    impl RecvState for SendEventState {
        fn poll(&mut self, st: &mut ClientState, cx: &mut Context) -> Poll<Result<()>> {
            let reserve_res = ready!(st.event_tx.poll_reserve(cx));
            let event = self.event.take().unwrap();
            if reserve_res.is_ok() {
                let _ = st.event_tx.send_item(event);
            }
            Poll::Ready(Ok(()))
        }
    }

    Ok(Some(Box::new(SendEventState { event: Some(event) })))
}

fn not_implemented(st: &mut ClientState, msg_id: u8, packet: &RecvPacket) -> ResultRecvState {
    log::debug!("received unimplemented packet {}, seq {}", msg_id, packet.packet_seq);
    let mut reply = PacketEncode::new();
    reply.put_u8(msg::UNIMPLEMENTED);
    reply.put_u32(packet.packet_seq);
    st.codec.send_pipe.feed_packet(&reply.finish())?;
    Ok(None)
}

