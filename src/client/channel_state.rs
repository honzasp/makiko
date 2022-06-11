use bytes::Bytes;
use futures_core::ready;
use guard::guard;
use parking_lot::Mutex;
use std::cmp::min;
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::PollSender;
use crate::codec::{PacketEncode, PacketDecode};
use crate::error::{Result, Error};
use crate::numbers::msg;
use super::negotiate;
use super::channel::{ChannelEvent, ChannelReq, ChannelReply, DataType};
use super::client_state::{self, ClientState};
use super::pump::Pump;
use super::recv::{ResultRecvState, RecvState};

pub(super) struct ChannelInit {
    pub our_id: u32,
    pub their_id: u32,
    pub event_tx: mpsc::Sender<ChannelEvent>,
    pub send_window: usize,
    pub recv_window: usize,
    pub send_len_max: usize,
    pub recv_window_max: usize,
}

pub(super) struct ChannelState {
    our_id: u32,
    their_id: u32,
    want_close: bool,
    close_sent: bool,
    close_recvd: bool,
    closed: bool,
    event_tx: PollSender<ChannelEvent>,
    send_reqs: VecDeque<ChannelReq>,
    send_datas: VecDeque<SendData>,
    recv_replies: VecDeque<RecvReply>,
    send_window: usize,
    recv_window: usize,
    send_len_max: usize,
    recv_window_max: usize,
}

#[derive(Debug)]
struct SendData {
    data: ChannelSendData,
    sent_tx: oneshot::Sender<()>,
}

#[derive(Debug)]
pub(super) enum ChannelSendData {
    Data(Bytes, DataType),
    Eof,
}

#[derive(Debug)]
struct RecvReply {
    reply_tx: oneshot::Sender<ChannelReply>,
}

pub(super) fn init_channel(init: ChannelInit) -> ChannelState {
    ChannelState {
        our_id: init.our_id,
        their_id: init.their_id,
        want_close: false,
        close_sent: false,
        close_recvd: false,
        closed: false,
        event_tx: PollSender::new(init.event_tx),
        send_reqs: VecDeque::new(),
        send_datas: VecDeque::new(),
        recv_replies: VecDeque::new(),
        send_window: init.send_window,
        recv_window: init.recv_window,
        send_len_max: init.send_len_max,
        recv_window_max: init.recv_window_max,
    }
}

pub(super) fn pump_channel(
    st: &mut ClientState,
    channel_st: &mut ChannelState,
    _cx: &mut Context,
) -> Result<Pump> {
    debug_assert!(!channel_st.closed);

    if (channel_st.close_recvd || channel_st.want_close) && !channel_st.close_sent {
        if negotiate::is_ready(st) {
            send_channel_close(st, channel_st)?;
            channel_st.close_sent = true;
            return Ok(Pump::Progress)
        }
    }

    if channel_st.close_recvd && channel_st.close_sent {
        channel_st.closed = true;
        channel_st.send_reqs.clear();
        channel_st.send_datas.clear();
        channel_st.recv_replies.clear();
        return Ok(Pump::Progress)
    }

    if negotiate::is_ready(st) {
        if let Some(req) = channel_st.send_reqs.pop_front() {
            send_channel_request(st, channel_st, &req)?;
            if let Some(reply_tx) = req.reply_tx {
                channel_st.recv_replies.push_back(RecvReply { reply_tx });
            }
            return Ok(Pump::Progress)
        }

        if let Some(mut data) = channel_st.send_datas.pop_front() {
            if send_channel_data(st, channel_st, &mut data.data)? {
                let _ = data.sent_tx.send(());
                return Ok(Pump::Progress)
            } else {
                channel_st.send_datas.push_front(data);
            }
        }

        let recv_window_delta = channel_st.recv_window_max - channel_st.recv_window;
        if recv_window_delta >= channel_st.recv_window_max / 8 {
            send_channel_window_adjust(st, channel_st, recv_window_delta)?;
            channel_st.recv_window += recv_window_delta;
            return Ok(Pump::Progress)
        }
    }

    Ok(Pump::Pending)
}



pub(super) fn send_request(
    st: &mut ClientState,
    channel_st: &mut ChannelState,
    req: ChannelReq,
) -> Result<()> {
    if channel_st.closed {
        return Err(Error::ChannelClosed)
    }
    channel_st.send_reqs.push_back(req);
    client_state::wakeup_client(st);
    Ok(())
}

fn send_channel_request(st: &mut ClientState, channel_st: &ChannelState, req: &ChannelReq) -> Result<()> {
    let mut payload = PacketEncode::new();
    payload.put_u8(msg::CHANNEL_REQUEST);
    payload.put_u32(channel_st.their_id);
    payload.put_str(&req.request_type);
    payload.put_bool(req.reply_tx.is_some());
    payload.put_raw(&req.payload);
    st.codec.send_pipe.feed_packet(&payload.finish())?;
    log::debug!("sending SSH_MSG_CHANNEL_REQUEST {:?} for our channel {}",
        req.request_type, channel_st.our_id);
    Ok(())
}

pub(super) fn recv_channel_success(_st: &mut ClientState, channel_st: &mut ChannelState) -> ResultRecvState {
    guard!{let Some(reply) = channel_st.recv_replies.pop_front() else {
        return Err(Error::Protocol("received SSH_MSG_CHANNEL_SUCCESS, but no reply was expected"))
    }};
    log::debug!("received SSH_MSG_CHANNEL_SUCCESS for our channel {}", channel_st.our_id);
    let _ = reply.reply_tx.send(ChannelReply::Success);
    Ok(None)
}

pub(super) fn recv_channel_failure(_st: &mut ClientState, channel_st: &mut ChannelState) -> ResultRecvState {
    guard!{let Some(reply) = channel_st.recv_replies.pop_front() else {
        return Err(Error::Protocol("received SSH_MSG_CHANNEL_FAILURE, but no reply was expected"))
    }};
    log::debug!("received SSH_MSG_CHANNEL_FAILURE for our channel {}", channel_st.our_id);
    let _ = reply.reply_tx.send(ChannelReply::Failure);
    Ok(None)
}



pub(super) fn send_data(
    st: &mut ClientState,
    channel_st: &mut ChannelState,
    data: ChannelSendData,
) -> Result<impl Future<Output = Result<()>>> {
    if channel_st.closed {
        return Err(Error::ChannelClosed)
    }
    let (sent_tx, sent_rx) = oneshot::channel();
    channel_st.send_datas.push_back(SendData { data, sent_tx });
    client_state::wakeup_client(st);
    Ok(async { sent_rx.await.map_err(|_| Error::ChannelClosed) })
}

fn send_channel_data(st: &mut ClientState, channel_st: &mut ChannelState, data: &mut ChannelSendData) -> Result<bool> {
    match data {
        ChannelSendData::Data(ref mut data, data_type) => {
            if data.is_empty() { return Ok(true) }

            let send_len = min(data.len(), min(channel_st.send_window, channel_st.send_len_max));
            if send_len == 0 { return Ok(false) }
            let send_data = data.split_to(send_len);

            let mut payload = PacketEncode::new();
            match data_type {
                DataType::Standard => {
                    payload.put_u8(msg::CHANNEL_DATA);
                    payload.put_u32(channel_st.their_id);
                    log::trace!("sending SSH_MSG_CHANNEL_DATA for our channel {} with {} bytes",
                        channel_st.our_id, send_data.len());
                },
                DataType::Extended(code) => {
                    payload.put_u8(msg::CHANNEL_EXTENDED_DATA);
                    payload.put_u32(channel_st.their_id);
                    payload.put_u32(*code);
                    log::trace!("sending SSH_MSG_CHANNEL_EXTENDED_DATA for our channel {}, code {}, with {} bytes",
                        channel_st.our_id, code, send_data.len());
                },
            }
            payload.put_bytes(&send_data);
            st.codec.send_pipe.feed_packet(&payload.finish())?;

            channel_st.send_window -= send_len;
            Ok(false)
        },
        ChannelSendData::Eof => {
            let mut payload = PacketEncode::new();
            payload.put_u8(msg::CHANNEL_EOF);
            payload.put_u32(channel_st.their_id);
            st.codec.send_pipe.feed_packet(&payload.finish())?;
            log::debug!("sending SSH_MSG_CHANNEL_EOF for our channel {}", channel_st.our_id);
            Ok(true)
        },
    }
}

pub(super) fn recv_channel_data(
    channel_st: &mut ChannelState,
    channel_mutex: Arc<Mutex<ChannelState>>,
    payload: &mut PacketDecode,
) -> ResultRecvState {
    let data = payload.get_bytes()?;
    if data.len() > channel_st.recv_window {
        return Err(Error::Protocol("received SSH_MSG_CHANNEL_DATA that exceeds window size"))
    }

    log::trace!("received SSH_MSG_CHANNEL_DATA for our channel {} with {} bytes",
        channel_st.our_id, data.len());
    send_event(channel_mutex, ChannelEvent::Data(data, DataType::Standard))
}

pub(super) fn recv_channel_extended_data(
    channel_st: &mut ChannelState,
    channel_mutex: Arc<Mutex<ChannelState>>,
    payload: &mut PacketDecode,
) -> ResultRecvState {
    let code = payload.get_u32()?;
    let data = payload.get_bytes()?;
    if data.len() > channel_st.recv_window {
        return Err(Error::Protocol("received SSH_MSG_CHANNEL_EXTENDED_DATA that exceeds window size"))
    }

    log::trace!("received SSH_MSG_CHANNEL_EXTENDED_DATA for our channel {}, code {}, with {} bytes",
        channel_st.our_id, code, data.len());
    send_event(channel_mutex, ChannelEvent::Data(data, DataType::Extended(code)))
}

pub(super) fn recv_channel_eof(
    channel_st: &mut ChannelState,
    channel_mutex: Arc<Mutex<ChannelState>>,
) -> ResultRecvState {
    log::debug!("received SSH_MSG_CHANNEL_EOF for our channel {}", channel_st.our_id);
    send_event(channel_mutex, ChannelEvent::Eof)
}

fn send_channel_window_adjust(
    st: &mut ClientState,
    channel_st: &mut ChannelState,
    adjust: usize,
) -> Result<()> {
    let mut payload = PacketEncode::new();
    payload.put_u8(msg::CHANNEL_WINDOW_ADJUST);
    payload.put_u32(channel_st.their_id);
    payload.put_u32(adjust as u32);
    st.codec.send_pipe.feed_packet(&payload.finish())?;
    log::trace!("sending SSH_MSG_CHANNEL_WINDOW_ADJUST for our channel {} with {} bytes",
        channel_st.our_id, adjust);
    Ok(())
}

pub(super) fn recv_channel_window_adjust(
    channel_st: &mut ChannelState,
    payload: &mut PacketDecode,
) -> ResultRecvState {
    let adjust = payload.get_u32()? as usize;
    if let Some(send_window) = channel_st.send_window.checked_add(adjust) {
        if send_window <= u32::MAX as usize {
            log::trace!("received SSH_MSG_CHANNEL_WINDOW_ADJUST for our channel {} with {} bytes",
                channel_st.our_id, adjust);
            channel_st.send_window = send_window;
            return Ok(None)
        }
    }
    Err(Error::Protocol("received SSH_MSG_CHANNEL_WINDOW_ADJUST that overflows the send window"))
}



pub(super) fn close(st: &mut ClientState, channel_st: &mut ChannelState) {
    if !channel_st.want_close {
        channel_st.want_close = true;
        client_state::wakeup_client(st);
    }
}

fn send_channel_close(st: &mut ClientState, channel_st: &ChannelState) -> Result<()> {
    let mut payload = PacketEncode::new();
    payload.put_u8(msg::CHANNEL_CLOSE);
    payload.put_u32(channel_st.their_id);
    st.codec.send_pipe.feed_packet(&payload.finish())?;
    log::debug!("sending SSH_MSG_CHANNEL_CLOSE for our channel {}", channel_st.our_id);
    Ok(())
}

pub(super) fn recv_channel_close(channel_st: &mut ChannelState) -> ResultRecvState {
    if channel_st.close_recvd {
        return Err(Error::Protocol("received SSH_MSG_CHANNEL_CLOSE twice"))
    }
    log::debug!("received SSH_MSG_CHANNEL_CLOSE for our channel {}", channel_st.our_id);
    channel_st.close_recvd = true;
    Ok(None)
}

pub(super) fn is_closed(channel_st: &ChannelState) -> bool {
    channel_st.closed
}



fn send_event(channel_mutex: Arc<Mutex<ChannelState>>, event: ChannelEvent) -> ResultRecvState {
    struct SendEventState {
        channel_mutex: Arc<Mutex<ChannelState>>,
        event: Option<ChannelEvent>,
    }

    impl RecvState for SendEventState {
        fn poll(&mut self, _st: &mut ClientState, cx: &mut Context) -> Poll<Result<()>> {
            let mut channel_st = self.channel_mutex.lock();
            let reserve_res = ready!(channel_st.event_tx.poll_reserve(cx));
            let event = self.event.take().unwrap();
            if reserve_res.is_ok() {
                let _ = channel_st.event_tx.send_item(event);
            }
            Poll::Ready(Ok(()))
        }
    }

    Ok(Some(Box::new(SendEventState { channel_mutex, event: Some(event) })))
}
