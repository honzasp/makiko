use bytes::Bytes;
use guard::guard;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::mem::{drop, replace};
use std::sync::{Arc, Weak};
use std::task::Context;
use tokio::sync::{oneshot, mpsc};
use crate::codec::{PacketEncode, PacketDecode};
use crate::error::{Result, ChannelOpenError, Error};
use crate::numbers::msg;
use super::{auth, negotiate};
use super::channel::ChannelEvent;
use super::channel_state::{self, ChannelState, ChannelInit};
use super::client_state::{self, ClientState};
use super::pump::Pump;
use super::recv::ResultRecvState;

#[derive(Default)]
pub(super) struct ConnState {
    service_requested: bool,
    service_accepted: bool,
    open_channels: VecDeque<OpenChannel>,
    channels: Arc<Mutex<HashMap<u32, ConnChannelState>>>,
}

enum ConnChannelState {
    Open(OpenChannelState),
    Ready(Arc<Mutex<ChannelState>>),
    Closed,
}

struct OpenChannelState {
    our_id: u32,
    open: OpenChannel,
    open_sent: bool,
}

pub(super) struct OpenChannel {
    pub channel_type: String,
    pub recv_window: usize,
    pub recv_window_max: usize,
    pub recv_packet_len_max: usize,
    pub open_payload: Bytes,
    pub confirmed_tx: oneshot::Sender<Result<ConfirmedChannel>>,
}

pub(super) struct ConfirmedChannel {
    pub channel_st: Weak<Mutex<ChannelState>>,
    pub event_rx: mpsc::Receiver<ChannelEvent>,
    pub confirm_payload: Bytes,
}

pub(super) fn init_conn() -> ConnState {
    ConnState::default()
}

pub(super) fn pump_conn(st: &mut ClientState, cx: &mut Context) -> Result<Pump> {
    if !auth::is_authenticated(st) {
        return Ok(Pump::Pending)
    }

    if !st.conn_st.service_requested && negotiate::is_ready(st) {
        send_service_request(st)?;
        st.conn_st.service_requested = true;
        return Ok(Pump::Progress)
    }

    if st.conn_st.service_accepted {
        let channels = st.conn_st.channels.clone();
        let mut channels = channels.lock();
        let mut progress = Pump::Pending;

        while let Some(open) = st.conn_st.open_channels.pop_front() {
            let our_id = alloc_our_id(&channels);
            let open_st = OpenChannelState { our_id, open, open_sent: false };
            channels.insert(our_id, ConnChannelState::Open(open_st));
            progress = Pump::Progress;
        }

        for conn_channel_st in channels.values_mut() {
            while pump_channel(st, conn_channel_st, cx)?.is_progress() { progress = Pump::Progress }
        }

        channels.retain(|_, conn_channel_st| {
            match conn_channel_st {
                ConnChannelState::Closed => false,
                _ => true,
            }
        });

        return Ok(progress)
    }

    Ok(Pump::Pending)
}

fn pump_channel(
    st: &mut ClientState,
    conn_channel_st: &mut ConnChannelState,
    cx: &mut Context,
) -> Result<Pump> {
    let mut progress = Pump::Pending;
    match replace(conn_channel_st, ConnChannelState::Closed) {
        ConnChannelState::Open(mut open_st) => {
            if !open_st.open_sent && negotiate::is_ready(st) {
                send_channel_open(st, &open_st)?;
                open_st.open_sent = true;
                progress = Pump::Progress;
            }
            *conn_channel_st = ConnChannelState::Open(open_st);
        },
        ConnChannelState::Ready(channel_mutex) => {
            let mut channel_st = channel_mutex.lock();
            if !channel_state::is_closed(&channel_st) {
                progress |= channel_state::pump_channel(st, &mut channel_st, cx)?;
                drop(channel_st);
                *conn_channel_st = ConnChannelState::Ready(channel_mutex);
            } else {
                *conn_channel_st = ConnChannelState::Closed;
            }
        },
        ConnChannelState::Closed => {},
    }
    Ok(progress)
}

pub(super) fn recv_conn_packet(
    st: &mut ClientState,
    msg_id: u8,
    payload: &mut PacketDecode,
) -> ResultRecvState {
    match msg_id {
        msg::CHANNEL_OPEN_CONFIRMATION => recv_channel_open_confirmation(st, payload),
        msg::CHANNEL_OPEN_FAILURE => recv_channel_open_failure(st, payload),
        msg::CHANNEL_SUCCESS => recv_channel_success(st, payload),
        msg::CHANNEL_FAILURE => recv_channel_failure(st, payload),
        msg::CHANNEL_REQUEST => recv_channel_request(st, payload),
        msg::CHANNEL_DATA => recv_channel_data(st, payload),
        msg::CHANNEL_EXTENDED_DATA => recv_channel_extended_data(st, payload),
        msg::CHANNEL_WINDOW_ADJUST => recv_channel_window_adjust(st, payload),
        msg::CHANNEL_EOF => recv_channel_eof(st, payload),
        msg::CHANNEL_CLOSE => recv_channel_close(st, payload),
        _ => Err(Error::PacketNotImplemented(msg_id)),
    }
}


pub(super) fn open_channel(st: &mut ClientState, open: OpenChannel) {
    st.conn_st.open_channels.push_back(open);
    client_state::wakeup_client(st);
}

fn alloc_our_id(channels: &HashMap<u32, ConnChannelState>) -> u32 {
    for our_id in 0.. {
        if !channels.contains_key(&our_id) {
            return our_id
        }
    }
    panic!("no free channel ids")
}

fn send_channel_open(st: &mut ClientState, open_st: &OpenChannelState) -> Result<()> {
    let mut payload = PacketEncode::new();
    payload.put_u8(msg::CHANNEL_OPEN);
    payload.put_str(&open_st.open.channel_type);
    payload.put_u32(open_st.our_id);
    payload.put_u32(open_st.open.recv_window as u32);
    payload.put_u32(open_st.open.recv_packet_len_max as u32);
    payload.put_raw(&open_st.open.open_payload);
    st.codec.send_pipe.feed_packet(&payload.finish())?;
    log::debug!("sending SSH_MSG_CHANNEL_OPEN {:?} for our channel {}",
        open_st.open.channel_type, open_st.our_id);
    Ok(())
}

fn recv_channel_open_confirmation(
    st: &mut ClientState,
    payload: &mut PacketDecode,
) -> ResultRecvState {
    let our_id = payload.get_u32()?;
    let their_id = payload.get_u32()?;
    let send_window = payload.get_u32()? as usize;
    let send_packet_len_max = payload.get_u32()? as usize;
    let confirm_payload = payload.remaining();
    
    let mut channels = st.conn_st.channels.lock();
    guard!{let Some(conn_channel_st) = channels.get_mut(&our_id) else {
        return Err(Error::Protocol("received SSH_MSG_CHANNEL_OPEN_CONFIRMATION for unknown channel"));
    }};

    guard!{let ConnChannelState::Open(_) = conn_channel_st else {
        return Err(Error::Protocol("received SSH_MSG_CHANNEL_OPEN_CONFIRMATION \
            for a channel that is not being opened"));
    }};
    guard!{let ConnChannelState::Open(open_st) = replace(conn_channel_st, ConnChannelState::Closed) else {
        unreachable!()
    }};

    if send_packet_len_max < 32000 {
        return Err(Error::Protocol("received SSH_MSG_CHANNEL_OPEN_CONFIRMATION \
            with 'maximum packet size' that is too small"));
    }

    log::debug!("received SSH_MSG_CHANNEL_OPEN_CONFIRMATION for our channel {}", our_id);

    let (event_tx, event_rx) = mpsc::channel(1);
    let channel_init = ChannelInit {
        our_id, their_id, event_tx,
        send_window,
        recv_window: open_st.open.recv_window,
        send_len_max: send_packet_len_max - 100,
        recv_window_max: open_st.open.recv_window_max,
    };

    let channel_st = channel_state::init_channel(channel_init);
    let channel_st = Arc::new(Mutex::new(channel_st));

    let confirmed = ConfirmedChannel {
        channel_st: Arc::downgrade(&channel_st),
        event_rx, confirm_payload,
    };
    let _ = open_st.open.confirmed_tx.send(Ok(confirmed));

    *conn_channel_st = ConnChannelState::Ready(channel_st);
    Ok(None)
}

fn recv_channel_open_failure(
    st: &mut ClientState,
    payload: &mut PacketDecode,
) -> ResultRecvState {
    let our_id = payload.get_u32()?;
    let reason_code = payload.get_u32()?;
    let description = payload.get_string()?;
    let description_lang = payload.get_string()?;
    
    let mut channels = st.conn_st.channels.lock();
    guard!{let Some(conn_channel_st) = channels.get_mut(&our_id) else {
        return Err(Error::Protocol("received SSH_MSG_CHANNEL_OPEN_FAILURE for unknown channel"));
    }};
    guard!{let ConnChannelState::Open(_) = conn_channel_st else {
        return Err(Error::Protocol("received SSH_MSG_CHANNEL_OPEN_FAILURE \
            for a channel that is not being opened"));
    }};
    guard!{let ConnChannelState::Open(open_st) = replace(conn_channel_st, ConnChannelState::Closed) else {
        unreachable!()
    }};

    log::debug!("received SSH_MSG_CHANNEL_OPEN_FAILURE for our channel {}", our_id);

    let error = ChannelOpenError { reason_code, description, description_lang };
    let _ = open_st.open.confirmed_tx.send(Err(Error::ChannelOpen(error)));

    Ok(None)
}



fn recv_channel_success(st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    recv_channel_packet(st, payload,
        |_, channel_st, _| channel_state::recv_channel_success(&mut channel_st.lock()),
        "received SSH_MSG_CHANNEL_SUCCESS for unknown channel",
        "received SSH_MSG_CHANNEL_SUCCESS for a channel that is not ready",
    )
}

fn recv_channel_failure(st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    recv_channel_packet(st, payload,
        |_, channel_st, _| channel_state::recv_channel_failure(&mut channel_st.lock()),
        "received SSH_MSG_CHANNEL_FAILURE for unknown channel",
        "received SSH_MSG_CHANNEL_FAILURE for a channel that is not ready",
    )
}

fn recv_channel_request(st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    recv_channel_packet(st, payload,
        |_, channel_st, payload|
            channel_state::recv_channel_request(&mut channel_st.lock(), channel_st.clone(), payload),
        "received SSH_MSG_CHANNEL_REQUEST for unknown channel",
        "received SSH_MSG_CHANNEL_REQUEST for a channel that is not ready",
    )
}

fn recv_channel_data(st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    recv_channel_packet(st, payload,
        |_, channel_st, payload|
            channel_state::recv_channel_data(&mut channel_st.lock(), channel_st.clone(), payload),
        "received SSH_MSG_CHANNEL_DATA for unknown channel",
        "received SSH_MSG_CHANNEL_DATA for a channel that is not ready",
    )
}

fn recv_channel_extended_data(st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    recv_channel_packet(st, payload,
        |_, channel_st, payload|
            channel_state::recv_channel_extended_data(&mut channel_st.lock(), channel_st.clone(), payload),
        "received SSH_MSG_CHANNEL_EXTENDED_DATA for unknown channel",
        "received SSH_MSG_CHANNEL_EXTENDED_DATA for a channel that is not ready",
    )
}

fn recv_channel_eof(st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    recv_channel_packet(st, payload,
        |_, channel_st, _|
            channel_state::recv_channel_eof(&mut channel_st.lock(), channel_st.clone()),
        "received SSH_MSG_CHANNEL_EOF for unknown channel",
        "received SSH_MSG_CHANNEL_EOF for a channel that is not ready",
    )
}

fn recv_channel_window_adjust(st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    recv_channel_packet(st, payload,
        |_, channel_st, payload| channel_state::recv_channel_window_adjust(&mut channel_st.lock(), payload),
        "received SSH_MSG_CHANNEL_WINDOW_ADJUST for unknown channel",
        "received SSH_MSG_CHANNEL_WINDOW_ADJUST for a channel that is not ready",
    )
}

fn recv_channel_close(st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    recv_channel_packet(st, payload,
        |_, channel_st, _| channel_state::recv_channel_close(&mut channel_st.lock()),
        "received SSH_MSG_CHANNEL_CLOSE for unknown channel",
        "received SSH_MSG_CHANNEL_CLOSE for a channel that is not ready",
    )
}

fn recv_channel_packet<F>(
    st: &mut ClientState,
    payload: &mut PacketDecode,
    callback: F,
    unknown_err: &'static str,
    not_ready_err: &'static str,
) -> ResultRecvState
    where F: Fn(&mut ClientState, &Arc<Mutex<ChannelState>>, &mut PacketDecode) -> ResultRecvState
{
    let our_id = payload.get_u32()?;

    let channels = st.conn_st.channels.clone();
    let mut channels = channels.lock();
    guard!{let Some(conn_channel_st) = channels.get_mut(&our_id) else {
        return Err(Error::Protocol(unknown_err));
    }};
    guard!{let ConnChannelState::Ready(channel_st) = conn_channel_st else {
        return Err(Error::Protocol(not_ready_err));
    }};

    callback(st, channel_st, payload)
}



fn send_service_request(st: &mut ClientState) -> Result<()> {
    let mut payload = PacketEncode::new();
    payload.put_u8(msg::SERVICE_REQUEST);
    payload.put_str("ssh-connection");
    st.codec.send_pipe.feed_packet(&payload.finish())?;
    log::debug!("sending SSH_MSG_SERVICE_REQUEST for 'ssh-connection'");
    Ok(())
}

pub(super) fn recv_service_accept(st: &mut ClientState) -> ResultRecvState {
    log::debug!("received SSH_MSG_SERVICE_ACCEPT for 'ssh-connection'");
    st.conn_st.service_accepted = true;
    Ok(None)
}
