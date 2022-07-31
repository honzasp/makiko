use bytes::Bytes;
use guard::guard;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::future::Future as _;
use std::mem::{drop, replace};
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use tokio::sync::{oneshot, mpsc};
use crate::codec::{PacketEncode, PacketDecode};
use crate::codes::{msg, open};
use crate::error::{Result, ChannelOpenError, Error};
use super::{auth, negotiate, recv};
use super::channel::ChannelEvent;
use super::channel_state::{self, ChannelState, ChannelInit};
use super::client::{GlobalReq, GlobalReply};
use super::client_event::{AcceptChannel, ClientEvent};
use super::client_state::{self, ClientState};
use super::pump::Pump;
use super::recv::ResultRecvState;

#[derive(Default)]
pub(super) struct ConnState {
    open_channels: VecDeque<OpenChannel>,
    channels: Arc<Mutex<HashMap<u32, ConnChannelState>>>,
    send_reqs: VecDeque<GlobalReq>,
    recv_replies: VecDeque<RecvReply>,
}

enum ConnChannelState {
    Open(OpenChannelState),
    Accept(AcceptChannelState),
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
    pub recv_window_max: usize,
    pub recv_packet_len_max: usize,
    pub open_payload: Bytes,
    pub result_tx: oneshot::Sender<Result<OpenChannelResult>>,
}

pub(super) struct OpenChannelResult {
    pub channel_st: Weak<Mutex<ChannelState>>,
    pub event_rx: mpsc::Receiver<ChannelEvent>,
    pub confirm_payload: Bytes,
}

struct ConfirmChannel {
    their_id: u32,
    send_window: usize,
    send_packet_len_max: usize,
    confirm_payload: Bytes,
}

struct AcceptChannelState {
    our_id: u32,
    their_id: u32,
    send_window: usize,
    send_packet_len_max: usize,
    accepted_rx: oneshot::Receiver<Result<AcceptedChannel, ChannelOpenError>>,
}

pub(super) struct AcceptedChannel {
    pub recv_window_max: usize,
    pub recv_packet_len_max: usize,
    pub confirm_payload: Bytes,
    pub result_tx: oneshot::Sender<AcceptedChannelResult>,
}

pub(super) struct AcceptedChannelResult {
    pub channel_st: Weak<Mutex<ChannelState>>,
    pub event_rx: mpsc::Receiver<ChannelEvent>,
}

#[derive(Debug)]
struct RecvReply {
    reply_tx: oneshot::Sender<GlobalReply>,
}


pub(super) fn init_conn() -> ConnState {
    ConnState::default()
}

pub(super) fn pump_conn(st: &mut ClientState, cx: &mut Context) -> Result<Pump> {
    if !auth::is_authenticated(st) {
        return Ok(Pump::Pending)
    }

    if negotiate::is_ready(st) {
        if let Some(req) = st.conn_st.send_reqs.pop_front() {
            send_global_request(st, &req);
            if let Some(reply_tx) = req.reply_tx {
                st.conn_st.recv_replies.push_back(RecvReply { reply_tx });
            }
            return Ok(Pump::Progress)
        }
    }

    pump_channels(st, cx)
}

fn pump_channels(st: &mut ClientState, cx: &mut Context) -> Result<Pump> {
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
        while pump_channel(st, conn_channel_st, cx)?.is_progress() {
            progress = Pump::Progress
        }
    }

    channels.retain(|_, conn_channel_st| {
        !matches!(conn_channel_st, ConnChannelState::Closed)
    });

    Ok(progress)
}

fn pump_channel(
    st: &mut ClientState,
    conn_channel_st: &mut ConnChannelState,
    cx: &mut Context,
) -> Result<Pump> {
    let mut progress = Pump::Pending;
    // NOTE: we move out of `*conn_channel_st` here to make the borrow checker happy, remember to
    // restore the state when necessary!
    match replace(conn_channel_st, ConnChannelState::Closed) {
        ConnChannelState::Open(mut open_st) => {
            if !open_st.open_sent && negotiate::is_ready(st) {
                send_channel_open(st, &open_st);
                open_st.open_sent = true;
                progress = Pump::Progress;
            }
            *conn_channel_st = ConnChannelState::Open(open_st);
        },
        ConnChannelState::Accept(mut accept_st) => {
            match Pin::new(&mut accept_st.accepted_rx).poll(cx) {
                Poll::Ready(Ok(Ok(accepted))) => {
                    send_channel_open_confirmation(st, &accept_st, &accepted);
                    *conn_channel_st = init_accepted_channel(accept_st, accepted);
                    progress = Pump::Progress;
                },
                Poll::Ready(Ok(Err(open_err))) => {
                    send_channel_open_failure(st, &accept_st, Some(open_err));
                },
                Poll::Ready(Err(_)) => {
                    send_channel_open_failure(st, &accept_st, None);
                },
                Poll::Pending => {
                    *conn_channel_st = ConnChannelState::Accept(accept_st);
                },
            }
        },
        ConnChannelState::Ready(channel_mutex) => {
            let mut channel_st = channel_mutex.lock();
            if !channel_state::is_closed(&channel_st) {
                progress |= channel_state::pump_channel(st, &mut channel_st, cx)?;
                drop(channel_st);
                *conn_channel_st = ConnChannelState::Ready(channel_mutex);
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
        msg::REQUEST_SUCCESS => recv_request_success(st, payload),
        msg::REQUEST_FAILURE => recv_request_failure(st),
        msg::CHANNEL_OPEN => recv_channel_open(st, payload),
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

fn send_channel_open(st: &mut ClientState, open_st: &OpenChannelState) {
    let mut payload = PacketEncode::new();
    payload.put_u8(msg::CHANNEL_OPEN);
    payload.put_str(&open_st.open.channel_type);
    payload.put_u32(open_st.our_id);
    payload.put_u32(open_st.open.recv_window_max as u32);
    payload.put_u32(open_st.open.recv_packet_len_max as u32);
    payload.put_raw(&open_st.open.open_payload);
    st.codec.send_pipe.feed_packet(&payload.finish());
    log::debug!("sending SSH_MSG_CHANNEL_OPEN {:?} for our channel {}",
        open_st.open.channel_type, open_st.our_id);
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
    
    log::debug!("received SSH_MSG_CHANNEL_OPEN_CONFIRMATION for our channel {}, \
        window {}, max packet size {}", our_id, send_window, send_packet_len_max);

    let mut channels = st.conn_st.channels.lock();
    guard!{let Some(conn_channel_st) = channels.get_mut(&our_id) else {
        return Err(Error::Protocol("received SSH_MSG_CHANNEL_OPEN_CONFIRMATION for unknown channel"));
    }};

    guard!{let ConnChannelState::Open(_) = conn_channel_st else {
        return Err(Error::Protocol("received SSH_MSG_CHANNEL_OPEN_CONFIRMATION \
            for a channel that is not being opened"));
    }};
    // use `replace()` only after we are sure that `*conn_channel_st` is `Open`
    guard!{let ConnChannelState::Open(open_st) = replace(conn_channel_st, ConnChannelState::Closed) else {
        unreachable!()
    }};

    let confirm = ConfirmChannel { their_id, send_window, send_packet_len_max, confirm_payload };
    *conn_channel_st = init_confirmed_channel(open_st, confirm);
    Ok(None)
}

fn init_confirmed_channel(
    open_st: OpenChannelState,
    confirm: ConfirmChannel,
) -> ConnChannelState {
    let (event_tx, event_rx) = mpsc::channel(1);
    let channel_init = ChannelInit {
        our_id: open_st.our_id,
        their_id: confirm.their_id,
        event_tx,
        send_window: confirm.send_window,
        send_len_max: packet_len_max_to_len_max(confirm.send_packet_len_max),
        recv_window_max: open_st.open.recv_window_max,
    };

    let channel_st = channel_state::init_channel(channel_init);
    let channel_st = Arc::new(Mutex::new(channel_st));

    let result = OpenChannelResult {
        channel_st: Arc::downgrade(&channel_st),
        event_rx,
        confirm_payload: confirm.confirm_payload,
    };
    let _: Result<_, _> = open_st.open.result_tx.send(Ok(result));

    ConnChannelState::Ready(channel_st)
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
    // use `replace()` only after we are sure that `*conn_channel_st` is `Open`
    guard!{let ConnChannelState::Open(open_st) = replace(conn_channel_st, ConnChannelState::Closed) else {
        unreachable!()
    }};

    log::debug!("received SSH_MSG_CHANNEL_OPEN_FAILURE for our channel {}", our_id);

    let error = ChannelOpenError { reason_code, description, description_lang };
    let _: Result<_, _> = open_st.open.result_tx.send(Err(Error::ChannelOpen(error)));

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



fn recv_channel_open(st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    let channel_type = payload.get_string()?;
    let their_id = payload.get_u32()?;
    let send_window = payload.get_u32()? as usize;
    let send_packet_len_max = payload.get_u32()? as usize;
    let open_payload = payload.remaining();

    let mut channels = st.conn_st.channels.lock();
    let our_id = alloc_our_id(&channels);
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let accept_st = AcceptChannelState { our_id, their_id, send_window, send_packet_len_max, accepted_rx };
    channels.insert(our_id, ConnChannelState::Accept(accept_st));

    log::debug!("received SSH_MSG_CHANNEL_OPEN {:?} for our channel {}, their channel {}",
        channel_type, our_id, their_id);

    let accept_channel = AcceptChannel {
        // we don't have a `Weak<Mutex<ClientState>>` handy, but `ClientReceiver` will set it
        // before returning this event to the user
        client_st: None,
        channel_type,
        open_payload,
        accepted_tx,
    };

    drop(channels);
    client_state::wakeup_client(st);
    recv::send_event(ClientEvent::Channel(accept_channel))
}

fn init_accepted_channel(
    accept_st: AcceptChannelState,
    accepted: AcceptedChannel,
) -> ConnChannelState {
    let (event_tx, event_rx) = mpsc::channel(1);
    let channel_init = ChannelInit {
        our_id: accept_st.our_id,
        their_id: accept_st.their_id,
        event_tx,
        send_window: accept_st.send_window,
        send_len_max: packet_len_max_to_len_max(accept_st.send_packet_len_max),
        recv_window_max: accepted.recv_window_max,
    };

    let channel_st = channel_state::init_channel(channel_init);
    let channel_st = Arc::new(Mutex::new(channel_st));

    let _: Result<_, _> = accepted.result_tx.send(AcceptedChannelResult {
        channel_st: Arc::downgrade(&channel_st),
        event_rx,
    });

    ConnChannelState::Ready(channel_st)
}

fn send_channel_open_confirmation(
    st: &mut ClientState,
    accept_st: &AcceptChannelState,
    accepted: &AcceptedChannel,
) {
    let mut payload = PacketEncode::new();
    payload.put_u8(msg::CHANNEL_OPEN_CONFIRMATION);
    payload.put_u32(accept_st.their_id);
    payload.put_u32(accept_st.our_id);
    payload.put_u32(accepted.recv_window_max as u32);
    payload.put_u32(accepted.recv_packet_len_max as u32);
    payload.put_raw(&accepted.confirm_payload);
    st.codec.send_pipe.feed_packet(&payload.finish());
    log::debug!("sending SSH_MSG_CHANNEL_OPEN_CONFIRMATION for our channel {}", accept_st.our_id);
}

fn send_channel_open_failure(
    st: &mut ClientState,
    accept_st: &AcceptChannelState,
    open_err: Option<ChannelOpenError>,
) {
    let open_err = open_err.unwrap_or_else(|| {
        ChannelOpenError {
            reason_code: open::ADMINISTRATIVELY_PROHIBITED,
            description: "administratively prohibited".into(),
            description_lang: "".into(),
        }
    });

    let mut payload = PacketEncode::new();
    payload.put_u8(msg::CHANNEL_OPEN_FAILURE);
    payload.put_u32(accept_st.their_id);
    payload.put_u32(open_err.reason_code);
    payload.put_str(&open_err.description);
    payload.put_str(&open_err.description_lang);
    st.codec.send_pipe.feed_packet(&payload.finish());
    log::debug!("sending SSH_MSG_CHANNEL_OPEN_FAILURE for our channel {}, reason: {}",
        accept_st.our_id, open::to_str(open_err.reason_code).unwrap_or("unknown"));
}



pub(super) fn send_request(st: &mut ClientState, req: GlobalReq) -> Result<()> {
    st.conn_st.send_reqs.push_back(req);
    client_state::wakeup_client(st);
    Ok(())
}

fn send_global_request(st: &mut ClientState, req: &GlobalReq) {
    let mut payload = PacketEncode::new();
    payload.put_u8(msg::GLOBAL_REQUEST);
    payload.put_str(&req.request_type);
    payload.put_bool(req.reply_tx.is_some());
    payload.put_raw(&req.payload);
    st.codec.send_pipe.feed_packet(&payload.finish());
    log::debug!("sending SSH_MSG_GLOBAL_REQUEST {:?}", req.request_type);
}

fn recv_request_success(st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    guard!{let Some(reply) = st.conn_st.recv_replies.pop_front() else {
        return Err(Error::Protocol("received SSH_MSG_REQUEST_SUCCESS, but no reply was expected"))
    }};
    log::debug!("received SSH_MSG_REQUEST_SUCCESS");
    let payload = payload.remaining();
    let _: Result<_, _> = reply.reply_tx.send(GlobalReply::Success(payload));
    Ok(None)
}

fn recv_request_failure(st: &mut ClientState) -> ResultRecvState {
    guard!{let Some(reply) = st.conn_st.recv_replies.pop_front() else {
        return Err(Error::Protocol("received SSH_MSG_REQUEST_FAILURE, but no reply was expected"))
    }};
    log::debug!("received SSH_MSG_REQUEST_FAILURE");
    let _: Result<_, _> = reply.reply_tx.send(GlobalReply::Failure);
    Ok(None)
}



fn packet_len_max_to_len_max(packet_len_max: usize) -> usize {
    // the SSH specification is unclear about the exact semantics of the 'maximum packet size'
    // field in SSH_MSG_CHANNEL_OPEN and SSH_MSG_CHANNEL_OPEN_CONFIRMATION. does it limit only the
    // size of the data? size of the data plus the length field? size of the whole packet payload?
    // size of the packet including padding? including MAC tag? including the "packet length"
    // field?
    //
    // for this reason, we are conservative and limit the size of data chunks that we send to a
    // lower value than given by the peer.
    usize::max(packet_len_max, 200) - 100
}
