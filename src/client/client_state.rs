use bytes::Bytes;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use crate::codec::{Codec, RecvPipe, SendPipe, PacketEncode};
use crate::codes::msg;
use crate::error::{Error, Result, DisconnectError};
use crate::util::{self, AsyncReadWrite, CryptoRngCore};
use super::auth::{self, AuthState};
use super::client::ClientConfig;
use super::client_event::ClientEvent;
use super::conn::{self, ConnState};
use super::ext::TheirExtInfo;
use super::negotiate::{self, NegotiateState, LastKex};
use super::pump::Pump;
use super::recv::{self, RecvState};

pub(super) struct ClientState {
    pub config: ClientConfig,

    pub codec: Codec,
    pub recv_st: Option<Box<dyn RecvState + Send>>,
    pub negotiate_st: Box<NegotiateState>,
    pub auth_st: Box<AuthState>,
    pub conn_st: Box<ConnState>,
    pub rng: Box<dyn CryptoRngCore + Send>,

    pub event_tx: PollSender<ClientEvent>,
    waker: Option<Waker>,

    pub our_ident: Bytes,
    pub their_ident: Option<Bytes>,
    our_disconnect: Option<DisconnectError>,
    disconnect_sent: bool,
    pub session_id: Option<Vec<u8>>,
    pub last_kex: LastKex,
    pub their_ext_info: TheirExtInfo,
}

pub(super) fn new_client(
    mut config: ClientConfig,
    mut rng: Box<dyn CryptoRngCore + Send>,
    event_tx: mpsc::Sender<ClientEvent>,
) -> Result<ClientState> {
    sanitize_config(&mut config);
    let mut send_pipe = SendPipe::new(&mut *rng)?;
    let our_ident: Bytes = "SSH-2.0-makiko".into();
    send_pipe.feed_ident(&our_ident);

    Ok(ClientState {
        config,
        codec: Codec {
            recv_pipe: RecvPipe::new(),
            send_pipe,
        },
        recv_st: None,
        negotiate_st: Box::new(negotiate::init_negotiate()),
        auth_st: Box::new(auth::init_auth()),
        conn_st: Box::new(conn::init_conn()),
        rng,
        event_tx: PollSender::new(event_tx),
        waker: None,
        our_ident,
        their_ident: None,
        our_disconnect: None,
        disconnect_sent: false,
        session_id: None,
        last_kex: negotiate::init_last_kex(),
        their_ext_info: TheirExtInfo::default(),
    })
}

pub(super) fn poll_client(
    st: &mut ClientState,
    mut stream: Pin<&mut dyn AsyncReadWrite>,
    cx: &mut Context,
) -> Poll<Result<()>> {
    if st.our_disconnect.is_some() && !st.disconnect_sent {
        let error = st.our_disconnect.take().unwrap();
        send_disconnect(st, error);
        st.disconnect_sent = true;
    }

    loop {
        let mut progress = false;

        if !st.disconnect_sent {
            while recv::pump_recv(st, cx)?.is_progress() { progress = true }
            while negotiate::pump_negotiate(st, cx)?.is_progress() { progress = true }
            while auth::pump_auth(st, cx)?.is_progress() { progress = true }
            while conn::pump_conn(st, cx)?.is_progress() { progress = true }

            if pump_read(st, stream.as_mut(), cx)?.is_progress() { continue }
        }

        while pump_write(st, stream.as_mut(), cx)?.is_progress() { progress = true }

        if !progress { break }
    }

    let flushed = flush_write(st, stream.as_mut(), cx)?;
    if st.disconnect_sent && flushed {
        return Poll::Ready(Ok(()))
    }

    st.waker = Some(cx.waker().clone());
    Poll::Pending
}

pub(super) fn wakeup_client(st: &mut ClientState) {
    if let Some(waker) = st.waker.take() {
        waker.wake();
    }
}

fn pump_read(
    st: &mut ClientState,
    stream: Pin<&mut dyn AsyncReadWrite>,
    cx: &mut Context,
) -> Result<Pump> {
    if st.their_ident.is_some() {
        pump_read_packet(st, stream, cx)
    } else {
        pump_read_ident(st, stream, cx)
    }
}

fn pump_read_packet(
    st: &mut ClientState,
    mut stream: Pin<&mut dyn AsyncReadWrite>,
    cx: &mut Context,
) -> Result<Pump> {
    if st.recv_st.is_some() {
        return Ok(Pump::Pending)
    }

    let packet = pump_ready!(poll_read(st, stream.as_mut(), cx, |pipe| pipe.consume_packet()))?;
    st.recv_st = recv::recv_packet(st, packet)?;
    Ok(Pump::Progress)
}

fn pump_read_ident(
    st: &mut ClientState,
    mut stream: Pin<&mut dyn AsyncReadWrite>,
    cx: &mut Context,
) -> Result<Pump> {
    let ident = pump_ready!(poll_read(st, stream.as_mut(), cx, |pipe| pipe.consume_ident()))?;

    // the returned `Bytes` reference the internal buffer in `st.codec.recv_pipe`, so we
    // copy the data into a new `Bytes` to avoid keeping this reference in `ClientState`
    let ident = Bytes::copy_from_slice(&ident);
    log::debug!("received peer identifier: {:?}", ident);
    st.their_ident = Some(ident);

    Ok(Pump::Progress)
}

fn pump_write(
    st: &mut ClientState,
    mut stream: Pin<&mut dyn AsyncReadWrite>,
    cx: &mut Context,
) -> Result<Pump> {
    let data = st.codec.send_pipe.peek_bytes();
    if data.is_empty() { return Ok(Pump::Pending) }
    match stream.as_mut().poll_write(cx, data) {
        Poll::Ready(Ok(0)) | Poll::Pending => {
            log::trace!("pending write of {} bytes", data.len());
            Ok(Pump::Pending)
        },
        Poll::Ready(Ok(written_len)) => {
            log::trace!("written {}/{} bytes", written_len, data.len());
            st.codec.send_pipe.consume_bytes(written_len);
            Ok(Pump::Progress)
        },
        Poll::Ready(Err(err)) => {
            log::debug!("error when writing: {}", err);
            Err(Error::WriteIo(err))
        },
    }
}

fn flush_write(
    st: &mut ClientState,
    stream: Pin<&mut dyn AsyncReadWrite>,
    cx: &mut Context,
) -> Result<bool> {
    match stream.poll_flush(cx) {
        Poll::Ready(Ok(())) => Ok(st.codec.send_pipe.is_empty()),
        Poll::Pending => Ok(false),
        Poll::Ready(Err(err)) => Err(Error::WriteIo(err)),
    }
}

fn poll_read<F, T>(
    st: &mut ClientState,
    mut stream: Pin<&mut dyn AsyncReadWrite>,
    cx: &mut Context,
    consume_f: F
) -> Poll<Result<T>>
    where F: Fn(&mut RecvPipe) -> Result<Option<T>>
{
    loop {
        if let Some(value) = consume_f(&mut st.codec.recv_pipe)? {
            return Poll::Ready(Ok(value))
        }

        match util::poll_read_buf(stream.as_mut(), cx, st.codec.recv_pipe.feed_buf()) {
            Poll::Pending => {
                log::trace!("pending read");
                return Poll::Pending
            },
            Poll::Ready(Ok(0)) => {
                log::debug!("received eof");
                return Poll::Ready(Err(Error::PeerClosed))
            },
            Poll::Ready(Ok(read_len)) => {
                log::trace!("read {} bytes", read_len);
                continue
            },
            Poll::Ready(Err(err)) => {
                log::debug!("error when reading: {}", err);
                return Poll::Ready(Err(Error::ReadIo(err)))
            },
        }
    }
}



pub(super) fn disconnect(st: &mut ClientState, error: DisconnectError) -> Result<()> {
    if !st.disconnect_sent && st.our_disconnect.is_none() {
        st.our_disconnect = Some(error);
        wakeup_client(st);
        Ok(())
    } else {
        Err(Error::ClientDisconnected)
    }
}

fn send_disconnect(st: &mut ClientState, error: DisconnectError) {
    let mut payload = PacketEncode::new();
    payload.put_u8(msg::DISCONNECT);
    payload.put_u32(error.reason_code);
    payload.put_str(&error.description);
    payload.put_str(&error.description_lang);
    st.codec.send_pipe.feed_packet(&payload.finish());
    log::debug!("sending SSH_MSG_DISCONNECT with reason code {}", error.reason_code);
}

fn sanitize_config(config: &mut ClientConfig) {
    config.rekey_after_bytes = config.rekey_after_bytes.min(2 << 30);
}
