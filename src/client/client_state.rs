use bytes::{Bytes, BytesMut};
use futures_core::ready;
use ring::rand::SecureRandom;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use crate::codec::{Codec, RecvPipe, SendPipe};
use crate::error::{Error, Result};
use super::auth::{self, AuthState};
use super::client_event::ClientEvent;
use super::conn::{self, ConnState};
use super::negotiate::{self, NegotiateState};
use super::pump::Pump;
use super::recv::{self, RecvState};

pub(super) trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

pub(super) struct ClientState {
    pub rng: Box<dyn SecureRandom + Send>,
    pub event_tx: PollSender<ClientEvent>,
    pub codec: Codec,
    pub our_ident: Bytes,
    pub their_ident: Option<Bytes>,
    pub recv_st: Option<Box<dyn RecvState + Send>>,
    pub negotiate_st: Box<NegotiateState>,
    pub auth_st: Box<AuthState>,
    pub conn_st: Box<ConnState>,
    pub session_id: Option<Vec<u8>>,
    waker: Option<Waker>,
}

pub(super) fn new_client(
    rng: Box<dyn SecureRandom + Send + Sync>,
    event_tx: mpsc::Sender<ClientEvent>,
) -> Result<ClientState> {
    let mut send_pipe = SendPipe::new(&*rng)?;
    let our_ident: Bytes = "SSH-2.0-makiko".into();
    send_pipe.feed_ident(&our_ident);

    Ok(ClientState {
        rng,
        event_tx: PollSender::new(event_tx),
        codec: Codec {
            recv_pipe: RecvPipe::new(),
            send_pipe,
        },
        our_ident,
        their_ident: None,
        recv_st: None,
        negotiate_st: Box::new(negotiate::init_negotiate()),
        auth_st: Box::new(auth::init_auth()),
        conn_st: Box::new(conn::init_conn()),
        session_id: None,
        waker: None,
    })
}

pub(super) fn poll_client(
    st: &mut ClientState,
    mut stream: Pin<&mut dyn AsyncReadWrite>,
    cx: &mut Context,
) -> Poll<Result<()>> {
    loop {
        let mut progress = false;

        while recv::pump_recv(st, cx)?.is_progress() { progress = true }
        while negotiate::pump_negotiate(st, cx)?.is_progress() { progress = true }
        while auth::pump_auth(st, cx)?.is_progress() { progress = true }
        while conn::pump_conn(st, cx)?.is_progress() { progress = true }

        if pump_read(st, stream.as_mut(), cx)?.is_progress() { continue }
        while pump_write(st, stream.as_mut(), cx)?.is_progress() { progress = true }

        if !progress { break }
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
            return Ok(Pump::Pending)
        },
        Poll::Ready(Ok(written_len)) => {
            log::trace!("written {}/{} bytes", written_len, data.len());
            st.codec.send_pipe.consume_bytes(written_len)
        },
        Poll::Ready(Err(err)) => {
            log::debug!("error when writing: {}", err);
            return Err(Error::WriteIo(err))
        },
    }

    match stream.poll_flush(cx) {
        Poll::Ready(Ok(())) | Poll::Pending => Ok(Pump::Progress),
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

        match poll_read_buf(stream.as_mut(), cx, st.codec.recv_pipe.feed_buf()) {
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

// adapted from `tokio_util::io::poll_read_buf`
fn poll_read_buf(
    stream: Pin<&mut dyn AsyncReadWrite>,
    cx: &mut Context,
    buf: &mut BytesMut,
) -> Poll<std::io::Result<usize>> {
    use bytes::BufMut as _;
    use std::mem::MaybeUninit;
    use tokio::io::ReadBuf;

    assert!(buf.has_remaining_mut());

    let n = {
        let dst = buf.chunk_mut();
        let dst = unsafe { &mut *(dst as *mut _ as *mut [MaybeUninit<u8>]) };
        let mut read_buf = ReadBuf::uninit(dst);
        let ptr = read_buf.filled().as_ptr();
        ready!(stream.poll_read(cx, &mut read_buf))?;

        assert_eq!(ptr, read_buf.filled().as_ptr());
        read_buf.filled().len()
    };

    unsafe { buf.advance_mut(n); }

    Poll::Ready(Ok(n))
}
