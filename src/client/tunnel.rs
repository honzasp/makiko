use bytes::{Bytes, Buf as _};
use futures_core::ready;
use futures_core::future::BoxFuture;
use std::cmp::min;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncBufRead, AsyncWrite};
use crate::codec::PacketEncode;
use crate::error::Result;
use super::channel::{Channel, ChannelReceiver, ChannelEvent, ChannelConfig, DATA_STANDARD};
use super::client::Client;

/// Handle to an SSH tunnel (TCP/IP forwarding channel).
///
/// TCP/IP forwarding channels (RFC 4253, section 7), commonly called "tunnels", allow you to
/// transmit ordinary TCP/IP sockets over SSH. There are two ways how to obtain a tunnel:
///
/// - You can ask the server to connect to an address using [`Client::connect_tunnel()`]. This is
/// sometimes called "local forwarding".
/// - You can ask the server to bind to an address and listen for incoming connections. This is
/// sometimes called "remote forwarding".
///
/// If you need to have something that implements `AsyncWrite`, consider using [`TunnelWriter`] or
/// [`TunnelStream`].
#[derive(Clone)]
pub struct Tunnel {
    channel: Channel,
}

impl Tunnel {
    pub(super) async fn connect(
        client: &Client,
        config: ChannelConfig,
        connect_addr: (String, u16),
        originator_addr: (String, u16),
    ) -> Result<(Tunnel, TunnelReceiver)> {
        let mut open_payload = PacketEncode::new();
        open_payload.put_str(&connect_addr.0);
        open_payload.put_u32(connect_addr.1 as u32);
        open_payload.put_str(&originator_addr.0);
        open_payload.put_u32(originator_addr.1 as u32);

        let (channel, channel_rx, _) = client.open_channel(
            "direct-tcpip".into(), config, open_payload.finish()).await?;
        Ok((Tunnel { channel }, TunnelReceiver { channel_rx }))
    }

    pub(super) fn accept(channel: Channel, channel_rx: ChannelReceiver) -> Result<(Tunnel, TunnelReceiver)> {
        Ok((Tunnel { channel }, TunnelReceiver { channel_rx }))
    }
}

impl Tunnel {
    /// Send data to the tunnel.
    ///
    /// This method returns after all bytes have been accepted by the flow control mechanism and
    /// written to the internal send buffer, but before we send them to the socket (or other I/O
    /// stream that backs this SSH connection).
    pub async fn send_data(&self, data: Bytes) -> Result<()> {
        self.channel.send_data(data, DATA_STANDARD).await
    }

    /// Signals that no more data will be sent to this channel.
    ///
    /// This method returns after all bytes previously sent to this tunnel have been accepted by
    /// the flow control mechanism, but before we write the message to the socket (or other I/O
    /// stream that backs this SSH connection).
    ///
    /// If the tunnel is closed before you call this method, or if it closes before this method
    /// returns, we quietly ignore this error and return `Ok`.
    pub async fn send_eof(&self) -> Result<()> {
        self.channel.send_eof().await
    }
}

/// Receiving half of a [`Tunnel`].
///
/// [`TunnelReceiver`] produces [`TunnelEvent`]s, which correspond to the data sent by the server
/// on the tunnel. You can ignore these events if you don't need them, but you **must** receive
/// them, otherwise the client will stall when the internal buffer of events fills up.
///
/// If you need to have something that implements `AsyncRead`, consider using [`TunnelReader`] or
/// [`TunnelStream`].
#[derive(Debug)]
pub struct TunnelReceiver {
    channel_rx: ChannelReceiver,
}

/// An event returned from [`TunnelReceiver`].
///
/// These are events related to a particular SSH tunnel, they correspond to the data sent by the
/// server.
///
/// This enum is marked as `#[non_exhaustive]`, so that we can add new variants without breaking
/// backwards compatibility. It should always be safe to ignore any events that you don't intend to
/// handle.
#[derive(Debug)]
#[non_exhaustive]
pub enum TunnelEvent {
    /// Data received from the tunnel.
    ///
    /// You should handle this data as a byte stream, the boundaries between consecutive `Data`
    /// events might be arbitrary.
    Data(Bytes),

    /// End of file received from the tunnel.
    ///
    /// After this, we should not receive more data from the tunnel, but the tunnel is not yet
    /// closed.
    Eof,
}

impl TunnelReceiver {
    /// Receive data from the tunnel.
    ///
    /// Returns `None` if the tunnel was closed.
    pub async fn recv(&mut self) -> Result<Option<TunnelEvent>> {
        struct Recv<'a> { rx: &'a mut TunnelReceiver }
        impl<'a> Future for Recv<'a> {
            type Output = Result<Option<TunnelEvent>>;
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
                self.rx.poll_recv(cx)
            }
        }
        Recv { rx: self }.await
    }

    /// Poll-friendly variant of [`.recv()`][Self::recv()].
    pub fn poll_recv(&mut self, cx: &mut Context) -> Poll<Result<Option<TunnelEvent>>> {
        loop {
            match ready!(self.channel_rx.poll_recv(cx)) {
                Some(ChannelEvent::Data(data, DATA_STANDARD)) =>
                    return Poll::Ready(Ok(Some(TunnelEvent::Data(data)))),
                Some(ChannelEvent::Eof) =>
                    return Poll::Ready(Ok(Some(TunnelEvent::Eof))),
                Some(ChannelEvent::Data(_, _) | ChannelEvent::Request(_)) =>
                    continue,
                None => return Poll::Ready(Ok(None)),
            }
        }
    }
}

/// `AsyncRead` and `AsyncBufRead` for an SSH tunnel.
///
/// This helper wraps [`TunnelReceiver`] and implements `AsyncRead` and `AsyncBufRead`. This allows
/// you to use the tunnel as a buffered Tokio read stream.
///
/// The reader wraps a [`TunnelReceiver`], so you **must** be continuously polling the reader in a
/// timely manner, otherwise the client will stall.
pub struct TunnelReader {
    tunnel_rx: TunnelReceiver,
    /// Data that we received from the tunnel but which the caller hasn't read yet.
    read_buf: Bytes,
    /// Have we received an EOF?
    read_eof: bool,
}

impl TunnelReader {
    /// Create [`TunnelReader`] from a [`TunnelReceiver`].
    pub fn new(tunnel_rx: TunnelReceiver) -> Self {
        Self {
            tunnel_rx,
            read_buf: Bytes::new(),
            read_eof: false,
        }
    }

    /// Consumes this [`TunnelReader`] and returns the underlying [`TunnelReceiver`].
    ///
    /// Note that any buffered data, including the EOF flag, will be lost.
    pub fn into_inner(self) -> TunnelReceiver {
        self.tunnel_rx
    }

    /// Get a reference to the buffered data.
    pub fn buffer(&self) -> &Bytes {
        &self.read_buf
    }
}

impl AsyncRead for TunnelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled_buf = ready!(self.as_mut().poll_fill_buf(cx))?;
        let fill_len = min(filled_buf.len(), buf.remaining());
        buf.put_slice(&filled_buf[..fill_len]);
        self.as_mut().consume(fill_len);
        Poll::Ready(Ok(()))
    }
}

impl AsyncBufRead for TunnelReader {
    fn poll_fill_buf(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<&[u8]>> {
        let this = self.get_mut();
        loop {
            if !this.read_buf.is_empty() || this.read_eof {
                return Poll::Ready(Ok(&this.read_buf))
            }

            match ready!(this.tunnel_rx.poll_recv(cx))? {
                Some(TunnelEvent::Data(data)) => this.read_buf = data,
                Some(TunnelEvent::Eof) | None => this.read_eof = true,
            }
        }
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.get_mut().read_buf.advance(amt);
    }
}

/// `AsyncWrite` for an SSH tunnel.
///
/// This helper wraps [`Tunnel`] and implements `AsyncWrite`. This allows you to use the tunnel as
/// a normal Tokio write stream.
pub struct TunnelWriter {
    tunnel: Tunnel,
    /// Future from the last call to `Tunnel::send_data()` that is still pending. We must poll
    /// this future before writing more data.
    pending_write_fut: Option<BoxFuture<'static, Result<()>>>,
    /// Future from the call to `Tunnel::send_eof()` that is still pending.
    pending_shutdown_fut: Option<BoxFuture<'static, Result<()>>>,
}

impl TunnelWriter {
    /// Create [`TunnelWriter`] from a [`Tunnel`].
    pub fn new(tunnel: Tunnel) -> Self {
        Self {
            tunnel,
            pending_write_fut: None,
            pending_shutdown_fut: None,
        }
    }
}

impl AsyncWrite for TunnelWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;

        let this = self.get_mut();
        debug_assert!(this.pending_write_fut.is_none());

        let data = Bytes::copy_from_slice(buf);
        let tunnel = this.tunnel.clone();
        let mut write_fut = Box::pin(async move {
            tunnel.send_data(data).await
        });
        match write_fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {},
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err.into())),
            Poll::Pending => this.pending_write_fut = Some(write_fut),
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        if let Some(write_fut) = this.pending_write_fut.as_mut() {
            let res = ready!(write_fut.as_mut().poll(cx));
            this.pending_write_fut = None;
            res?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;

        let this = self.get_mut();
        let shutdown_fut = this.pending_shutdown_fut.get_or_insert_with(|| {
            let tunnel = this.tunnel.clone();
            Box::pin(async move {
                tunnel.send_eof().await
            })
        });

        let res = ready!(shutdown_fut.as_mut().poll(cx));
        this.pending_shutdown_fut = None;
        res?;
        Poll::Ready(Ok(()))
    }
}

/// `AsyncRead + AsyncWrite` for an SSH tunnel.
///
/// This helper wraps [`Tunnel`] and its [`TunnelReceiver`] and implements `AsyncRead`,
/// `AsyncBufRead` and `AsyncWrite`. This allows you to use tunnels as any other Tokio async
/// stream. It also enables you to implement `ProxyJump` functionality by opening a new SSH
/// connection through a tunnel on an existing SSH connection.
///
/// The reader wraps a [`TunnelReceiver`], so you **must** be continuously polling the reader in a
/// timely manner, otherwise the client will stall.
pub struct TunnelStream {
    /// The reader part of this I/O stream.
    pub reader: TunnelReader,
    /// The writer part of this I/O stream.
    pub writer: TunnelWriter,
}

impl TunnelStream {
    /// Create a [`TunnelStream`] from the tunnel and the tunnel receiver.
    ///
    /// The `tunnel` and `tunnel_rx` will usually come from the same SSH tunnel, but this is not
    /// stricly required by this API, so you can write data to one tunnel and read it from another
    /// tunnel.
    pub fn new(tunnel: Tunnel, tunnel_rx: TunnelReceiver) -> Self {
        let reader = TunnelReader::new(tunnel_rx);
        let writer = TunnelWriter::new(tunnel);
        Self { reader, writer }
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl AsyncBufRead for TunnelStream {
    fn poll_fill_buf(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<&[u8]>> {
        Pin::new(&mut self.get_mut().reader).poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        Pin::new(&mut self.get_mut().reader).consume(amt)
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}
