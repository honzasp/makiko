use bytes::Bytes;
use futures_core::ready;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
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
/// sometimes called "remote forwarding" and is not yet implemented.
#[derive(Clone)]
pub struct Tunnel {
    channel: Channel,
}

impl Tunnel {
    pub(super) async fn connect(
        client: &Client,
        config: ChannelConfig,
        connect_addr: (String, u16),
        originator_addr: (IpAddr, u16),
    ) -> Result<(Tunnel, TunnelReceiver)> {
        let mut open_payload = PacketEncode::new();
        open_payload.put_str(&connect_addr.0);
        open_payload.put_u32(connect_addr.1 as u32);
        open_payload.put_str(&originator_addr.0.to_string());
        open_payload.put_u32(originator_addr.1 as u32);

        let (channel, channel_rx, _) = client.open_channel(
            "direct-tcpip".into(), config, open_payload.finish()).await?;
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
