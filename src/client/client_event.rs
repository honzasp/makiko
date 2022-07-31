use bytes::Bytes;
use derivative::Derivative;
use futures_core::ready;
use parking_lot::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::sync::Weak;
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot};
use crate::codec::PacketDecode;
use crate::error::{Result, Error, ChannelOpenError};
use crate::pubkey::Pubkey;
use super::channel::{Channel, ChannelConfig, ChannelReceiver};
use super::client_state::ClientState;
use super::conn::AcceptedChannel;
use super::tunnel::{Tunnel, TunnelReceiver};

/// Receiving half of a [`Client`][super::Client].
///
/// [`ClientReceiver`] provides you with the [`ClientEvent`]s, various events that are produced
/// during the life of the connection. You can usually ignore them, except
/// [`ClientEvent::ServerPubkey`], which is used to verify the server's public key (if you ignore
/// that event, we assume that you reject the key and we abort the connection). However, you
/// **must** receive these events, otherwise the client will stall when the internal buffer of
/// events fills up.
pub struct ClientReceiver {
    pub(super) client_st: Weak<Mutex<ClientState>>,
    pub(super) event_rx: mpsc::Receiver<ClientEvent>,
    pub(super) specialize_channels: bool,
}

impl ClientReceiver {
    /// Wait for the next event.
    ///
    /// Returns `None` if the connection was closed.
    pub async fn recv(&mut self) -> Result<Option<ClientEvent>> {
        struct Recv<'a> { rx: &'a mut ClientReceiver }
        impl<'a> Future for Recv<'a> {
            type Output = Result<Option<ClientEvent>>;
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
                self.rx.poll_recv(cx)
            }
        }
        Recv { rx: self }.await
    }

    /// Poll-friendly variant of [`.recv()`][Self::recv()].
    pub fn poll_recv(&mut self, cx: &mut Context) -> Poll<Result<Option<ClientEvent>>> {
        match ready!(self.event_rx.poll_recv(cx)) {
            Some(ClientEvent::Channel(mut accept)) => {
                accept.client_st = Some(self.client_st.clone());
                if accept.channel_type == "forwarded-tcpip" && self.specialize_channels {
                    let accept = AcceptTunnel::decode(accept)?;
                    Poll::Ready(Ok(Some(ClientEvent::Tunnel(accept))))
                } else {
                    Poll::Ready(Ok(Some(ClientEvent::Channel(accept))))
                }
            },
            event => Poll::Ready(Ok(event)),
        }
    }

    /// Control whether we should treat some [`ClientEvent::Channel`] events specially (low level
    /// API).
    ///
    /// When the server attempts to open a channel, we normally give you a
    /// [`ClientEvent::Channel`]. However, to provide a higher level API, we treat some channels
    /// specially: when the channel type is `"forwarded-tcpip"`, you will get a
    /// [`ClientEvent::Tunnel`] event instead of [`ClientEvent::Channel`] event, so you can easily
    /// work with the high-level [`Tunnel`] API instead of the low-level [`Channel`] API.
    ///
    /// In most cases, the default behavior is perfectly OK and you want to keep this enabled. But
    /// if you want to use the low-level API, you can disable this behavior by calling this method
    /// with `false`.
    pub fn specialize_channels(&mut self, enable: bool) {
        self.specialize_channels = enable;
    }
}

/// An event returned from [`ClientReceiver`][super::ClientReceiver].
///
/// These are "global" events that are related to the SSH connection, not to a particular
/// session/channel. You can safely ignore all events except [`ServerPubkey`][Self::ServerPubkey],
/// which you must handle in order to accept or reject the server's public key (if you don't handle
/// this event, the key will be rejected and we will abort the connection).
///
/// This enum is marked as `#[non_exhaustive]`, so that we can add new variants without breaking
/// backwards compatibility. It should always be safe to ignore any events that you don't intend to
/// handle.
#[non_exhaustive]
#[derive(Debug)]
pub enum ClientEvent {
    /// Server presented its public key and you should verify it.
    ///
    /// This event is produced as part of the SSH key exchange. You will always receive this event
    /// during the initial handshake, but you may also receive it again later on, when the
    /// connection is "rekeyed".
    ///
    /// The SSH protocol does not provide any mechanism to verify the identity of the server, so it
    /// is up to you. Please read RFC 4251, section 4.1 for more details and suggestions on how to
    /// deal with this problem.
    ///
    /// The [`Pubkey`] is the public key that the server provided as part of the key exchange. We
    /// have already verified that the server owns the private key. You should use the
    /// [`AcceptPubkey`] object to either [`.accept()`][AcceptPubkey::accept()] or
    /// [`.reject()`][AcceptPubkey::reject()] the key.
    ServerPubkey(Pubkey, AcceptPubkey),
    
    /// Server sent us a debugging message.
    ///
    /// This is the "debug message" (`SSH_MSG_DEBUG`) described in RFC 4253, section 11.3. You can
    /// simply ignore this event.
    DebugMsg(DebugMsg),

    /// Server sent a text that the user should see before authentication.
    ///
    /// This is the "banner message" (`SSH_MSG_USERAUTH_BANNER`) described in RFC 4252, section
    /// 5.2. Citing from the RFC, this message "may be relevant for getting legal protection". You
    /// can probably ignore this event.
    AuthBanner(AuthBanner),

    /// Server attempts to open a tunnel.
    ///
    /// You normally recieve this event when you have requested remote forwarding using
    /// [`Client::bind_tunnel()`][super::Client::bind_tunnel()] and somebody tries to connect to
    /// the address that you specified. You can use the [`AcceptTunnel`] object to inspect the
    /// connection attempt and accept or reject the tunnel.
    Tunnel(AcceptTunnel),

    /// Server attempts to open a channel (low level API).
    ///
    /// This is the `SSH_MSG_CHANNEL_OPEN` message described in RFC 4255, section 5.1. You can use
    /// the [`AcceptChannel`] object to get details about the message and accept or reject the
    /// channel.
    ///
    /// Note that by default, some of these messages are translated to higher-level events (such as
    /// [`Tunnel`][Self::Tunnel]). See [`ClientReceiver::specialize_channels()`] for a way to
    /// disable this behavior.
    Channel(AcceptChannel),
}



/// Debugging message sent by the SSH server.
///
/// You might receive this in [`ClientEvent::DebugMsg`]. Please consult RFC 4253, section 11.3 for
/// details.
#[derive(Debug)]
pub struct DebugMsg {
    /// If true, you should display this message.
    pub always_display: bool,
    /// The debugging message string.
    pub message: String,
    /// Language tag of the message (as in RFC 3066).
    pub message_lang: String,
}

/// Banner message sent by the SSH server.
///
/// You might receive this in [`ClientEvent::AuthBanner`]. Please consult RFC 4252, section 5.2 for
/// details.
#[derive(Debug)]
pub struct AuthBanner {
    /// The banner message string.
    pub message: String,
    /// Language tag of the message (per RFC 3066).
    pub message_lang: String,
}



/// Tell us whether the server public key is valid.
///
/// You receive this object in [`ClientEvent::ServerPubkey`] and use it to tell us whether you
/// accept or reject the server public key. If you drop this object, it is treated as rejection.
#[derive(Debug)]
pub struct AcceptPubkey {
    pub(super) accepted_tx: oneshot::Sender<Result<PubkeyAccepted>>,
}

/// A "witness" that the user has called [`AcceptPubkey::accept()`].
#[derive(Debug)]
pub(super) struct PubkeyAccepted(());

impl AcceptPubkey {
    /// Accept the server public key.
    ///
    /// You assert that this public key really belongs to the server that you want to connect to.
    pub fn accept(self) {
        let _: Result<_, _> = self.accepted_tx.send(Ok(PubkeyAccepted(())));
    }

    /// Reject the server public key.
    ///
    /// The connection will be aborted with error `Error::PubkeyAccept(Box::new(err))`.
    pub fn reject<E: std::error::Error + Send + Sync + 'static>(self, err: E) {
        let _: Result<_, _> = self.accepted_tx.send(Err(Error::PubkeyAccept(Box::new(err))));
    }
}



/// Tell us whether to accept a channel opened by the server (low level API).
///
/// You receive this object in [`ClientEvent::Channel`] and use it to accept or reject a channel
/// that the server wants to open.
///
/// Dropping this object is the same as calling [`reject_prohibited()`][Self::reject_prohibited].
#[derive(Derivative)]
#[derivative(Debug)]
pub struct AcceptChannel {
    /// This field is set by the [`ClientReceiver`] before `self` is returned to the user.
    #[derivative(Debug = "ignore")]
    pub(super) client_st: Option<Weak<Mutex<ClientState>>>,
    /// The identifier of the channel type (RFC 4254, section 5.1).
    pub channel_type: String,
    /// The type-specific payload of the `SSH_MSG_CHANNEL_OPEN` message (RFC 4254, section 5.1).
    pub open_payload: Bytes,
    #[derivative(Debug = "ignore")]
    pub(super) accepted_tx: oneshot::Sender<Result<AcceptedChannel, ChannelOpenError>>,
}

impl AcceptChannel {
    /// Accept the opened channel.
    ///
    /// After you call this method, we respond with `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` to the
    /// server (RFC 4254, section 5.1) and open the channel. You can use `confirm_payload` to add a
    /// type-specific payload to the confirmation message.
    ///
    /// If all goes well, this method returns two objects:
    ///
    /// - [`Channel`] is the handle for interacting with the channel and sending data to the
    /// server.
    /// - [`ChannelReceiver`] receives the [`ChannelEvent`][super::ChannelEvent]s produced by the
    /// channel. You **must** receive these events in time, otherwise the client will stall.
    pub async fn accept(self, config: ChannelConfig, confirm_payload: Bytes)
        -> Result<(Channel, ChannelReceiver)> 
    {
        let (result_tx, result_rx) = oneshot::channel();
        let accepted = AcceptedChannel {
            recv_window_max: config.recv_window_max(),
            recv_packet_len_max: config.recv_packet_len_max(),
            confirm_payload,
            result_tx,
        };
        let _: Result<_, _> = self.accepted_tx.send(Ok(accepted));

        let result = result_rx.await.map_err(|_| Error::ClientClosed)?;

        let channel = Channel {
            client_st: self.client_st.unwrap(),
            channel_st: result.channel_st,
        };
        let channel_rx = ChannelReceiver { event_rx: result.event_rx };
        Ok((channel, channel_rx))
    }
    
    /// Reject the channel.
    ///
    /// This sends the `SSH_MSG_CHANNEL_OPEN_FAILURE` message to the server (RFC 4254, section
    /// 5.1). The `error` specifies the reasons for the rejection that will be sent to the server.
    pub fn reject(self, error: ChannelOpenError) {
        let _: Result<_, _> = self.accepted_tx.send(Err(error));
    }

    /// Reject the channel with reasonable default error.
    ///
    /// This is the same as calling [`reject()`][Self::reject()] with reason code
    /// `ADMINISTRATIVELY_PROHIBITED`.
    pub fn reject_prohibited(self) {}
}



/// Tell us whether to accept a tunnel opened by the server.
///
/// You receive this object in [`ClientEvent::Tunnel`] and use it to accept or reject a tunnel
/// that the server wants to open.
///
/// Dropping this object is the same as calling [`reject_prohibited()`][Self::reject_prohibited].
#[derive(Debug)]
pub struct AcceptTunnel {
    accept: AcceptChannel,
    /// The address on the SSH server that the remote peer has connected to.
    pub connected_addr: (String, u16),
    /// The address of the remote peer.
    pub originator_addr: (String, u16),
}

impl AcceptTunnel {
    fn decode(accept: AcceptChannel) -> Result<AcceptTunnel> {
        let mut payload = PacketDecode::new(accept.open_payload.clone());
        let connected_host = payload.get_string()?;
        let connected_port = payload.get_u32()? as u16;
        let connected_addr = (connected_host, connected_port);
        let originator_host = payload.get_string()?;
        let originator_port = payload.get_u32()? as u16;
        let originator_addr = (originator_host, originator_port);
        Ok(AcceptTunnel { accept, connected_addr, originator_addr })
    }

    /// Accept the opened tunnel.
    ///
    /// If everything goes well, this method returns two objects:
    ///
    /// - [`Tunnel`] is the handle for sending data to the server.
    /// - [`TunnelReceiver`] receives the data from the server as
    /// [`TunnelEvent`][super::TunnelEvent]s. You **must** receive these events in time, otherwise
    /// the client will stall.
    pub async fn accept(self, config: ChannelConfig) -> Result<(Tunnel, TunnelReceiver)> {
        let (channel, channel_rx) = self.accept.accept(config, Bytes::new()).await?;
        Tunnel::accept(channel, channel_rx)
    }

    /// Reject the tunnel.
    ///
    /// The `error` specifies the reasons for the rejection that will be sent to the server.
    pub fn reject(self, error: ChannelOpenError) {
        self.accept.reject(error);
    }

    /// Reject the tunnel with reasonable default error.
    ///
    /// This is the same as calling [`reject()`][Self::reject()] with reason code
    /// `ADMINISTRATIVELY_PROHIBITED`.
    pub fn reject_prohibited(self) {
        self.accept.reject_prohibited();
    }
}
