use bytes::Bytes;
use parking_lot::Mutex;
use std::future::Future;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot};
use crate::error::{Result, Error};
use super::channel_state::{self, ChannelState, ChannelSendData};
use super::client_state::ClientState;

/// Handle to an SSH channel (low level API).
///
/// Use this object to send requests and data to the server over an SSH channel. To receive events
/// and data from the server, use the matching [`ChannelReceiver`]. To obtain an instance of
/// [`Channel`] and [`ChannelReceiver`], use the method
/// [`Client::open_channel()`][super::Client::open_channel()].
///
/// This is part of a **low level API** that gives you direct access to an SSH channel, as
/// described in RFC 4254, section 5.  If you want to execute programs, consider using a
/// [`Session`][super::Session], which provides an API that hides the details of the SSH protocol.
///
/// You can cheaply clone this object and safely share the clones between tasks.
#[derive(Clone)]
pub struct Channel {
    pub(super) client_st: Arc<Mutex<ClientState>>,
    pub(super) channel_st: Weak<Mutex<ChannelState>>,
}

impl Channel {
    /// Send a request to the server.
    ///
    /// This sends a `SSH_MSG_CHANNEL_REQUEST` to the channel (RFC 4254, section 5.4). We simply
    /// enqueue the request and immediately return without any blocking, but you may use
    /// [`ChannelReq::reply_tx`] to wait for the reply. Note that requests are not subject to the
    /// SSH flow control mechanism.
    pub fn send_request(&self, req: ChannelReq) -> Result<()> {
        let mut st = self.client_st.lock();
        let channel_st = self.get_channel_st()?;
        let mut channel_st = channel_st.lock();
        channel_state::send_request(&mut st, &mut channel_st, req)
    }

    /// Send channel data to the server.
    ///
    /// This sends a series of `SSH_MSG_CHANNEL_DATA` or `SSH_MSG_CHANNEL_EXTENDED_DATA` (depending
    /// on `data_type`) to the channel (RFC 4254, section 5.2). We may split `data` into
    /// multiple packets, subject to the SSH flow control mechanism and maximum packet size.
    ///
    /// This method returns after all bytes have been accepted by the flow control mechanism and
    /// written to the internal send buffer, but before we send them to the socket (or other I/O
    /// stream that backs this SSH connection).
    pub async fn send_data(&self, data: Bytes, data_type: DataType) -> Result<()> {
        self.send_channel_data(ChannelSendData::Data(data, data_type))?.await
    }

    /// Send end-of-file marker to the server.
    ///
    /// This sends `SSH_MSG_CHANNEL_EOF` to the channel (RFC 4254, section 5.3) to signify that you
    /// will not send any more data to this channel.
    ///
    /// This method returns after all bytes previously sent to this channel have been accepted by
    /// the flow control mechanism, but before we write the message to the socket (or other I/O
    /// stream that backs this SSH connection).
    ///
    /// If the channel is closed before you call this method, or if it closes before this method
    /// returns, we quietly ignore this error and return `Ok`.
    pub async fn send_eof(&self) -> Result<()> {
        match self.try_send_eof().await {
            Ok(_) => Ok(()),
            // it is common that the peer closes the channel before we have a change to send EOF,
            // so we just ignore the error in this case
            Err(Error::ChannelClosed) => Ok(()),
            Err(err) => Err(err),
        }
    }

    async fn try_send_eof(&self) -> Result<()> {
        self.send_channel_data(ChannelSendData::Eof)?.await
    }

    /// Close the channel.
    ///
    /// This sends `SSH_MSG_CHANNEL_CLOSE` to the channel (RFC 4254, section 5.3) and the channel
    /// will become closed after we receive the same message from the server. We won't send any
    /// further requests or data to the server.
    ///
    /// This method is idempotent: if the channel is already closed or closing, we do nothing.
    pub fn close(&self) {
        let mut st = self.client_st.lock();
        if let Ok(channel_st) = self.get_channel_st() {
            channel_state::close(&mut st, &mut channel_st.lock());
        }
    }

    fn send_channel_data(&self, data: ChannelSendData) -> Result<impl Future<Output = Result<()>>> {
        let mut st = self.client_st.lock();
        let channel_st = self.get_channel_st()?;
        let mut channel_st = channel_st.lock();
        channel_state::send_data(&mut st, &mut channel_st, data)
    }

    fn get_channel_st(&self) -> Result<Arc<Mutex<ChannelState>>> {
        self.channel_st.upgrade().ok_or(Error::ChannelClosed)
    }
}


/// Receiving half of a [`Channel`] (low level API).
///
/// [`ChannelReceiver`] produces [`ChannelEvent`]s, which correspond to the requests and data sent
/// by the server on the channel. You can ignore these events if you don't need them, but you
/// **must** receive them, otherwise the client will stall when the internal buffer of events fills
/// up.
///
/// This is part of a **low level [`Channel`] API** that gives you direct access to an SSH channel.
#[derive(Debug)]
pub struct ChannelReceiver {
    pub(super) event_rx: mpsc::Receiver<ChannelEvent>,
}

impl ChannelReceiver {
    /// Wait for the next event.
    ///
    /// Returns `None` if the channel was closed.
    pub async fn recv(&mut self) -> Option<ChannelEvent> {
        self.event_rx.recv().await
    }

    /// Poll-friendly variant of [`.recv()`][Self::recv()].
    pub fn poll_recv(&mut self, cx: &mut Context) -> Poll<Option<ChannelEvent>> {
        self.event_rx.poll_recv(cx)
    }
}


/// An event returned from [`ChannelReceiver`] (low level API).
///
/// These are events related to a particular SSH channel, they correspond to the requests and data
/// sent by the server.
///
/// This enum is marked as `#[non_exhaustive]`, so that we can add new variants without breaking
/// backwards compatibility. It should always be safe to ignore any events that you don't intend to
/// handle.
///
/// This is part of a **low level [`Channel`] API** that gives you direct access to an SSH channel.
#[non_exhaustive]
pub enum ChannelEvent {
    /// Requests received from the server.
    ///
    /// This corresponds to a received `SSH_MSG_CHANNEL_REQUEST` (RFC 4254, section 5.4). Use
    /// [`ChannelReq::reply_tx`] to send a reply; if the server requested a reply but you drop the
    /// `reply_tx`, we will send a failure reply.
    /// 
    /// Note that the SSH protocol requires that replies are sent in the same order as the
    /// requests. We ensure that this is the case, but it means that if you take a long time to
    /// reply to a request, replies to following requests will be stalled.
    Request(ChannelReq),

    /// Data received from the server.
    ///
    /// These events correspond to received `SSH_MSG_CHANNEL_DATA` or
    /// `SSH_MSG_CHANNEL_EXTENDED_DATA` (RFC 4254, section 5.2). You should handle this data as a
    /// byte stream, the boundaries between consecutive `Data` events might be arbitrary.
    Data(Bytes, DataType),

    /// End-of-file marker received from the server.
    ///
    /// This corresponds to a received `SSH_MSG_CHANNEL_EOF` (RFC 4254, section 5.3), the server
    /// tells us that it won't send any more data to this channel.
    Eof,
}


/// Request on an SSH channel (low level API).
///
/// Requests provide a way to send out-of-band information to the SSH channel (such as environment
/// variables) using `SSH_MSG_CHANNEL_REQUEST`, as described in RFC 4254, section 5.4. They are not
/// subject to the flow control mechanism.
///
/// We use the same structure for requests that you send to the server (using
/// [`Channel::send_request()`] and requests that we receive from the server (in
/// [`ChannelEvent::Request`]).
///
/// This is part of a **low level [`Channel`] API** that gives you direct access to an SSH channel.
#[derive(Debug)]
pub struct ChannelReq {
    /// The type of the request.
    ///
    /// The types of supported requests, such as `"pty-req"` or `"env"`, depend on the type of
    /// channel.
    pub request_type: String,

    /// The raw type-specific request data.
    ///
    /// These are raw bytes from the `SSH_MSG_CHANNEL_REQUEST` packet. You may want to use
    /// [`PacketEncode`][crate::PacketEncode] to encode the payload or
    /// [`PacketDecode`][crate::PacketDecode] to decode it.
    pub payload: Bytes,

    /// The reply to the request.
    ///
    /// The meaning of this field depends on the "direction" of the request:
    ///
    /// - For requests that you send to the server, you can create a [`oneshot`] pair and store
    /// the sender here. We will set the `want reply` field in the `SSH_MSG_CHANNEL_REQUEST`, wait
    /// for the reply from the server, and then send the reply to the sender. You may then receive
    /// the reply from the `oneshot` receiver that you created along with the sender.
    ///
    /// - For requests that we received from the server, we will set this field if the server set
    /// the `want reply` field in the `SSH_MSG_CHANNEL_REQUEST`. When you receive the
    /// [`ChannelReq`] in [`ChannelEvent::Request`], you should handle the request and send the
    /// reply to this sender, if it is not `None`. If you don't send anything and drop the
    /// [`oneshot::Sender`], we will send a failure reply to the server.
    pub reply_tx: Option<oneshot::Sender<ChannelReply>>,
}

/// Reply to a request on an SSH channel (low level API).
///
/// This is a reply to a `SSH_MSG_CHANNEL_REQUEST`, as described in RFC 4254, section 5.4.
///
/// This is part of a **low level [`Channel`] API** that gives you direct access to an SSH channel.
#[derive(Debug)]
pub enum ChannelReply {
    /// Successful reply (`SSH_MSG_CHANNEL_SUCCESS`).
    Success,
    /// Failure reply (`SSH_MSG_CHANNEL_FAILURE`).
    Failure,
}


/// Type of data sent over an SSH channel (low level API).
///
/// Channel data transfer is described in RFC 4254, section 5.2. In practice, the only two data
/// types used are `DataType::Standard` ([`DATA_STANDARD`]) and `DataType::Extended(1)`
/// ([`DATA_STDERR`]).
///
/// This is part of a **low level [`Channel`] API** that gives you direct access to an SSH channel.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum DataType {
    /// Standard channel data sent using `SSH_MSG_CHANNEL_DATA`.
    Standard,
    /// Extended channel data sent using `SSH_MSG_CHANNEL_EXTENDED_DATA`.
    Extended(u32),
}

/// Shorthand for `DataType::Standard` (low level API).
///
/// This is part of a **low level [`Channel`] API** that gives you direct access to an SSH channel.
pub const DATA_STANDARD: DataType = DataType::Standard;

/// Shorthand for `DataType::Extended(1)` (low level API).
///
/// This is part of a **low level [`Channel`] API** that gives you direct access to an SSH channel.
pub const DATA_STDERR: DataType = DataType::Extended(1);
