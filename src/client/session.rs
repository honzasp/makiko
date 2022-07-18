use bytes::Bytes;
use futures_core::ready;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;
use crate::codec::{PacketDecode, PacketEncode};
use crate::error::{Result, Error};
use super::channel::{
    Channel, ChannelReceiver, ChannelEvent, ChannelConfig,
    ChannelReq, ChannelReply, DATA_STANDARD, DATA_STDERR
};
use super::client::Client;

/// Handle to an SSH session.
///
/// SSH session (RFC 4254, section 6) corresponds to the execution of a single process. The
/// [`Session`] is used to send requests and data to the server, and [`SessionReceiver`] will
/// receive the requests and data from the server. To open the session, use
/// [`Client::open_session()`].
///
/// Once the session is open, you will typically go through three stages:
/// - prepare the execution environment: [`env()`][Self::env()],
/// - start the execution: [`shell()`][Self::shell()], [`exec()`][Self::exec()],
/// [`subsystem()`][Self::subsystem()],
/// - interact with the process: [`send_stdin()`][Self::send_stdin()],
/// [`send_eof()`][Self::send_eof()], [`signal()`][Self::signal()].
///
/// In parallel, you will handle the events produced by [`SessionReceiver`].
///
/// An SSH session is a particular type of an SSH channel. However, this object provides higher
/// level API than a raw [`Channel`].
///
/// You can cheaply clone this object and safely share the clones between tasks.
#[derive(Clone)]
pub struct Session {
    channel: Channel,
}

impl Session {
    pub(super) async fn open(client: &Client, config: ChannelConfig) -> Result<(Session, SessionReceiver)> {
        let (channel, channel_rx, _) = client.open_channel("session".into(), config, Bytes::new()).await?;
        Ok((Session { channel }, SessionReceiver { channel_rx }))
    }

    /// Get the [`Client`] that this session belongs to.
    pub fn client(&self) -> Client {
        self.channel.client()
    }

    /// Close the session.
    ///
    /// We won't send any further requests or data to the server and the session will be closed
    /// once the server acknowledges our request.
    ///
    /// This method is idempotent: if the session is already closed or closing, we do nothing.
    pub fn close(&self) -> Result<()> {
        self.channel.close()
    }
}

/// # Preparing the execution environment
///
/// Use these methods to configure the session before starting the process.
impl Session {
    /// Pass an environment variable to the future process.
    ///
    /// This will set an environment variable for the process that will be started later.
    ///
    /// This method returns immediately without any blocking, but you may use the returned
    /// [`SessionReply`] to wait for the server response.
    pub fn env(&self, name: &[u8], value: &[u8]) -> Result<SessionReply> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let mut payload = PacketEncode::new();
        payload.put_bytes(name);
        payload.put_bytes(value);
        self.channel.send_request(ChannelReq {
            request_type: "env".into(),
            payload: payload.finish(),
            reply_tx: Some(reply_tx),
        })?;
        Ok(SessionReply { reply_rx })
    }

    /// Request a pseudo-terminal (pty) for the future process.
    ///
    /// This will allocate a pseudo-terminal according to the `request`.
    ///
    /// This method returns immediately without any blocking, but you may use the returned
    /// [`SessionReply`] to wait for the server response.
    pub fn request_pty(&self, request: &PtyRequest) -> Result<SessionReply> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let mut payload = PacketEncode::new();
        payload.put_str(&request.term);
        payload.put_u32(request.width);
        payload.put_u32(request.height);
        payload.put_u32(request.width_px);
        payload.put_u32(request.height_px);

        let mut encoded_modes = PacketEncode::new();
        for &(op, arg) in request.modes.opcodes.iter() {
            encoded_modes.put_u8(op);
            encoded_modes.put_u32(arg);
        }
        encoded_modes.put_u8(0);
        payload.put_bytes(&encoded_modes.finish());

        self.channel.send_request(ChannelReq {
            request_type: "pty-req".into(),
            payload: payload.finish(),
            reply_tx: Some(reply_tx),
        })?;
        Ok(SessionReply { reply_rx })
    }
}

/// # Starting the process
///
/// Use one of these methods to start the remote process. Only one of them can succeed, you cannot
/// start multiple processes with a single session (but you may open multiple sessions).
impl Session {
    /// Start the user's default shell on the server.
    ///
    /// This method returns immediately without any blocking, but you may use the returned
    /// [`SessionReply`] to wait for the server response.
    pub fn shell(&self) -> Result<SessionReply> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.channel.send_request(ChannelReq {
            request_type: "shell".into(),
            payload: Bytes::new(),
            reply_tx: Some(reply_tx),
        })?;
        Ok(SessionReply { reply_rx })
    }

    /// Start a command on the server.
    ///
    /// This method returns immediately without any blocking, but you may use the returned
    /// [`SessionReply`] to wait for the server response.
    pub fn exec(&self, command: &[u8]) -> Result<SessionReply> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let mut payload = PacketEncode::new();
        payload.put_bytes(command);
        self.channel.send_request(ChannelReq {
            request_type: "exec".into(),
            payload: payload.finish(),
            reply_tx: Some(reply_tx),
        })?;
        Ok(SessionReply { reply_rx })
    }

    /// Start an SSH subsystem on the server.
    ///
    /// Subsystems are described in RFC 4254, section 6.5.
    ///
    /// This method returns immediately without any blocking, but you may use the returned
    /// [`SessionReply`] to wait for the server response.
    pub fn subsystem(&self, subsystem_name: &str) -> Result<SessionReply> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let mut payload = PacketEncode::new();
        payload.put_str(subsystem_name);
        self.channel.send_request(ChannelReq {
            request_type: "subsystem".into(),
            payload: payload.finish(),
            reply_tx: Some(reply_tx),
        })?;
        Ok(SessionReply { reply_rx })
    }
}

/// # Interacting with a running process
impl Session {
    /// Send data to the standard input of the running process.
    ///
    /// This method returns after all bytes have been accepted by the flow control mechanism and
    /// written to the internal send buffer, but before we send them to the socket (or other I/O
    /// stream that backs this SSH connection).
    pub async fn send_stdin(&self, data: Bytes) -> Result<()> {
        self.channel.send_data(data, DATA_STANDARD).await
    }

    /// Close the standard input of the running process.
    ///
    /// This method returns after all bytes previously sent to this session have been accepted by
    /// the flow control mechanism, but before we write the message to the socket (or other I/O
    /// stream that backs this SSH connection).
    ///
    /// If the session is closed before you call this method, or if it closes before this method
    /// returns, we quietly ignore this error and return `Ok`.
    pub async fn send_eof(&self) -> Result<()> {
        self.channel.send_eof().await
    }

    /// Deliver a signal to the running process.
    ///
    /// Signal names are described in RFC 4254, section 6.10.
    /// [`codes::signal`][crate::codes::signal] lists the signal names defined by SSH.
    ///
    /// This method returns immediately without any blocking, it is not possible to get a reply
    /// from the server.
    pub fn signal(&self, signal_name: &str) -> Result<()> {
        let mut payload = PacketEncode::new();
        payload.put_str(signal_name);
        self.channel.send_request(ChannelReq {
            request_type: "signal".into(),
            payload: payload.finish(),
            reply_tx: None,
        })?;
        Ok(())
    }

    /// Notify the process that the terminal window size has changed.
    ///
    /// This method returns immediately without any blocking, it is not possible to get a reply
    /// from the server.
    pub fn window_change(&self, change: &WindowChange) -> Result<()> {
        let mut payload = PacketEncode::new();
        payload.put_u32(change.width);
        payload.put_u32(change.height);
        payload.put_u32(change.width_px);
        payload.put_u32(change.height_px);
        self.channel.send_request(ChannelReq {
            request_type: "window-change".into(),
            payload: payload.finish(),
            reply_tx: None,
        })?;
        Ok(())
    }
}



/// Future server response to a [`Session`] request.
///
/// You may either wait for the reply using [`.want_reply()`][Self::want_reply], or ignore the
/// reply using [`.no_reply()`].
#[derive(Debug)]
#[must_use = "please use .want_reply() to await the reply, or .no_reply() to ignore it"]
pub struct SessionReply {
    reply_rx: oneshot::Receiver<ChannelReply>,
}

impl SessionReply {
    /// Wait for the reply from the server.
    ///
    /// If the request failed, this returns an error ([`Error::ChannelReq`]).
    pub async fn want_reply(self) -> Result<()> {
        match self.reply_rx.await {
            Ok(ChannelReply::Success) => Ok(()),
            Ok(ChannelReply::Failure) => Err(Error::ChannelReq),
            Err(_) => Err(Error::ChannelClosed),
        }
    }

    /// Ignore the reply.
    ///
    /// This just drops the [`SessionReply`], but it is a good practice to do this explicitly with
    /// this method.
    pub fn no_reply(self) {}
}



/// An event returned from [`SessionReceiver`].
///
/// These are events related to a particular SSH session, they correspond to the requests and data
/// sent by the server.
///
/// This enum is marked as `#[non_exhaustive]`, so that we can add new variants without breaking
/// backwards compatibility. It should always be safe to ignore any events that you don't intend to
/// handle.
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionEvent {
    /// Data from the standard output of the running process.
    ///
    /// You should handle this data as a byte stream, the boundaries between consecutive
    /// `StdoutData` events might be arbitrary.
    StdoutData(Bytes),

    /// Data from the standard error of the running process.
    ///
    /// You should handle this data as a byte stream, the boundaries between consecutive
    /// `StderrData` events might be arbitrary.
    StderrData(Bytes),

    /// End-of-file marker from the running process.
    ///
    /// After this, the server should not send more data (both stdout and stderr).
    Eof,

    /// The process terminated with given exit status.
    ExitStatus(u32),

    /// The process terminated violently due to a signal.
    ExitSignal(ExitSignal),
}

/// Information about a process that terminated due to a signal.
#[derive(Debug)]
pub struct ExitSignal {
    /// Name of the signal that terminated the process.
    ///
    /// Signal names are described in RFC 4254, section 6.10.
    /// [`codes::signal`][crate::codes::signal] lists the signal names defined by SSH.
    pub signal_name: String,

    /// True if the process produced a core dump.
    pub core_dumped: bool,

    /// Error message.
    pub message: String,

    /// Language tag of `message` (per RFC 3066).
    pub message_lang: String,
}

/// Receiving half of a [`Session`].
///
/// [`SessionReceiver`] produces [`SessionEvent`]s, which correspond to the requests and data sent
/// by the server on the channel. You can ignore these events if you don't need them, but you
/// **must** receive them, otherwise the client will stall when the internal buffer of events fills
/// up.
#[derive(Debug)]
pub struct SessionReceiver {
    channel_rx: ChannelReceiver,
}

impl SessionReceiver {
    /// Wait for the next event.
    ///
    /// Returns `None` if the session was closed.
    pub async fn recv(&mut self) -> Result<Option<SessionEvent>> {
        struct Recv<'a> { rx: &'a mut SessionReceiver }
        impl<'a> Future for Recv<'a> {
            type Output = Result<Option<SessionEvent>>;
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
                self.rx.poll_recv(cx)
            }
        }
        Recv { rx: self }.await
    }

    /// Poll-friendly variant of [`.recv()`][Self::recv()].
    pub fn poll_recv(&mut self, cx: &mut Context) -> Poll<Result<Option<SessionEvent>>> {
        loop {
            match ready!(self.channel_rx.poll_recv(cx)) {
                Some(channel_event) => match translate_event(channel_event)? {
                    Some(event) => return Poll::Ready(Ok(Some(event))),
                    None => continue,
                },
                None => return Poll::Ready(Ok(None)),
            }
        }
    }
}

fn translate_event(event: ChannelEvent) -> Result<Option<SessionEvent>> {
    Ok(match event {
        ChannelEvent::Data(data, DATA_STANDARD) =>
            Some(SessionEvent::StdoutData(data)),
        ChannelEvent::Data(data, DATA_STDERR) =>
            Some(SessionEvent::StderrData(data)),
        ChannelEvent::Data(_data, _) =>
            None,
        ChannelEvent::Eof =>
            Some(SessionEvent::Eof),
        ChannelEvent::Request(req) =>
            translate_request(req)?,
    })
}

fn translate_request(request: ChannelReq) -> Result<Option<SessionEvent>> {
    let mut payload = PacketDecode::new(request.payload);
    let event = match request.request_type.as_str() {
        "exit-status" => {
            let status = payload.get_u32()?;
            SessionEvent::ExitStatus(status)
        },
        "exit-signal" => {
            let signal_name = payload.get_string()?;
            let core_dumped = payload.get_bool()?;
            let message = payload.get_string()?;
            let message_lang = payload.get_string()?;
            let signal = ExitSignal { signal_name, core_dumped, message, message_lang };
            SessionEvent::ExitSignal(signal)
        },
        _ =>
            return Ok(None)
    };

    if let Some(reply_tx) = request.reply_tx {
        let _ = reply_tx.send(ChannelReply::Success);
    }
    Ok(Some(event))
}



/// Pseudo-terminal request.
///
/// Request for allocation of a pseudo-terminal (pty), used with [`Session::request_pty()`], as
/// described in RFC 4254, section 6.2.
#[derive(Debug, Clone, Default)]
pub struct PtyRequest {
    /// Value of the `TERM` environment variable (e.g. `"vt100"`).
    pub term: String,
    /// Terminal width in characters (e.g. 80).
    pub width: u32,
    /// Terminal height in rows (e.g. 24).
    pub height: u32,
    /// Terminal width in pixels (e.g. 640).
    pub width_px: u32,
    /// Terminal height in pixels (e.g. 480).
    pub height_px: u32,
    /// Terminal modes.
    pub modes: PtyTerminalModes,
}

/// Terminal modes for a [`PtyRequest`].
///
/// The terminal modes are encoded as a sequence of opcodes that take a single `u32` argument. For
/// more details, please see RFC 4254, section 8. 
#[derive(Debug, Clone, Default)]
pub struct PtyTerminalModes {
    opcodes: Vec<(u8, u32)>,
}

impl PtyTerminalModes {
    /// Create an empty instance.
    pub fn new() -> Self {
        Default::default()
    }

    /// Adds an opcode with a single `u32` argument.
    ///
    /// Only opcodes between 1 and 159 are supported. This method will panic if you try to use it
    /// with other opcodes. In particular, do not use the `TTY_OP_END` (0) opcode.
    ///
    /// The opcodes are defined in [`codes::terminal_mode`][crate::codes::terminal_mode].
    pub fn add(&mut self, opcode: u8, arg: u32) {
        assert!(opcode >= 1 && opcode < 160);
        self.opcodes.push((opcode, arg));
    }
}

/// Change of terminal window dimensions.
///
/// Notification that window dimensions have changed, used with [`Session::window_change()`], as
/// described in RFC 4254, section 6.7.
#[derive(Debug, Copy, Clone)]
pub struct WindowChange {
    /// Terminal width in characters (e.g. 80).
    pub width: u32,
    /// Terminal height in rows (e.g. 24).
    pub height: u32,
    /// Terminal width in pixels (e.g. 640).
    pub width_px: u32,
    /// Terminal height in pixels (e.g. 480).
    pub height_px: u32,
}
