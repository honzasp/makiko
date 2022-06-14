use bytes::Bytes;
use futures_core::ready;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;
use crate::codec::{PacketDecode, PacketEncode};
use crate::error::{Result, Error};
use super::channel::{
    Channel, ChannelReceiver, ChannelEvent,
    ChannelReq, ChannelReply, DATA_STANDARD, DATA_STDERR
};
use super::client::Client;

#[derive(Clone)]
pub struct Session {
    channel: Channel,
}

impl Session {
    pub async fn open(client: &Client) -> Result<(Session, SessionReceiver)> {
        let (channel, channel_rx, _) = client.open_channel("session".into(), Bytes::new()).await?;
        Ok((Session { channel }, SessionReceiver { channel_rx }))
    }

    pub async fn send_stdin(&self, data: Bytes) -> Result<()> {
        self.channel.send_data(data, DATA_STANDARD).await
    }

    pub async fn send_eof(&self) -> Result<()> {
        self.channel.send_eof().await
    }

    pub fn env(&self, name: &[u8], value: &[u8]) -> Result<Reply> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let mut payload = PacketEncode::new();
        payload.put_bytes(name);
        payload.put_bytes(value);
        self.channel.send_request(ChannelReq {
            request_type: "env".into(),
            payload: payload.finish(),
            reply_tx: Some(reply_tx),
        })?;
        Ok(Reply { reply_rx })
    }

    pub fn shell(&self) -> Result<Reply> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.channel.send_request(ChannelReq {
            request_type: "shell".into(),
            payload: Bytes::new(),
            reply_tx: Some(reply_tx),
        })?;
        Ok(Reply { reply_rx })
    }

    pub fn exec(&self, command: &[u8]) -> Result<Reply> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let mut payload = PacketEncode::new();
        payload.put_bytes(command);
        self.channel.send_request(ChannelReq {
            request_type: "exec".into(),
            payload: payload.finish(),
            reply_tx: Some(reply_tx),
        })?;
        Ok(Reply { reply_rx })
    }

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

    pub fn close(&self) {
        self.channel.close()
    }
}



#[derive(Debug)]
#[must_use = "please use .want_reply() to await the reply, or .no_reply() to ignore it"]
pub struct Reply {
    reply_rx: oneshot::Receiver<ChannelReply>,
}

impl Reply {
    pub async fn want_reply(self) -> Result<()> {
        match self.reply_rx.await {
            Ok(ChannelReply::Success) => Ok(()),
            Ok(ChannelReply::Failure) => Err(Error::ChannelReq),
            Err(_) => Err(Error::ChannelClosed),
        }
    }

    pub fn no_reply(self) {}
}



#[non_exhaustive]
pub enum SessionEvent {
    StdoutData(Bytes),
    StderrData(Bytes),
    Eof,
    ExitStatus(u32),
    ExitSignal(ExitSignal),
}

#[derive(Debug)]
pub struct ExitSignal {
    pub signal_name: String,
    pub core_dumped: bool,
    pub message: String,
    pub message_lang: String,
}

pub struct SessionReceiver {
    channel_rx: ChannelReceiver,
}

impl SessionReceiver {
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

    pub async fn recv(&mut self) -> Result<Option<SessionEvent>> {
        struct Recv<'a> { rx: &'a mut SessionReceiver }
        impl<'a> Future for Recv<'a> {
            type Output = Result<Option<SessionEvent>>;
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
                (&mut self.rx).poll_recv(cx)
            }
        }
        Recv { rx: self }.await
    }
}

fn translate_event(event: ChannelEvent) -> Result<Option<SessionEvent>> {
    Ok(match event {
        ChannelEvent::Data(data, DATA_STANDARD) =>
            Some(SessionEvent::StdoutData(data)),
        ChannelEvent::Data(data, DATA_STDERR) =>
            Some(SessionEvent::StderrData(data)),
        ChannelEvent::Eof =>
            Some(SessionEvent::Eof),
        ChannelEvent::Request(req) =>
            translate_request(req)?,
        _ =>
            None,
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
