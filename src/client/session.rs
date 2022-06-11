use bytes::Bytes;
use futures_core::ready;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;
use crate::codec::PacketEncode;
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
pub struct Reply {
    reply_rx: oneshot::Receiver<ChannelReply>,
}

impl Reply {
    pub async fn want_reply(self) -> Result<()> {
        match self.reply_rx.await {
            Ok(ChannelReply::Success) => Ok(()),
            Ok(ChannelReply::Failure) => Err(Error::ChannelReqFailure),
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
            let event = match ready!(self.channel_rx.poll_recv(cx)) {
                Some(ChannelEvent::Data(data, DATA_STANDARD)) =>
                    SessionEvent::StdoutData(data),
                Some(ChannelEvent::Data(data, DATA_STDERR)) =>
                    SessionEvent::StderrData(data),
                Some(ChannelEvent::Eof) =>
                    SessionEvent::Eof,
                Some(_) =>
                    continue,
                None =>
                    return Poll::Ready(Ok(None)),
            };
            return Poll::Ready(Ok(Some(event)))
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
