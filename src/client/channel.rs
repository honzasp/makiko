use bytes::Bytes;
use parking_lot::Mutex;
use std::future::Future;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot};
use crate::error::{Result, Error};
use super::channel_state::{self, ChannelState, ChannelSendData};
use super::client_state::ClientState;

#[derive(Clone)]
pub struct Channel {
    pub(super) client_st: Arc<Mutex<ClientState>>,
    pub(super) channel_st: Weak<Mutex<ChannelState>>,
}

impl Channel {
    pub fn send_request(&self, req: ChannelReq) -> Result<()> {
        let mut st = self.client_st.lock();
        let channel_st = self.get_channel_st()?;
        let mut channel_st = channel_st.lock();
        channel_state::send_request(&mut st, &mut channel_st, req)
    }

    pub async fn send_data(&self, data: Bytes, data_type: DataType) -> Result<()> {
        self.send_channel_data(ChannelSendData::Data(data, data_type))?.await
    }

    pub async fn send_eof(&self) -> Result<()> {
        self.send_channel_data(ChannelSendData::Eof)?.await
    }

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


#[derive(Debug)]
pub struct ChannelReceiver {
    pub(super) event_rx: mpsc::Receiver<ChannelEvent>,
}

impl ChannelReceiver {
    pub fn poll_recv(&mut self, cx: &mut Context) -> Poll<Option<ChannelEvent>> {
        self.event_rx.poll_recv(cx)
    }

    pub async fn recv(&mut self) -> Option<ChannelEvent> {
        self.event_rx.recv().await
    }
}


#[non_exhaustive]
pub enum ChannelEvent {
    Data(Bytes, DataType),
    Eof,
    Request(ChannelReq),
}


#[derive(Debug)]
pub struct ChannelReq {
    pub request_type: String,
    pub payload: Bytes,
    pub reply_tx: Option<oneshot::Sender<ChannelReply>>,
}

#[derive(Debug)]
pub enum ChannelReply {
    Success,
    Failure,
}


#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum DataType {
    Standard,
    Extended(u32),
}

pub const DATA_STANDARD: DataType = DataType::Standard;
pub const DATA_STDERR: DataType = DataType::Extended(1);
