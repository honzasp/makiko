use tokio::sync::mpsc;
use crate::error::{Result, Error};
use super::channel::{Channel, ChannelEvent};

#[derive(Clone)]
pub struct Session(Channel)

impl Session {
    pub async fn env(&self, name: &[u8], value: &[u8]) -> Result<Reply<()>>;
    pub async fn shell(&self) -> Result<Reply<()>>;
    pub async fn exec(&self, command: &[u8]) -> Result<Reply<()>>;
    pub async fn signal(&self, signal_name: &str) -> Result<()>;
}

impl Deref for Session {
    type Target = Channel;
    fn deref(&self) -> &Channel { &self.0 }
}

pub struct Reply<T>;

impl<T> Reply<T> {
    pub async fn want_reply(self) -> Result<T>;
    pub fn no_reply(self);
}

#[non_exhaustive]
enum SessionEvent {
    Channel(ChannelEvent),
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
    event_rx: mpsc::Receiver<SessionEvent>,
}

