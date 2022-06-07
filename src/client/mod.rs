pub use client::{Client, ClientReceiver, ClientFuture, ClientEvent, AcceptPubkeySender};

#[macro_use] mod pump;
mod auth;
mod auth_method;
mod client;
mod client_state;
mod negotiate;
mod recv;

/*

pub struct Channel;
pub struct ChannelReceiver;

impl Channel {
    pub fn send_data(&self, data: Bytes, data_type: DataType) -> impl Future<Output = Result<()>>;
    pub fn close(self);
}

impl ChannelReceiver {
    pub fn poll_recv(&mut self) -> Poll<Option<ChannelEvent>>;
    pub async fn recv(&mut self) -> Option<ChannelEvent>;
}

#[non_exhaustive]
pub enum ChannelEvent {
    Data(Bytes, DataType),
    Eof,
}


pub struct Session;
pub struct SessionReceiver;

impl Session {
    pub fn env(&self, name: Bytes, value: Bytes) -> ChannelRequest;
    pub fn exec(&self, command: Bytes) -> ChannelRequest;
}

impl Deref for Session {
    type Target = Channel;
}

impl SessionReceiver {
    pub fn poll_recv(&mut self) -> Poll<Option<SessionEvent>>;
    pub async fn recv(&mut self) -> Option<SessionEvent>;
}

#[non_exhaustive]
pub enum SessionEvent {
    Data(Bytes, DataType),
    Eof,
    XonXoff(bool),
    Exit(Exit),
}


#[must_use]
pub struct ChannelRequest;

impl ChannelRequest {
    pub fn want_reply(self) -> impl Future<Output = Result<()>>;
    pub fn no_reply(self);
}
*/
