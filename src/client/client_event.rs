use tokio::sync::oneshot;
use crate::error::{Result, Error};
use crate::pubkey::Pubkey;

#[non_exhaustive]
pub enum ClientEvent {
    ServerPubkey(Pubkey, AcceptPubkeySender),
    DebugMsg(DebugMsg),
    AuthBanner(AuthBanner),
    //ForwardedTunnel(ForwardedTunnel),
}

#[derive(Debug)]
pub struct DebugMsg {
    pub always_display: bool,
    pub message: String,
    pub message_lang: String,
}

#[derive(Debug)]
pub struct AuthBanner {
    pub message: String,
    pub message_lang: String,
}


#[derive(Debug)]
pub struct AcceptPubkeySender {
    pub(super) accept_tx: oneshot::Sender<Result<PubkeyAccepted>>,
}

#[derive(Debug)]
pub(super) struct PubkeyAccepted(());

impl AcceptPubkeySender {
    pub fn accept(self) {
        let _ = self.accept_tx.send(Ok(PubkeyAccepted(())));
    }

    pub fn reject<E: std::error::Error + Send + Sync + 'static>(self, err: E) {
        let _ = self.accept_tx.send(Err(Error::PubkeyAccept(Box::new(err))));
    }
}

/*
pub struct ForwardedTunnel;

impl ForwardedTunnel {
    pub fn connected_host(&self) -> &str;
    pub fn connected_port(&self) -> u32;
    pub fn original_host(&self) -> &str;
    pub fn original_port(&self) -> u32;
    pub fn into_channel(self) -> (Channel, ChannelReceiver);
}
*/

