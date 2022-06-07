use parking_lot::Mutex;
use pin_project::pin_project;
use ring::rand::SystemRandom;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use crate::{Error, Result};
use crate::pubkey::Pubkey;
use super::{auth, client_state};
use super::auth_method::none::{AuthNone, AuthNoneResult};

#[derive(Clone)]
pub struct Client {
    #[allow(dead_code)] client_st: Arc<Mutex<client_state::ClientState>>,
}

impl Client {
    pub fn open<IO>(stream: IO) -> Result<(Client, ClientReceiver, ClientFuture<IO>)>
        where IO: AsyncRead + AsyncWrite
    {
        let rng = Box::new(SystemRandom::new());
        let (event_tx, event_rx) = mpsc::channel(1);
        let client_st = client_state::new_client(rng, event_tx)?;
        let client_st = Arc::new(Mutex::new(client_st));

        let client = Client { client_st: client_st.clone() };
        let client_rx = ClientReceiver { event_rx };
        let client_fut = ClientFuture { client_st, stream };
        Ok((client, client_rx, client_fut))
    }

    pub async fn auth_none(&self, username: String) -> Result<AuthNoneResult> {
        let (result_tx, result_rx) = oneshot::channel();
        let method = AuthNone::new(username, result_tx);
        auth::start_method(&mut self.client_st.lock(), Box::new(method))?;
        result_rx.await.map_err(|_| Error::AuthAborted)
    }

    pub fn is_authenticated(&self) -> bool {
        auth::is_authenticated(&self.client_st.lock())
    }

    //pub fn open_session(&self) -> impl Future<Output = Result<(Session, SessionReceiver)>>;

    //pub fn open_tunnel(&self, tunnel: OpenTunnel) -> impl Future<Output = Result<(Channel, ChannelReceiver)>>;
}

pub struct ClientReceiver {
    event_rx: mpsc::Receiver<ClientEvent>,
}

impl ClientReceiver {
    pub fn poll_recv(&mut self, cx: &mut Context) -> Poll<Option<ClientEvent>> {
        self.event_rx.poll_recv(cx)
    }

    pub async fn recv(&mut self) -> Option<ClientEvent> {
        self.event_rx.recv().await
    }
}

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

#[pin_project]
pub struct ClientFuture<IO> {
    client_st: Arc<Mutex<client_state::ClientState>>,
    #[pin] stream: IO,
}

impl<IO> Future for ClientFuture<IO>
    where IO: AsyncRead + AsyncWrite
{
    type Output = Result<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
        let this = self.project();
        let mut client_st = this.client_st.lock();
        client_state::poll_client(&mut client_st, this.stream, cx)
    }
}


