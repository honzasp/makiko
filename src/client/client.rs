use bytes::Bytes;
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
use super::auth;
use super::auth_method::none::{AuthNone, AuthNoneResult};
use super::channel::{Channel, ChannelReceiver};
use super::client_event::ClientEvent;
use super::client_state::{self, ClientState};
use super::conn::{self, OpenChannel};
use super::session::{Session, SessionReceiver};

#[derive(Clone)]
pub struct Client {
    client_st: Arc<Mutex<ClientState>>,
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

    pub async fn open_channel(&self, channel_type: String, open_payload: Bytes) 
        -> Result<(Channel, ChannelReceiver, Bytes)> 
    {
        let (confirmed_tx, confirmed_rx) = oneshot::channel();
        let open = OpenChannel {
            channel_type,
            recv_window: 100_000,
            recv_window_max: 100_000,
            recv_packet_len_max: 1_000_000,
            open_payload,
            confirmed_tx,
        };
        conn::open_channel(&mut self.client_st.lock(), open);

        let confirmed = confirmed_rx.await.map_err(|_| Error::ChannelClosed)??;

        let channel = Channel {
            client_st: self.client_st.clone(), 
            channel_st: confirmed.channel_st,
        };
        let channel_rx = ChannelReceiver {
            event_rx: confirmed.event_rx,
        };
        Ok((channel, channel_rx, confirmed.confirm_payload))
    }

    pub async fn open_session(&self) -> Result<(Session, SessionReceiver)> {
        Session::open(self).await
    }

    //pub async fn open_tunnel(&self, tunnel: OpenTunnel) -> Result<(Tunnel, TunnelReceiver)>;
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


