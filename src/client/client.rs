use bytes::Bytes;
use derivative::Derivative;
use parking_lot::Mutex;
use pin_project::pin_project;
use rand::rngs::OsRng;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use crate::cipher::{self, CipherAlgo};
use crate::codec::{PacketDecode, PacketEncode};
use crate::error::{Error, Result, DisconnectError};
use crate::kex::{self, KexAlgo};
use crate::mac::{self, MacAlgo};
use crate::pubkey::{self, PubkeyAlgo, Pubkey, Privkey};
use super::{auth, negotiate};
use super::auth_method::none::{AuthNone, AuthNoneResult};
use super::auth_method::password::{AuthPassword, AuthPasswordResult};
use super::auth_method::pubkey::{AuthPubkey, AuthPubkeyResult, CheckPubkey};
use super::channel::{Channel, ChannelReceiver, ChannelConfig};
use super::client_event::ClientReceiver;
use super::client_state::{self, ClientState};
use super::conn::{self, OpenChannel};
use super::session::{Session, SessionReceiver};
use super::tunnel::{Tunnel, TunnelReceiver};

/// Handle to an SSH connection.
///
/// Use this object to send requests to the SSH server. In tandem, you will also need to use
/// [`ClientReceiver`] to handle events that we receive from the server, and [`ClientFuture`] to
/// perform the actual I/O.
///
/// To open a connection, pass your I/O stream (such as `tokio::net::TcpStream`) to
/// [`Client::open()`] and perform authentication using one of the `auth_*` methods. Once
/// you are authenticated, you can open a [`Session`] and execute a program. You can also open
/// multiple sessions from a single connection.
///
/// At the same time, you must handle events from the [`ClientReceiver`] and poll the
/// [`ClientFuture`] (probably from a different task).
///
/// You can cheaply clone this object and safely share the clones between tasks.
#[derive(Clone)]
pub struct Client {
    pub(super) client_st: Weak<Mutex<ClientState>>,
}

impl Client {
    /// Create an SSH connection from an existing stream.
    ///
    /// We initialize the client, but do not perform any I/O in this method. You should use the
    /// returned objects as follows:
    ///
    /// - [`Client`] allows you to interact with the SSH client. You should use it to authenticate
    /// yourself to the server and then you can open channels or sessions.
    /// - [`ClientReceiver`] is the receiving half of the client. It produces
    /// [`ClientEvent`][super::ClientEvent]s, which mostly correspond to actions initiated by the
    /// server. The only event that you need to handle is
    /// [`ClientEvent::ServerPubkey`][super::ClientEvent::ServerPubkey]. However, you **must**
    /// receive these events in a timely manner, otherwise the client will stall.
    /// - [`ClientFuture`] is a future that you must poll to drive the connection state machine
    /// forward. You will usually spawn a task for this future.
    pub fn open<IO>(stream: IO, config: ClientConfig) -> Result<(Client, ClientReceiver, ClientFuture<IO>)>
        where IO: AsyncRead + AsyncWrite
    {
        let rng = Box::new(OsRng);
        let (event_tx, event_rx) = mpsc::channel(1);
        let client_st = client_state::new_client(config, rng, event_tx)?;
        let client_st = Arc::new(Mutex::new(client_st));

        let client = Client { client_st: Arc::downgrade(&client_st) };
        let client_rx = ClientReceiver {
            client_st: Arc::downgrade(&client_st),
            event_rx,
            specialize_channels: true,
        };
        let client_fut = ClientFuture { client_st, stream };
        Ok((client, client_rx, client_fut))
    }

    fn upgrade(&self) -> Result<Arc<Mutex<ClientState>>> {
        self.client_st.upgrade().ok_or(Error::ClientClosed)
    }

    /// Try to authenticate using the "none" method.
    ///
    /// The "none" method (RFC 4252, section 5.2) is useful in two situations:
    ///
    /// - The user can be "authorized" without any authorization, e.g. if the user has a blank
    /// password. Note that most SSH servers disable blank passwords by default.
    /// - You want to determine the list of authentication methods for this user, so you expect to
    /// get an [`AuthFailure`][auth::AuthFailure] (inside [`AuthNoneResult::Failure`]) and look at
    /// the [list of methods that can continue][auth::AuthFailure::methods_can_continue].
    ///
    /// If a previous authentication attempt was successful, this call immediately succeeds. If you
    /// start another authentication attempt before this attempt is resolved, it will fail with
    /// [`Error::AuthPending`].
    pub async fn auth_none(&self, username: String) -> Result<AuthNoneResult> {
        let (result_tx, result_rx) = oneshot::channel();
        let method = AuthNone::new(username, result_tx);
        auth::start_method(&mut self.upgrade()?.lock(), Box::new(method))?;
        result_rx.await.map_err(|_| Error::AuthAborted)
    }

    /// Try to authenticate using the "password" method.
    ///
    /// Technically, the "password" method (RFC 4252, section 8) allows you to change the password
    /// during authentication, but nobody seems to implement it (neither servers nor client), so we
    /// don't support that.
    ///
    /// If a previous authentication attempt was successful, this call immediately succeeds. If you
    /// start another authentication attempt before this attempt is resolved, it will fail with
    /// [`Error::AuthPending`].
    pub async fn auth_password(&self, username: String, password: String) -> Result<AuthPasswordResult> {
        let (result_tx, result_rx) = oneshot::channel();
        let method = AuthPassword::new(username, password, result_tx);
        auth::start_method(&mut self.upgrade()?.lock(), Box::new(method))?;
        result_rx.await.map_err(|_| Error::AuthAborted)
    }

    /// Try to authenticate using the "publickey" method.
    ///
    /// With the "publickey" method (RFC 4252, section 7), the server knows your public key and you
    /// prove that you own the corresponding private key.
    ///
    /// You must specify the private key `privkey` and also `pubkey_algo`, the pubkey algorithm
    /// that is used to prove that you own the private key (see [`Pubkey::algos_secure()`] and
    /// [`Pubkey::algos_compatible_less_secure()`]). If you supply `pubkey_algo` that is not
    /// compatible with the `privkey`, you will get an [`Error::PrivkeyFormat`].
    ///
    /// If a previous authentication attempt was successful, this call immediately succeeds. If you
    /// start another authentication attempt before this attempt is resolved, it will fail with
    /// [`Error::AuthPending`].
    pub async fn auth_pubkey(
        &self,
        username: String,
        privkey: Privkey,
        pubkey_algo: &'static PubkeyAlgo,
    ) -> Result<AuthPubkeyResult> {
        let (result_tx, result_rx) = oneshot::channel();
        let method = AuthPubkey::new(username, privkey, pubkey_algo, result_tx);
        auth::start_method(&mut self.upgrade()?.lock(), Box::new(method))?;
        result_rx.await.map_err(|_| Error::AuthAborted)?
    }

    /// Check whether "publickey" authentication method would be acceptable.
    ///
    /// Before attempting the "publickey" authentication method using
    /// [`auth_pubkey()`][Self::auth_pubkey()], you may ask the server whether authentication using
    /// the given `username`, `pubkey` and `pubkey_algo` would be acceptable.
    pub async fn check_pubkey(
        &self,
        username: String,
        pubkey: &Pubkey,
        pubkey_algo: &'static PubkeyAlgo,
    ) -> Result<bool> {
        let (result_tx, result_rx) = oneshot::channel();
        let method = CheckPubkey::new(username, pubkey, pubkey_algo, result_tx);
        auth::start_method(&mut self.upgrade()?.lock(), Box::new(method))?;
        result_rx.await.map_err(|_| Error::AuthAborted)
    }

    /// Get the public key algorithms that the server supports for authentication.
    ///
    /// Returns a list of public key algorithm names that the server claims to support for
    /// "publickey" authentication (see [`Self::auth_pubkey()`]). For example, you can use this
    /// information to select which algorithm to use in case of a
    /// [`RsaPrivkey`][crate::pubkey::RsaPrivkey], which supports multiple algorithms.
    /// 
    /// The server sends this information using the SSH extension packet (RFC 8308, section
    /// 3.1). If we haven't received this packet, this method returns `None`. Unfortunately, before
    /// you start authenticating, `None` might mean that the server sent the packet, but we
    /// simply haven't received it yet. We suggest that you call [`Self::auth_none()`] and then
    /// call this method: in this case you can be sure that if the server supports this extension,
    /// this method returns `Some`.
    pub fn auth_pubkey_algo_names(&self) -> Result<Option<Vec<String>>> {
        Ok(self.upgrade()?.lock().their_ext_info.auth_pubkey_algo_names.clone())
    }

    /// Return true if the server has authenticated you.
    ///
    /// You must use one of the `auth_*` methods to authenticate.
    pub fn is_authenticated(&self) -> Result<bool> {
        Ok(auth::is_authenticated(&self.upgrade()?.lock()))
    }

    /// Open an SSH session to execute a program or the shell.
    ///
    /// If the session is opened successfully, you receive two objects:
    ///
    /// - [`Session`] is the handle for interacting with the session and sending data to the
    /// server.
    /// - [`SessionReceiver`] receives the [`SessionEvent`][super::SessionEvent]s produced by the
    /// session. You **must** receive these events in time, otherwise the client will stall.
    ///
    /// You can open many sessions in parallel, the SSH protocol will multiplex the sessions over
    /// the underlying connection under the hood.
    ///
    /// This method will wait until you are authenticated before doing anything.
    pub async fn open_session(&self, config: ChannelConfig) -> Result<(Session, SessionReceiver)> {
        Session::open(self, config).await
    }

    /// Open a tunnel by asking the server to connect to a host ("local forwarding").
    ///
    /// If the server accepts the request, it will try to connect to a host and port determined by
    /// `connect_addr`. The host may be either an IP address or a domain name. You should also
    /// specify the `originator_addr`, which should be the IP address and port of the machine from
    /// where the connection request originates.
    ///
    /// If the tunnel is opened successfully, you receive two objects:
    ///
    /// - [`Tunnel`] is the handle for sending data to the server.
    /// - [`TunnelReceiver`] receives the data from the server as
    /// [`TunnelEvent`][super::TunnelEvent]s. You **must** receive these events in time, otherwise
    /// the client will stall.
    ///
    /// If you need something that implements `AsyncRead` and `AsyncWrite`, consider using
    /// [`TunnelStream`][super::TunnelStream].
    ///
    /// You can open many tunnels or sessions in parallel, the SSH protocol will multiplex them
    /// over the underlying connection.
    ///
    /// This method will wait until you are authenticated before doing anything.
    pub async fn connect_tunnel(
        &self,
        config: ChannelConfig,
        connect_addr: (String, u16),
        originator_addr: (String, u16),
    ) -> Result<(Tunnel, TunnelReceiver)> {
        Tunnel::connect(self, config, connect_addr, originator_addr).await
    }

    /// Start listening for connections on the server and tunnels them to us ("remote
    /// forwarding").
    ///
    /// If the server accepts the request, it will try to bind to the host and port determined by
    /// `bind_addr`. The host might be an IP address, `"localhost"` (listen on loopback addresses)
    /// or `""` (listen on all addresses). The port might be 0, in which case the server assigns a
    /// free port and returns it in the response. Note that by default, most SSH servers will allow
    /// you to bind only to the loopback (localhost) address.
    ///
    /// Once somebody connects to the server on the bound address, you will receive
    /// [`ClientEvent::Tunnel`][super::ClientEvent::Tunnel] from the [`ClientReceiver`], and you
    /// then may accept the tunnel.
    ///
    /// The server responds with the bound port if you specified port 0.
    ///
    /// This method will wait until you are authenticated before doing anything.
    pub fn bind_tunnel(&self, bind_addr: (String, u16)) -> Result<ClientResp<Option<u16>>> {
        let (reply_tx, reply_rx) = oneshot::channel();

        let mut payload = PacketEncode::new();
        payload.put_str(&bind_addr.0);
        payload.put_u32(bind_addr.1 as u32);
        self.send_request(GlobalReq {
            request_type: "tcpip-forward".into(),
            payload: payload.finish(),
            reply_tx: Some(reply_tx),
        })?;

        Ok(ClientResp::map(reply_rx, |payload| {
            if payload.remaining_len() >= 4 {
                payload.get_u32().map(|x| Some(x as u16))
            } else {
                Ok(None)
            }
        }))
    }

    /// Stop listening for connections on the server.
    ///
    /// This cancels the remote forwarding set up by [`bind_tunnel()`][Self::bind_tunnel()].
    ///
    /// This method will wait until you are authenticated before doing anything.
    pub fn unbind_tunnel(&self, bind_addr: (String, u16)) -> Result<ClientResp<()>> {
        let (reply_tx, reply_rx) = oneshot::channel();

        let mut payload = PacketEncode::new();
        payload.put_str(&bind_addr.0);
        payload.put_u32(bind_addr.1 as u32);
        self.send_request(GlobalReq {
            request_type: "cancel-tcpip-forward".into(),
            payload: payload.finish(),
            reply_tx: Some(reply_tx),
        })?;

        Ok(ClientResp::map(reply_rx, |_payload| Ok(())))
    }

    /// Open a raw SSH channel (low level API).
    ///
    /// Use this to directly open an SSH channel, as described in RFC 4254, section 5.
    /// The bytes in `open_payload` will be appended to the `SSH_MSG_CHANNEL_OPEN` packet as the
    /// "channel specific data".
    ///
    /// If the channel is opened successfully, you receive three objects:
    ///
    /// - [`Channel`] is the handle for interacting with the channel and sending data to the
    /// server.
    /// - [`ChannelReceiver`] receives the [`ChannelEvent`][super::ChannelEvent]s produced by the
    /// channel. You **must** receive these events in time, otherwise the client will stall.
    /// - The `Bytes` contain the channel specific data from the
    /// `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` packet.
    ///
    /// You should use this method only if you really know what you are doing. To execute programs,
    /// please use [`open_session()`][Self::open_session()] and [`Session`], which wrap the
    /// [`Channel`] in an API that hides the details of the SSH protocol.
    ///
    /// This method will wait until you are authenticated before doing anything.
    pub async fn open_channel(&self, channel_type: String, config: ChannelConfig, open_payload: Bytes) 
        -> Result<(Channel, ChannelReceiver, Bytes)> 
    {
        let (result_tx, result_rx) = oneshot::channel();
        let open = OpenChannel {
            channel_type,
            recv_window_max: config.recv_window_max(),
            recv_packet_len_max: config.recv_packet_len_max(),
            open_payload,
            result_tx,
        };
        conn::open_channel(&mut self.upgrade()?.lock(), open);

        let result = result_rx.await.map_err(|_| Error::ChannelClosed)??;

        let channel = Channel {
            client_st: self.client_st.clone(), 
            channel_st: result.channel_st,
        };
        let channel_rx = ChannelReceiver {
            event_rx: result.event_rx,
        };
        Ok((channel, channel_rx, result.confirm_payload))
    }

    /// Send a keepalive request.
    ///
    /// This sends a `keepalive@openssh.com` global request to the server. The server will respond
    /// with an error, because this request is not defined, but this should be enough to keep the
    /// connection alive on the server. (This is the keepalive mechanism used by the OpenSSH client.)
    ///
    /// This method will wait until you are authenticated before it sends the request, and it will
    /// ignore the response (which should be an error).
    pub fn send_keepalive(&self) -> Result<()> {
        let (reply_tx, _reply_rx) = oneshot::channel();
        let req = GlobalReq {
            request_type: "keepalive@openssh.com".to_owned(),
            payload: Bytes::new(),
            reply_tx: Some(reply_tx),
        };
        self.send_request(req)
    }

    /// Send a global request (low level API).
    ///
    /// This sends `SSH_MSG_GLOBAL_REQUEST` to the server (RFC 4254, section 4). We simply enqueue
    /// the request and immediately return without any blocking, but you may use
    /// [`GlobalReq::reply_tx`] to wait for the reply.
    ///
    /// The request will not be sent until you are authenticated.
    pub fn send_request(&self, req: GlobalReq) -> Result<()> {
        conn::send_request(&mut self.upgrade()?.lock(), req)
    }

    /// Trigger key exchange (rekeying).
    ///
    /// Starts a key re-exchange (RFC 4253, section 9). Normally, we trigger the re-exchange
    /// automatically as needed (see [`ClientConfig::rekey_after_bytes`] and
    /// [`ClientConfig::rekey_after_duration`]), but you can use this method to start the exchange
    /// earlier.
    ///
    /// This method returns when the key exchange completes. If an exchange is already in progress,
    /// we simply wait for it to complete, we don't trigger another one.
    ///
    /// Note that according to the SSH specification, you should not trigger a key re-exchange
    /// before the authentication is complete. Some servers tolerate it, but others reject the
    /// exchange (OpenSSH) or disconnect (tinyssh). If the server rejects the request, you will get
    /// [`Error::RekeyRejected`].
    pub async fn rekey(&self) -> Result<()> {
        let (done_tx, done_rx) = oneshot::channel();
        negotiate::start_kex(&mut self.upgrade()?.lock(), Some(done_tx));
        done_rx.await.map_err(|_| Error::RekeyAborted)?
    }

    /// Disconnect from the server and close the client.
    ///
    /// We send a disconnection message to the server, so that they can be sure that we intended to
    /// close the connection (i.e., it was not closed by a man-in-the-middle attacker). After
    /// this message is sent, the [`ClientFuture`] returns.
    ///
    /// The `error` describes the reasons for the disconnection to the server. You may want to use
    /// [`DisconnectError::by_app()`] as a reasonable default value.
    pub fn disconnect(&self, error: DisconnectError) -> Result<()> {
        client_state::disconnect(&mut self.upgrade()?.lock(), error)
    }
}

/// Global request on an SSH connection (low level API).
///
/// Global requests are used to alter the state of the connection globally, without reference to
/// any channels, using `SSH_MSG_GLOBAL_REQUEST`, as described in RFC 4254, section 4.
#[derive(Debug)]
pub struct GlobalReq {
    /// The type of the request.
    pub request_type: String,

    /// The type-specifiec payload of the `SSH_MSG_GLOBAL_REQUEST` message.
    pub payload: Bytes,

    /// The reply to the request.
    ///
    /// For requests that you send to the server, you can create a [`oneshot`] pair and store the
    /// sender here. We will set the `want reply` field in the `SSH_MSG_GLOBAL_REQUEST`, wait for
    /// the reply from the server, and then send the reply to this sender. You may then receive the
    /// reply from the `oneshot` receiver that you created along with the sender.
    pub reply_tx: Option<oneshot::Sender<GlobalReply>>,
}

/// Reply to global request on an SSH connection (low level API).
///
/// This is a reply to `SSH_MSG_GLOBAL_REQUEST`, as described in RFC 4254, section 4.
#[derive(Debug)]
pub enum GlobalReply {
    /// Successful reply (`SSH_MSG_REQUEST_SUCCESS`) with response specific payload.
    Success(Bytes),
    /// Failure reply (`SSH_MSG_REQUEST_FAILURE` or `SSH_MSG_UNIMPLEMENTED`).
    Failure,
}

/// Future server response to a [global request][Client::send_request()].
///
/// You may either wait for the response using [`.wait()`][Self::wait()], or ignore the response
/// using [`.ignore()`][Self::ignore()].
#[derive(Derivative)]
#[derivative(Debug)]
#[must_use = "please use .wait().await to await the response, or .ignore() to ignore it"]
pub struct ClientResp<T> {
    reply_rx: oneshot::Receiver<GlobalReply>,
    #[derivative(Debug = "ignore")]
    map_fn: Box<dyn FnOnce(&mut PacketDecode) -> Result<T> + Send + Sync>,
}

impl<T> ClientResp<T> {
    fn map<F>(reply_rx: oneshot::Receiver<GlobalReply>, map_fn: F) -> Self 
        where F: FnOnce(&mut PacketDecode) -> Result<T> + Send + Sync + 'static
    {
        Self { reply_rx, map_fn: Box::new(map_fn) }
    }

    /// Wait for the response from the server.
    ///
    /// If the request failed, this returns an error ([`Error::GlobalReq`]).
    pub async fn wait(self) -> Result<T> {
        match self.reply_rx.await {
            Ok(GlobalReply::Success(payload)) => (self.map_fn)(&mut PacketDecode::new(payload)),
            Ok(GlobalReply::Failure) => Err(Error::GlobalReq),
            Err(_) => Err(Error::ClientClosed),
        }
    }

    /// Ignore the response.
    ///
    /// This just drops the [`ClientResp`], but it is a good practice to do this explicitly
    /// with this method.
    pub fn ignore(self) {}
}

/// Future that drives the connection state machine.
///
/// This future performs the reads and writes on `IO` and stores the state of the connection. You
/// must poll this future, usually by spawning a task for it. The future completes when the
/// connection is closed or when an error happens.
#[pin_project]
pub struct ClientFuture<IO> {
    client_st: Arc<Mutex<client_state::ClientState>>,
    #[pin] stream: IO,
}

impl<IO> ClientFuture<IO> {
    /// Deconstructs the future and gives the `IO` back to you.
    pub fn into_stream(self) -> IO {
        self.stream
    }
}

impl<IO> Future for ClientFuture<IO>
    where IO: AsyncRead + AsyncWrite
{
    type Output = Result<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
        let this = self.project();
        let mut client_st = this.client_st.lock();
        let res = client_state::poll_client(&mut client_st, this.stream, cx);
        if let Poll::Ready(Err(ref err)) = res {
            log::debug!("client future returned error: {:#}", err);
        }
        res
    }
}

/// Configuration of a [`Client`].
///
/// You should start from the [default][Default] instance, which has reasonable default
/// configuration, and modify it according to your needs. You may also find the method
/// [`ClientConfig::with()`] syntactically convenient.
///
/// If you need compatibility with old SSH servers that use outdated crypto, you may use
/// [`ClientConfig::default_compatible_less_secure()`]. However, this configuration is less secure.
///
/// This struct is `#[non_exhaustive]`, so we may add more fields without breaking backward
/// compatibility.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ClientConfig {
    /// Supported [key exchange algorithms][crate::kex].
    ///
    /// We will use the first algorithm that is also supported by the server. If there is no
    /// overlap, the connnection will abort.
    pub kex_algos: Vec<&'static KexAlgo>,

    /// Supported [server public key algorithms][crate::pubkey].
    ///
    /// We will use the first algorithm that is also supported by the server. If there is no
    /// overlap, the connnection will abort.
    pub server_pubkey_algos: Vec<&'static PubkeyAlgo>,

    /// Supported [encryption algorithms][crate::cipher].
    ///
    /// We will use the first algorithm that is also supported by the server. If there is no
    /// overlap, the connnection will abort.
    pub cipher_algos: Vec<&'static CipherAlgo>,

    /// Supported [message authentication algorithms][crate::mac].
    ///
    /// We will use the first algorithm that is also supported by the server. If there is no
    /// overlap, the connnection will abort.
    pub mac_algos: Vec<&'static MacAlgo>,

    /// Start key re-exchange after this many bytes.
    ///
    /// The amount of data that symmetric ciphers can securely encrypt is usually limited, so we
    /// should periodically repeat key exchange to generate new symmetric keys (RFC 4253, section
    /// 9). We will trigger a key re-exchange after this number of bytes is transmitted or
    /// received.
    ///
    /// By default, this configuration is set to 2^30 bytes (as recommended by the SSH
    /// specification). To ensure that security is not compromised by a mis-configuration, we only
    /// allow you to make this value lower: if you try to use a higher value, we ignore it and use
    /// the default instead.
    pub rekey_after_bytes: u64,

    /// Start key re-exchange after this amount of time.
    ///
    /// It is important to perform a key re-exchange after a certain number of bytes is encrypted
    /// (see [`Self::rekey_after_bytes`]), but the SSH specification also recommends to trigger the
    /// re-exchange after a certain amount of time, "just in case".
    ///
    /// By default, we perform the re-exchange after one hour (as recommended by the SSH
    /// specification).
    pub rekey_after_duration: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            kex_algos: vec![
                &kex::CURVE25519_SHA256, &kex::CURVE25519_SHA256_LIBSSH,
            ],
            server_pubkey_algos: vec![
                &pubkey::SSH_ED25519,
                &pubkey::RSA_SHA2_256, &pubkey::RSA_SHA2_512,
            ],
            cipher_algos: vec![
                &cipher::CHACHA20_POLY1305,
                &cipher::AES128_GCM, &cipher::AES256_GCM,
                &cipher::AES128_CTR, &cipher::AES192_CTR, &cipher::AES256_CTR,
            ],
            mac_algos: vec![
                &mac::HMAC_SHA2_256_ETM, &mac::HMAC_SHA2_512_ETM,
                &mac::HMAC_SHA2_256, &mac::HMAC_SHA2_512,
            ],
            rekey_after_bytes: 1 << 30,
            rekey_after_duration: Duration::from_secs(60 * 60),
        }
    }
}

impl ClientConfig {
    /// Default configuration with higher compatibility and lower security.
    ///
    /// Returns a configuration that includes support for subpar crypto, notably SHA-1, NIST curves
    /// and CBC-mode ciphers. Use at your own risk!
    pub fn default_compatible_less_secure() -> ClientConfig {
        Self::default().with(|c| {
            c.kex_algos.extend_from_slice(&[
                &kex::DIFFIE_HELLMAN_GROUP14_SHA256,
                &kex::DIFFIE_HELLMAN_GROUP16_SHA512,
                &kex::DIFFIE_HELLMAN_GROUP18_SHA512,
                &kex::DIFFIE_HELLMAN_GROUP14_SHA1,
            ]);
            c.server_pubkey_algos.extend_from_slice(&[
                &pubkey::ECDSA_SHA2_NISTP256,
                &pubkey::ECDSA_SHA2_NISTP384,
                &pubkey::SSH_RSA_SHA1,
            ]);
            c.cipher_algos.extend_from_slice(&[
                &cipher::AES128_CBC, &cipher::AES192_CBC, &cipher::AES256_CBC,
            ]);
            c.mac_algos.extend_from_slice(&[
                &mac::HMAC_SHA1_ETM, &mac::HMAC_SHA1,
            ]);
        })
    }

    /// Default configuration with highest compatibility and lowest security.
    ///
    /// Returns a configuration that supports outdated and insecure crypto.
    #[cfg(feature = "insecure-crypto")]
    pub fn default_insecure() -> ClientConfig {
        Self::default_compatible_less_secure().with(|c| {
            c.kex_algos.extend_from_slice(&[
                &kex::DIFFIE_HELLMAN_GROUP1_SHA1,
            ]);
            c.cipher_algos.extend_from_slice(&[
                &cipher::TDES_CBC,
            ]);
        })
    }

    /// Update the configuration in pseudo-builder pattern style.
    ///
    /// This method applies your closure to `self` and returns the mutated configuration.
    pub fn with<F: FnOnce(&mut Self)>(mut self, f: F) -> Self {
        f(&mut self);
        self
    }
}
