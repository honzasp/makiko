use bytes::Bytes;
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
use crate::{Error, Result, DisconnectError};
use crate::cipher::{self, CipherAlgo};
use crate::kex::{self, KexAlgo};
use crate::mac::{self, MacAlgo};
use crate::pubkey::{self, PubkeyAlgo, Pubkey, Privkey};
use super::{auth, negotiate};
use super::auth_method::none::{AuthNone, AuthNoneResult};
use super::auth_method::password::{AuthPassword, AuthPasswordResult};
use super::auth_method::pubkey::{AuthPubkey, AuthPubkeyResult, CheckPubkey};
use super::channel::{Channel, ChannelReceiver, ChannelConfig};
use super::client_event::ClientEvent;
use super::client_state::{self, ClientState};
use super::conn::{self, OpenChannel};
use super::session::{Session, SessionReceiver};

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
    client_st: Weak<Mutex<ClientState>>,
}

impl Client {
    /// Creates an SSH connection from an existing stream.
    ///
    /// We initialize the client, but do not perform any I/O in this method. You should use the
    /// returned objects as follows:
    ///
    /// - [`Client`] allows you to interact with the SSH client. You should use it to authenticate
    /// yourself to the server and then you can open channels or sessions.
    /// - [`ClientReceiver`] is the receiving half of the client. It produces [`ClientEvent`]s,
    /// which mostly correspond to actions initiated by the server. The only event that you need to
    /// handle is [`ClientEvent::ServerPubkey`]. However, you **must** receive these events in a
    /// timely manner, otherwise the client will stall.
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
        let client_rx = ClientReceiver { event_rx };
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
    /// that is used to prove that you own the private key. You can look up compatible algorithms
    /// in the documentation of your private key (such as
    /// [`Ed25519Privkey`][crate::pubkey::Ed25519Privkey] or
    /// [`RsaPrivkey`][crate::pubkey::RsaPrivkey]); if you supply `pubkey_algo` that is not
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

    /// Checks whether "publickey" authentication method would be acceptable.
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

    /// Returns true if the server has authenticated you.
    ///
    /// You must use one of the `auth_*` methods to authenticate.
    pub fn is_authenticated(&self) -> Result<bool> {
        Ok(auth::is_authenticated(&self.upgrade()?.lock()))
    }

    /// Opens an SSH session to execute a program or the shell.
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

    /// Opens a raw SSH channel (low level API).
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
        let (confirmed_tx, confirmed_rx) = oneshot::channel();
        let open = OpenChannel {
            channel_type,
            recv_window_max: config.recv_window_max.clamp(1000, u32::MAX as usize),
            recv_packet_len_max: config.recv_packet_len_max.clamp(200, u32::MAX as usize),
            open_payload,
            confirmed_tx,
        };
        conn::open_channel(&mut self.upgrade()?.lock(), open);

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

    /// Disconnects from the server and closes the client.
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

/// Receiving half of a [`Client`].
///
/// [`ClientReceiver`] provides you with the [`ClientEvent`]s, various events that are produced
/// during the life of the connection. You can usually ignore them, except
/// [`ClientEvent::ServerPubkey`], which is used to verify the server's public key (if you ignore
/// that event, we assume that you reject the key and we abort the connection). However, you
/// **must** receive these events, otherwise the client will stall when the internal buffer of
/// events fills up.
pub struct ClientReceiver {
    event_rx: mpsc::Receiver<ClientEvent>,
}

impl ClientReceiver {
    /// Wait for the next event.
    ///
    /// Returns `None` if the connection was closed.
    pub async fn recv(&mut self) -> Option<ClientEvent> {
        self.event_rx.recv().await
    }

    /// Poll-friendly variant of [`.recv()`][Self::recv()].
    pub fn poll_recv(&mut self, cx: &mut Context) -> Poll<Option<ClientEvent>> {
        self.event_rx.poll_recv(cx)
    }
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
        client_state::poll_client(&mut client_st, this.stream, cx)
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
    /// Returns a configuration that includes support for outdated and potentially insecure crypto,
    /// notably SHA-1. **Use at your own risk!**.
    pub fn default_compatible_less_secure() -> ClientConfig {
        Self::default().with(|c| {
            c.kex_algos.extend_from_slice(&[
                &kex::DIFFIE_HELLMAN_GROUP14_SHA256,
                &kex::DIFFIE_HELLMAN_GROUP16_SHA512,
                &kex::DIFFIE_HELLMAN_GROUP18_SHA512,
                &kex::DIFFIE_HELLMAN_GROUP14_SHA1,
            ]);
            c.server_pubkey_algos.push(&pubkey::SSH_RSA_SHA1);
            c.cipher_algos.extend_from_slice(&[
                &cipher::AES128_CBC, &cipher::AES192_CBC, &cipher::AES256_CBC
            ]);
            c.mac_algos.extend_from_slice(&[
                &mac::HMAC_SHA1_ETM, &mac::HMAC_SHA1
            ]);
        })
    }

    /// Mutate `self` in a closure.
    ///
    /// This method applies your closure to `self` and returns the mutated configuration.
    pub fn with<F: FnOnce(&mut Self)>(mut self, f: F) -> Self {
        f(&mut self);
        self
    }
}
