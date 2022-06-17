use tokio::sync::oneshot;
use crate::error::{Result, Error};
use crate::pubkey::Pubkey;

/// An event returned from [`ClientReceiver`][super::ClientReceiver].
///
/// These are "global" events that are related to the SSH connection, not to a particular
/// session/channel. You can safely ignore all events except [`ServerPubkey`][Self::ServerPubkey],
/// which you must handle in order to accept or reject the server's public key (if you don't handle
/// this event, the key will be rejected and we will abort the connection).
///
/// This enum is marked as `#[non_exhaustive]`, so that we can add new variants without breaking
/// backwards compatibility. It should always be safe to ignore any events that you don't intend to
/// handle.
#[non_exhaustive]
#[derive(Debug)]
pub enum ClientEvent {
    /// Server presented its public key and you should verify it.
    ///
    /// This event is produced as part of the SSH key exchange. You will always receive this event
    /// during the initial handshake, but you may also receive it again later on, when the
    /// connection is "rekeyed".
    ///
    /// The SSH protocol does not provide any mechanism to verify the identity of the server, so it
    /// is up to you. Please read RFC 4251, section 4.1 for more details and suggestions on how to
    /// deal with this problem.
    ///
    /// The [`Pubkey`] is the public key that the server provided as part of the key exchange. We
    /// have already verified that the server owns the private key. You should use the
    /// [`AcceptPubkeySender`] object to either [`.accept()`][AcceptPubkeySender::accept()] or
    /// [`.reject()`][AcceptPubkeySender::reject()] the key.
    ServerPubkey(Pubkey, AcceptPubkeySender),
    
    /// Server sent us a debugging message.
    ///
    /// This is the "debug message" (`SSH_MSG_DEBUG`) described in RFC 4253, section 11.3. You can
    /// simply ignore this event.
    DebugMsg(DebugMsg),

    /// Server sent a text that the user should see before authentication.
    ///
    /// This is the "banner message" (`SSH_MSG_USERAUTH_BANNER`) described in RFC 4252, section
    /// 5.2. Citing from the RFC, this message "may be relevant for getting legal protection". You
    /// can probably ignore this event.
    AuthBanner(AuthBanner),
}

/// Debugging message sent by the SSH server.
///
/// You might receive this in [`ClientEvent::DebugMsg`]. Please consult RFC 4253, section 11.3 for
/// details.
#[derive(Debug)]
pub struct DebugMsg {
    /// If true, you should display this message.
    pub always_display: bool,
    /// The debugging message string.
    pub message: String,
    /// Language tag of the message (as in RFC 3066).
    pub message_lang: String,
}

/// Banner message sent by the SSH server.
///
/// You might receive this in [`ClientEvent::AuthBanner`]. Please consult RFC 4252, section 5.2 for
/// details.
#[derive(Debug)]
pub struct AuthBanner {
    /// The banner message string.
    pub message: String,
    /// Language tag of the message (per RFC 3066).
    pub message_lang: String,
}


/// Tell us whether the server public key is valid.
///
/// You receive this object in [`ClientEvent::ServerPubkey`] and use it to tell us whether you
/// accept or reject the server public key. If you drop this object, it is treated as rejection.
#[derive(Debug)]
pub struct AcceptPubkeySender {
    pub(super) accept_tx: oneshot::Sender<Result<PubkeyAccepted>>,
}

/// A "witness" that the user has really called [`AcceptPubkeySender::accept()`].
#[derive(Debug)]
pub(super) struct PubkeyAccepted(());

impl AcceptPubkeySender {
    /// Accept the server public key.
    ///
    /// You assert that this public key really belongs to the server that you want to connect to.
    pub fn accept(self) {
        let _ = self.accept_tx.send(Ok(PubkeyAccepted(())));
    }

    /// Reject the server public key.
    ///
    /// The connection will be aborted with error `Error::PubkeyAccept(Box::new(err))`.
    pub fn reject<E: std::error::Error + Send + Sync + 'static>(self, err: E) {
        let _ = self.accept_tx.send(Err(Error::PubkeyAccept(Box::new(err))));
    }
}
