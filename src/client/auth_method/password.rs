use bytes::Bytes;
use std::task::Poll;
use tokio::sync::oneshot;
use crate::codec::{PacketDecode, PacketEncode};
use crate::codes::msg;
use crate::error::{Result, Error};
use super::super::auth::AuthFailure;
use super::AuthMethod;

/// Result of the ["password"][crate::Client::auth_password] authentication method.
#[derive(Debug, Clone)]
#[must_use]
pub enum AuthPasswordResult {
    /// The authentication was successful.
    ///
    /// If you requested a password change, the password has been changed.
    Success,

    /// The server asks you to change your password.
    ///
    /// The SSH protocol contains a mechanism to change the user password, but nobody seems to
    /// implement it (neither servers nor clients), so you will probably never encounter this in
    /// the wild.
    ChangePassword(AuthPasswordPrompt),

    /// The authentication was rejected.
    ///
    /// If you requested a password change and [`AuthFailure::partial_success`] is true,
    /// then the password has been changed, but more authentications are needed. Otherwise, if
    /// `partial_success` is false, the password has not been changed.
    Failure(AuthFailure),
}

/// Prompt that the server sends when asking you to change your password.
#[derive(Debug, Clone)]
pub struct AuthPasswordPrompt {
    /// Human-readable prompt.
    pub prompt: String,
    /// Language tag of `prompt` (per RFC 3066).
    pub prompt_lang: String,
}

#[derive(Debug)]
pub struct AuthPassword {
    username: String,
    password: String,
    request_sent: bool,
    result_tx: Option<oneshot::Sender<AuthPasswordResult>>,
}

impl AuthPassword {
    pub fn new(
        username: String,
        password: String,
        result_tx: oneshot::Sender<AuthPasswordResult>,
    ) -> AuthPassword {
        AuthPassword { username, password, request_sent: false, result_tx: Some(result_tx) }
    }
}

impl AuthMethod for AuthPassword {
    fn recv_success(&mut self) -> Result<()> {
        if let Some(result_tx) = self.result_tx.take() {
            let _ = result_tx.send(AuthPasswordResult::Success);
        }
        Ok(())
    }

    fn recv_failure(&mut self, failure: AuthFailure) -> Result<()> {
        if let Some(result_tx) = self.result_tx.take() {
            let _ = result_tx.send(AuthPasswordResult::Failure(failure));
        }
        Ok(())
    }

    fn recv_packet(&mut self, msg_id: u8, payload: &mut PacketDecode) -> Result<()> {
        if msg_id == msg::USERAUTH_PASSWD_CHANGEREQ {
            let prompt = payload.get_string()?;
            let prompt_lang = payload.get_string()?;
            if let Some(result_tx) = self.result_tx.take() {
                let password_prompt = AuthPasswordPrompt { prompt, prompt_lang };
                let _ = result_tx.send(AuthPasswordResult::ChangePassword(password_prompt));
            }
            Ok(())
        } else {
            Err(Error::PacketNotImplemented(msg_id))
        }
    }

    fn send_packet(&mut self, _session_id: &[u8]) -> Result<Option<Bytes>> {
        if !self.request_sent {
            let mut payload = PacketEncode::new();
            payload.put_u8(msg::USERAUTH_REQUEST);
            payload.put_str(&self.username);
            payload.put_str("ssh-connection");
            payload.put_str("password");
            payload.put_bool(false);
            payload.put_str(&self.password);
            log::debug!("sending SSH_MSG_USERAUTH_REQUEST for method 'password'");
            self.request_sent = true;
            return Ok(Some(payload.finish()))
        }
        Ok(None)
    }

    fn poll(&mut self) -> Poll<Result<()>> {
        if self.result_tx.is_some() {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl AuthPasswordResult {
    /// Returns `Ok` if this is a success, `Err` otherwise.
    pub fn success_or_error(&self) -> Result<()> {
        match self {
            Self::Success => Ok(()),
            Self::ChangePassword(_) | Self::Failure(_) => Err(Error::AuthFailed),
        }
    }
}
