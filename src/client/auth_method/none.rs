use bytes::Bytes;
use std::task::Poll;
use tokio::sync::oneshot;
use crate::codec::{PacketDecode, PacketEncode};
use crate::codes::msg;
use crate::error::{Result, Error};
use super::super::auth::AuthFailure;
use super::AuthMethod;

/// Result of the ["none"][crate::Client::auth_none] authentication method.
#[derive(Debug, Clone)]
#[must_use]
pub enum AuthNoneResult {
    /// The authentication was successful.
    Success,

    /// The authentication was rejected.
    Failure(AuthFailure),
}

#[derive(Debug)]
pub struct AuthNone {
    username: String,
    request_sent: bool,
    result_tx: Option<oneshot::Sender<AuthNoneResult>>,
}

impl AuthNone {
    pub fn new(username: String, result_tx: oneshot::Sender<AuthNoneResult>) -> AuthNone {
        AuthNone { username, result_tx: Some(result_tx), request_sent: false }
    }
}

impl AuthMethod for AuthNone {
    fn recv_success(&mut self) -> Result<()> {
        if let Some(result_tx) = self.result_tx.take() {
            let _ = result_tx.send(AuthNoneResult::Success);
        }
        Ok(())
    }

    fn recv_failure(&mut self, failure: AuthFailure) -> Result<()> {
        if let Some(result_tx) = self.result_tx.take() {
            let _ = result_tx.send(AuthNoneResult::Failure(failure));
        }
        Ok(())
    }

    fn recv_packet(&mut self, msg_id: u8, _payload: &mut PacketDecode) -> Result<()> {
        Err(Error::PacketNotImplemented(msg_id))
    }

    fn send_packet(&mut self, _session_id: &[u8]) -> Result<Option<Bytes>> {
        if !self.request_sent && self.result_tx.is_some() {
            let mut payload = PacketEncode::new();
            payload.put_u8(msg::USERAUTH_REQUEST);
            payload.put_str(&self.username);
            payload.put_str("ssh-connection");
            payload.put_str("none");
            log::debug!("sending SSH_MSG_USERAUTH_REQUEST for method 'none'");
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

impl AuthNoneResult {
    /// Returns `Ok` if this is a success, `Err` otherwise.
    pub fn success_or_error(&self) -> Result<()> {
        match self {
            Self::Success => Ok(()),
            Self::Failure(_) => Err(Error::AuthFailed),
        }
    }
}
