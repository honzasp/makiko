use bytes::Bytes;
use derivative::Derivative;
use std::task::Poll;
use tokio::sync::oneshot;
use crate::codec::{PacketDecode, PacketEncode};
use crate::codes::msg;
use crate::error::{Result, Error};
use crate::pubkey::{PubkeyAlgo, Pubkey, Privkey};
use super::super::auth::AuthFailure;
use super::AuthMethod;

/// Result of the ["publickey"][crate::Client::auth_pubkey] authentication method.
#[derive(Debug, Clone)]
#[must_use]
pub enum AuthPubkeyResult {
    /// The authentication was successful.
    Success,

    /// The authentication was rejected.
    Failure(AuthFailure),
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct AuthPubkey {
    username: String,
    #[derivative(Debug = "ignore")]
    privkey: Privkey,
    pubkey_blob: Bytes,
    pubkey_algo: &'static PubkeyAlgo,
    request_sent: bool,
    result_tx: Option<oneshot::Sender<Result<AuthPubkeyResult>>>,
}

impl AuthPubkey {
    pub fn new(
        username: String,
        privkey: Privkey,
        pubkey_algo: &'static PubkeyAlgo,
        result_tx: oneshot::Sender<Result<AuthPubkeyResult>>,
    ) -> AuthPubkey {
        let pubkey_blob = privkey.pubkey().encode();
        AuthPubkey {
            username, privkey, pubkey_blob, pubkey_algo,
            request_sent: false, result_tx: Some(result_tx),
        }
    }

    fn send_result(&mut self, result: Result<AuthPubkeyResult>) {
        if let Some(result_tx) = self.result_tx.take() {
            let _ = result_tx.send(result);
        }
    }
}

impl AuthMethod for AuthPubkey {
    fn recv_success(&mut self) -> Result<()> {
        self.send_result(Ok(AuthPubkeyResult::Success));
        Ok(())
    }

    fn recv_failure(&mut self, failure: AuthFailure) -> Result<()> {
        self.send_result(Ok(AuthPubkeyResult::Failure(failure)));
        Ok(())
    }

    fn recv_packet(&mut self, msg_id: u8, _payload: &mut PacketDecode) -> Result<()> {
        Err(Error::PacketNotImplemented(msg_id))
    }

    fn send_packet(&mut self, session_id: &[u8]) -> Result<Option<Bytes>> {
        if !self.request_sent && self.result_tx.is_some() {
            let mut signed = PacketEncode::new();
            signed.put_bytes(session_id);
            signed.put_u8(msg::USERAUTH_REQUEST);
            signed.put_str(&self.username);
            signed.put_str("ssh-connection");
            signed.put_str("publickey");
            signed.put_bool(true);
            signed.put_str(self.pubkey_algo.name);
            signed.put_bytes(&self.pubkey_blob);
            let signed = signed.finish();

            let signature = match (self.pubkey_algo.sign)(&self.privkey, &signed) {
                Ok(signature) => signature,
                Err(err) => {
                    // if the signing failed, the user most likely gave us incompatible `privkey`
                    // and `pubkey_algo`. instead of raising the error from this method (and
                    // killing the whole client), we send the error to `result_tx`, so that it will
                    // be returned from `Client::auth_pubkey()`
                    if let Some(result_tx) = self.result_tx.take() {
                        let _ = result_tx.send(Err(err));
                    }
                    return Ok(None)
                },
            };

            let mut payload = PacketEncode::new();
            payload.put_u8(msg::USERAUTH_REQUEST);
            payload.put_str(&self.username);
            payload.put_str("ssh-connection");
            payload.put_str("publickey");
            payload.put_bool(true);
            payload.put_str(self.pubkey_algo.name);
            payload.put_bytes(&self.pubkey_blob);
            payload.put_bytes(&signature);
            
            log::debug!("sending SSH_MSG_USERAUTH_REQUEST for method 'publickey'");
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



#[derive(Debug)]
pub struct CheckPubkey {
    username: String,
    pubkey_blob: Bytes,
    pubkey_algo: &'static PubkeyAlgo,
    request_sent: bool,
    result_tx: Option<oneshot::Sender<bool>>,
}

impl CheckPubkey {
    pub fn new(
        username: String,
        pubkey: &Pubkey,
        pubkey_algo: &'static PubkeyAlgo,
        result_tx: oneshot::Sender<bool>,
    ) -> CheckPubkey {
        let pubkey_blob = pubkey.encode();
        CheckPubkey { username, pubkey_blob, pubkey_algo, request_sent: false, result_tx: Some(result_tx) }
    }

    fn send_result(&mut self, result: bool) {
        if let Some(result_tx) = self.result_tx.take() {
            let _ = result_tx.send(result);
        }
    }
}

impl AuthMethod for CheckPubkey {
    fn recv_success(&mut self) -> Result<()> {
        Err(Error::Protocol("received SSH_MSG_USERAUTH_SUCCESS when querying \
            whether a public key would be acceptable"))
    }

    fn recv_failure(&mut self, _failure: AuthFailure) -> Result<()> {
        self.send_result(false);
        Ok(())
    }

    fn recv_packet(&mut self, msg_id: u8, payload: &mut PacketDecode) -> Result<()> {
        if msg_id == msg::USERAUTH_PK_OK {
            let algo_name = payload.get_string()?;
            let pubkey_blob = payload.get_bytes()?;
            if algo_name.as_str() != self.pubkey_algo.name {
                return Err(Error::Protocol("received SSH_MSG_USERAUTH_PK_OK with unexpected algorithm name"));
            } else if pubkey_blob != self.pubkey_blob {
                return Err(Error::Protocol("received SSH_MSG_USERAUTH_PK_OK with unexpected public key"));
            }
            self.send_result(true);
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
            payload.put_str("publickey");
            payload.put_bool(false);
            payload.put_str(self.pubkey_algo.name);
            payload.put_bytes(&self.pubkey_blob);
            
            log::debug!("sending SSH_MSG_USERAUTH_REQUEST for querying method 'publickey'");
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



impl AuthPubkeyResult {
    /// Returns `Ok` if this is a success, `Err` otherwise.
    pub fn success_or_error(&self) -> Result<()> {
        match self {
            Self::Success => Ok(()),
            Self::Failure(_) => Err(Error::AuthFailed),
        }
    }
}
