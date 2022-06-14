use std::fmt;
use crate::numbers::{disconnect, open};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("cryptography error: {0}")]
    Crypto(&'static str),
    #[error("randomness error: {0}")]
    Random(&'static str),
    #[error("mac verification failed")]
    Mac,
    #[error("signature verification failed")]
    Signature,
    #[error("server public key was not accepted")]
    PubkeyAccept(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("could not decode bytes: {0}")]
    Decode(&'static str),
    #[error("could not negotiate algorithm: {0}")]
    AlgoNegotiate(AlgoNegotiateError),
    #[error("packet {0} not implemented")]
    PacketNotImplemented(u8),
    #[error("another authentication method is pending")]
    AuthMethodPending,
    #[error("authentication method was aborted")]
    AuthAborted,
    #[error("authentication failed")]
    AuthFailed,
    #[error("channel is closed")]
    ChannelClosed,
    #[error("could not open channel: {0}")]
    ChannelOpen(ChannelOpenError),
    #[error("channel request failed")]
    ChannelReq,
    #[error("IO error when reading")]
    ReadIo(#[source] std::io::Error),
    #[error("IO error when writing")]
    WriteIo(#[source] std::io::Error),
    #[error("connection unexpectedly closed by peer")]
    PeerClosed,
    #[error("peer disconnected: {0}")]
    PeerDisconnected(DisconnectError),
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("for {algo_name:}, our algos are {our_algos:?}, their algos are {their_algos:?}")]
pub struct AlgoNegotiateError {
    pub algo_name: String,
    pub our_algos: Vec<String>,
    pub their_algos: Vec<String>,
}

#[derive(Debug, Clone, thiserror::Error)]
pub struct DisconnectError {
    pub reason_code: u32,
    pub description: String,
    pub description_lang: String,
}

impl fmt::Display for DisconnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt_reason(f, disconnect::to_str(self.reason_code), self.reason_code, &self.description)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub struct ChannelOpenError {
    pub reason_code: u32,
    pub description: String,
    pub description_lang: String,
}

impl fmt::Display for ChannelOpenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt_reason(f, open::to_str(self.reason_code), self.reason_code, &self.description)
    }
}

fn fmt_reason(
    f: &mut fmt::Formatter,
    reason: Option<&'static str>,
    reason_code: u32,
    description: &str,
) -> fmt::Result {
    write!(f, "server returned error ")?;
    if let Some(reason) = reason {
        write!(f, "`{}` ({})", reason, reason_code)?;
    } else {
        write!(f, "{}", reason_code)?;
    }
    if !description.is_empty() {
        write!(f, ": {:?}", description)?;
    }
    Ok(())
}
