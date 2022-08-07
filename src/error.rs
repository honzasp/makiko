use std::fmt;
use rsa::pkcs1;
use crate::codes::{disconnect, open};

/// Result type for our [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Error that occured while handling SSH connection.
///
/// This enum is `#[non_exhaustive]`, so we reserve the right to add more variants and don't
/// consider this to break backwards compatibility.
#[derive(thiserror::Error, Debug)]
#[allow(missing_docs)]
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
    #[error("algorithm is not compatible with this public key format")]
    PubkeyFormat,
    #[error("algorithm is not compatible with this private key format")]
    PrivkeyFormat,
    #[error("server public key was not accepted")]
    PubkeyAccept(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("could not decode bytes: {0}")]
    Decode(&'static str),
    #[error("could not negotiate algorithm: {0}")]
    AlgoNegotiate(AlgoNegotiateError),
    #[error("we do not implement packet {0}")]
    PacketNotImplemented(u8),
    #[error("authentication method was aborted")]
    AuthAborted,
    #[error("another authentication method is pending")]
    AuthPending,
    #[error("authentication failed")]
    AuthFailed,
    #[error("channel is closed")]
    ChannelClosed,
    #[error("could not open channel: {0}")]
    ChannelOpen(ChannelOpenError),
    #[error("channel request failed")]
    ChannelReq,
    #[error("global request failed")]
    GlobalReq,
    #[error("rekeying was aborted")]
    RekeyAborted,
    #[error("rekeying was rejected by the peer")]
    RekeyRejected,
    #[error("IO error when reading")]
    ReadIo(#[source] std::io::Error),
    #[error("IO error when writing")]
    WriteIo(#[source] std::io::Error),
    #[error("peer did not recognize our packet with seq {0}")]
    PeerRejectedPacket(u32),
    #[error("connection unexpectedly closed by peer")]
    PeerClosed,
    #[error("peer disconnected: {0}")]
    PeerDisconnected(DisconnectError),
    #[error("client is closed")]
    ClientClosed,
    #[error("client has already disconnected")]
    ClientDisconnected,
    #[error("could not parse PEM file")]
    Pem(pem::PemError),
    #[error("could not parse file in PKCS#1 format")]
    Pkcs1(pkcs1::Error),
    #[error("unexpected PEM tag {0:?}, expected {1:?}")]
    BadPemTag(String, String),
    #[error("bad passphrase when decoding key")]
    BadKeyPassphrase,
}

/// Error that occured because we could not negotiate an algorithm.
///
/// During the SSH key exchange, the client and the server must negotiate which cryptographic
/// algorithms (such as ciphers or MACs) to use, as described in RFC 4253, section 7.1. This error
/// occurs when there is no intersection between the set of algorithms supported by us (the client)
/// and by the server.
#[derive(Debug, Clone, thiserror::Error)]
#[error("for {algo_name:}, our algos are {our_algos:?}, their algos are {their_algos:?}")]
pub struct AlgoNegotiateError {
    /// Human readable name of the algorithm.
    pub algo_name: String,
    /// The set of algorithms supplied by us (the client).
    pub our_algos: Vec<String>,
    /// The set of algorithms supplied by them (the server).
    pub their_algos: Vec<String>,
}

/// Error that describes SSH disconnection.
///
/// This corresponds to the `SSH_MSG_DISCONNECT` packet described in RFC 4253, section 11.1.
#[derive(Debug, Clone, thiserror::Error)]
pub struct DisconnectError {
    /// Machine-readable reason code (see [`codes::disconnect`][crate::codes::disconnect]).
    pub reason_code: u32,
    /// Human-readable description of the error.
    pub description: String,
    /// Language tag of `description` (per RFC 3066).
    pub description_lang: String,
}

impl DisconnectError {
    /// Translates the [`reason_code`][Self::reason_code] into a string.
    pub fn reason_to_str(&self) -> Option<&'static str> {
        disconnect::to_str(self.reason_code)
    }

    /// Reasonable default instance for use with
    /// [`Client::disconnect()`][crate::Client::disconnect()].
    ///
    /// This instance has reason code `SSH_DISCONNECT_BY_APPLICATION` and a matching description.
    pub fn by_app() -> DisconnectError {
        DisconnectError {
            reason_code: disconnect::BY_APPLICATION,
            description: "disconnected by application".into(),
            description_lang: "".into(),
        }
    }
}

impl fmt::Display for DisconnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt_reason(f, disconnect::to_str(self.reason_code), self.reason_code, &self.description)
    }
}

/// Error that occured when opening a channel.
///
/// This corresponds to the `SSH_MSG_CHANNEL_OPEN_FAILURE` packet described in RFC 4254, section
/// 5.1.
#[derive(Debug, Clone, thiserror::Error)]
pub struct ChannelOpenError {
    /// Machine-readable reason code (see [`codes::open`][crate::codes::open]).
    pub reason_code: u32,
    /// Human-readable description of the error.
    pub description: String,
    /// Language tag of `description` (per RFC 3066).
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
