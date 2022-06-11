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
    AlgoNegotiate(&'static str),
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
    #[error("could not open channel")]
    ChannelOpenFailure(ChannelOpenFailure),
    #[error("channel request failed")]
    ChannelReqFailure,
    #[error("IO error when reading")]
    ReadIo(#[source] std::io::Error),
    #[error("IO error when writing")]
    WriteIo(#[source] std::io::Error),
    #[error("connection unexpectedly closed by peer")]
    PeerClosed,
    #[error("peer disconnected")]
    PeerDisconnected(Disconnect),
}

#[derive(Debug)]
pub struct Disconnect {
    pub reason_code: u32,
    pub description: String,
    pub description_lang: String,
}

#[derive(Debug)]
pub struct ChannelOpenFailure {
    pub reason_code: u32,
    pub description: String,
    pub description_lang: String,
}
