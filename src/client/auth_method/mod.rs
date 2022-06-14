use bytes::Bytes;
use std::task::Poll;
use crate::codec::PacketDecode;
use crate::error::Result;
use super::auth::AuthFailure;

pub mod none;
pub mod password;

pub trait AuthMethod {
    fn recv_success(&mut self) -> Result<()>;
    fn recv_failure(&mut self, failure: AuthFailure) -> Result<()>;
    fn recv_packet(&mut self, msg_id: u8, payload: &mut PacketDecode) -> Result<()>;
    fn send_packet(&mut self) -> Result<Option<Bytes>>;
    fn poll(&mut self) -> Poll<Result<()>>;
}
