pub use self::packet_encode::PacketEncode;
pub use self::packet_decode::PacketDecode;
pub(crate) use self::recv_pipe::{RecvPipe, RecvPacket};
pub(crate) use self::send_pipe::SendPipe;

pub(crate) struct Codec {
    pub recv_pipe: RecvPipe,
    pub send_pipe: SendPipe,
}

mod packet_encode;
mod packet_decode;
mod recv_pipe;
mod send_pipe;
