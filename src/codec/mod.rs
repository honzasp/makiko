pub use self::packet_encode::PacketEncode;
pub use self::packet_decode::PacketDecode;
pub use self::recv_pipe::{RecvPipe, RecvPacket};
pub use self::send_pipe::SendPipe;

pub struct Codec {
    pub recv_pipe: RecvPipe,
    pub send_pipe: SendPipe,
}

mod packet_encode;
mod packet_decode;
mod recv_pipe;
mod send_pipe;
