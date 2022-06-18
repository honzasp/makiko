use bytes::BytesMut;
use futures_core::ready;
use rand::{CryptoRng, RngCore};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};


pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

// adapted from `tokio_util::io::poll_read_buf`
pub fn poll_read_buf(
    stream: Pin<&mut dyn AsyncReadWrite>,
    cx: &mut Context,
    buf: &mut BytesMut,
) -> Poll<std::io::Result<usize>> {
    use bytes::BufMut as _;
    use std::mem::MaybeUninit;
    use tokio::io::ReadBuf;

    assert!(buf.has_remaining_mut());

    let n = {
        let dst = buf.chunk_mut();
        let dst = unsafe { &mut *(dst as *mut _ as *mut [MaybeUninit<u8>]) };
        let mut read_buf = ReadBuf::uninit(dst);
        let ptr = read_buf.filled().as_ptr();
        ready!(stream.poll_read(cx, &mut read_buf))?;

        assert_eq!(ptr, read_buf.filled().as_ptr());
        read_buf.filled().len()
    };

    unsafe { buf.advance_mut(n); }

    Poll::Ready(Ok(n))
}



// adapted from an unpublished version of `rng_core`
pub trait CryptoRngCore: CryptoRng + RngCore {
    fn as_rngcore(&mut self) -> &mut dyn RngCore;
}

impl<T: CryptoRng + RngCore> CryptoRngCore for T {
    fn as_rngcore(&mut self) -> &mut dyn RngCore {
        self
    }
}
