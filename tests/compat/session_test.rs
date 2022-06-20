use anyhow::{Result, ensure, bail, Context as _};
use bytes::{Bytes, BytesMut, Buf as _, BufMut as _};
use enclose::enclose;
use futures::future::BoxFuture;
use rand::{Rng as _, RngCore as _, SeedableRng as _};
use rand_chacha::ChaCha8Rng;
use std::cmp::min;
use std::future::Future;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use crate::{TestSuite, TestCase};
use crate::nursery::Nursery;

pub fn collect(suite: &mut TestSuite) {
    suite.add(TestCase::new("session_exec_cat", test_exec_cat));
}


async fn test_exec_cat(socket: TcpStream) -> Result<()> {
    test_session(socket, |session, mut session_rx| async move {
        let (nursery, mut nursery_stream) = Nursery::new();

        // receive stdout data from the session
        let (stdout_tx, mut stdout_rx) = mpsc::unbounded_channel();
        nursery.spawn(async move {
            let mut stdout_tx = Some(stdout_tx);
            let mut stdout_len = 0;
            while let Some(event) = session_rx.recv().await? {
                match event {
                    makiko::SessionEvent::StdoutData(chunk) => {
                        log::debug!("received {} bytes of stdout", chunk.len());
                        stdout_len += chunk.len();
                        let _ = stdout_tx.as_ref().context("received stdout after eof")?.send(chunk);
                    },
                    makiko::SessionEvent::StderrData(_) =>
                        bail!("received stderr data"),
                    makiko::SessionEvent::Eof => {
                        ensure!(stdout_tx.is_some(), "received eof twice");
                        stdout_tx = None;
                    },
                    makiko::SessionEvent::ExitStatus(status) =>
                        ensure!(status == 0, "received exit status {}", status),
                    makiko::SessionEvent::ExitSignal(signal) =>
                        bail!("received exit signal {:?}", signal),
                    _ => 
                        bail!("received unexpected event {:?}", event),
                }
            }
            log::debug!("session was closed after {} stdout bytes", stdout_len);
            ensure!(stdout_tx.is_none(), "session closed before eof");
            Ok(())
        });

        // send stdin data to the session
        let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel();
        nursery.spawn(enclose!{(session) async move {
            session.exec("cat".as_bytes())?.want_reply().await?;

            let mut rng = ChaCha8Rng::seed_from_u64(42);
            let mut stdin_len = 0;
            for _ in 0..100 {
                let chunk_len = rng.gen_range(0.0f64, 16.).exp2() as usize;
                let mut chunk = vec![0u8; chunk_len];
                rng.fill_bytes(&mut chunk);
                let chunk = Bytes::from(chunk);

                log::debug!("sending {} bytes to stdin", chunk.len());
                stdin_len += chunk.len();
                session.send_stdin(chunk.clone()).await?;
                stdin_tx.send(chunk)?;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }

            log::debug!("sending eof to stdin after {} bytes", stdin_len);
            session.send_eof().await?;
            Ok(())
        }});

        nursery.spawn(enclose!{(session => _session) async move {
            let mut stdin_data = BytesMut::new();
            let mut stdout_data = BytesMut::new();
            let mut zipped_len = 0;

            let mut stdin_closed = false;
            let mut stdout_closed = false;
            while !stdin_closed || !stdout_closed {
                tokio::select! {
                    res = stdin_rx.recv(), if !stdin_closed => match res {
                        Some(chunk) => stdin_data.put(chunk),
                        None => stdin_closed = true,
                    },
                    res = stdout_rx.recv(), if !stdout_closed => match res {
                        Some(chunk) => stdout_data.put(chunk),
                        None => stdout_closed = true,
                    },
                    _ = tokio::time::sleep(Duration::from_millis(1000)) =>
                        bail!("did not receive stdin or stdout in time"),
                }

                let zip_len = min(stdin_data.len(), stdout_data.len());
                ensure!(stdin_data[..zip_len] == stdout_data[..zip_len],
                    "stdout does not match stdin from pos {}, len {}", zipped_len, zip_len);
                stdin_data.advance(zip_len);
                stdout_data.advance(zip_len);
                log::debug!("advanced stdout-stdin zip by {} bytes (stdin {}, stdout {})",
                    zip_len, stdin_data.len(), stdout_data.len());
                zipped_len += zip_len;
            }

            ensure!(stdin_data.is_empty(), "did not receive enough stdout data");
            ensure!(stdout_data.is_empty(), "received too much stdout data");
            Ok(())
        }});

        drop(nursery);
        nursery_stream.try_run().await
    }).await
}



async fn test_session<F, Fut>(socket: TcpStream, f: F) -> Result<()>
    where F: FnOnce(makiko::Session, makiko::SessionReceiver) -> Fut + Send + Sync + 'static,
          Fut: Future<Output = Result<()>> + Send + Sync + 'static,
{
    test_session_inner(socket, Box::new(move |s, rx| Box::pin(f(s, rx)))).await
}

async fn test_session_inner(
    socket: TcpStream,
    f: Box<dyn FnOnce(makiko::Session, makiko::SessionReceiver) 
        -> BoxFuture<'static, Result<()>> + Sync + Send>,
) -> Result<()> {
    let (nursery, mut nursery_stream) = Nursery::new();
    let config = makiko::ClientConfig::default_compatible_insecure();
    let (client, mut client_rx, client_fut) = makiko::Client::open(socket, config)?;

    nursery.spawn(async move {
        client_fut.await?;
        Ok(())
    });

    nursery.spawn(async move {
        while let Some(event) = client_rx.recv().await {
            if let makiko::ClientEvent::ServerPubkey(_pubkey, accept_tx) = event {
                accept_tx.accept();
            }
        }
        Ok(())
    });

    nursery.spawn(async move {
        client.auth_password("alice".into(), "alicealice".into()).await
            .and_then(|res| res.success_or_error())
            .context("could not authenticate")?;

        let (session, session_rx) = client.open_session().await?;
        f(session, session_rx).await?;

        client.disconnect(makiko::DisconnectError::by_app())?;
        Ok(())
    });

    drop(nursery);
    nursery_stream.try_run().await
}