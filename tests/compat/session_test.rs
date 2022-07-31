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
use tokio::sync::{mpsc, oneshot};
use crate::{TestSuite, TestCase};
use crate::nursery::Nursery;
use crate::smoke_test::authenticate_alice;

pub fn collect(suite: &mut TestSuite) {
    suite.add(TestCase::new("session_cat", 
        |socket| test_cat(socket, makiko::ClientConfig::default_compatible_less_secure())));
    suite.add(TestCase::new("session_cat_rekey", 
        |socket| test_cat(socket, makiko::ClientConfig::default_compatible_less_secure().with(|c| {
            c.rekey_after_bytes = 10000;
        }))));
    suite.add(TestCase::new("session_exit_status_0", |socket| test_exit_status(socket, "true", 0)));
    suite.add(TestCase::new("session_exit_status_1", |socket| test_exit_status(socket, "false", 1)));
    suite.add(TestCase::new("session_exit_signal_kill",
        |socket| test_signal(socket, "KILL", TestSignal::Exit))
        .except_servers(vec!["paramiko"]));
    suite.add(TestCase::new("session_exit_signal_term",
        |socket| test_signal(socket, "TERM", TestSignal::Exit))
        .except_servers(vec!["paramiko"]));
    suite.add(TestCase::new("session_send_signal_kill",
        |socket| test_signal(socket, "KILL", TestSignal::Send))
        .except_servers(vec!["paramiko"]));
    suite.add(TestCase::new("session_send_signal_int",
        |socket| test_signal(socket, "INT", TestSignal::Send))
        .except_servers(vec!["paramiko"]));
    suite.add(TestCase::new("session_env", test_env)
        .only_servers(vec!["openssh"]));
    suite.add(TestCase::new("session_close", test_close)
        .except_servers(vec!["tinyssh"]));
}


async fn test_cat(socket: TcpStream, config: makiko::ClientConfig) -> Result<()> {
    test_session_config(socket, config, |session, mut session_rx| async move {
        let (nursery, mut nursery_stream) = Nursery::new();

        // receive stdout data from the session
        let (stdout_tx, mut stdout_rx) = mpsc::channel(8);
        nursery.spawn(async move {
            let mut stdout_tx = Some(stdout_tx);
            let mut stdout_len = 0;
            while let Some(event) = session_rx.recv().await? {
                match event {
                    makiko::SessionEvent::StdoutData(chunk) => {
                        log::debug!("received {} bytes of stdout", chunk.len());
                        stdout_len += chunk.len();
                        stdout_tx.as_ref().context("received stdout after eof")?.send(chunk).await?;
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
        let (stdin_tx, mut stdin_rx) = mpsc::channel(8);
        nursery.spawn(enclose!{(session) async move {
            session.exec("cat".as_bytes())?.wait().await?;

            let mut rng = ChaCha8Rng::seed_from_u64(42);
            let mut stdin_len = 0;
            for _ in 0..100 {
                let chunk_len = rng.gen_range(0.0f64..16.).exp2() as usize;
                let mut chunk = vec![0u8; chunk_len];
                rng.fill_bytes(&mut chunk);
                let chunk = Bytes::from(chunk);

                log::debug!("sending {} bytes to stdin", chunk.len());
                stdin_len += chunk.len();
                session.send_stdin(chunk.clone()).await?;
                stdin_tx.send(chunk).await?;
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

async fn test_exit_status(socket: TcpStream, command: &'static str, expected_status: u32) -> Result<()> {
    test_session(socket, move |session, mut session_rx| async move {
        let (nursery, mut nursery_stream) = Nursery::new();

        nursery.spawn(async move {
            let mut exit_recvd = 0;
            while let Some(event) = session_rx.recv().await? {
                if let makiko::SessionEvent::ExitStatus(status) = event {
                    ensure!(status == expected_status, "received status {}, expected {}",
                        status, expected_status);
                    exit_recvd += 1;
                } else if let makiko::SessionEvent::ExitSignal(signal) = event {
                    bail!("unexpected signal {:?}", signal);
                }
            }
            ensure!(exit_recvd == 1, "received exit status {} times", exit_recvd);
            Ok(())
        });

        session.exec(command.as_bytes())?.wait().await?;

        drop(nursery);
        nursery_stream.try_run().await
    }).await
}

#[derive(Copy, Clone)]
enum TestSignal {
    Exit,
    Send,
}

async fn test_signal(socket: TcpStream, expected_signal: &'static str, test: TestSignal) -> Result<()> {
    test_session(socket, move |session, mut session_rx| async move {
        let (nursery, mut nursery_stream) = Nursery::new();

        nursery.spawn(async move {
            let mut signal_recvd = 0;
            let mut status_recvd = 0;
            while let Some(event) = session_rx.recv().await? {
                if let makiko::SessionEvent::ExitSignal(signal) = event {
                    ensure!(signal.signal_name.as_str() == expected_signal,
                        "expected signal {:?}, got {:?}", expected_signal, signal.signal_name.as_str());
                    signal_recvd += 1;
                } else if let makiko::SessionEvent::ExitStatus(status) = event {
                    if matches!(test, TestSignal::Send) {
                        // some servers (lsh, tinyssh) return status 0 instead of signal in this case
                        ensure!(status == 0, "expected status 0, got {}", status);
                        status_recvd += 1;
                    } else {
                        bail!("unexpected exit status {}", status);
                    }
                }
            }
            ensure!(signal_recvd + status_recvd == 1,
                "received signal {} times and status {} times", signal_recvd, status_recvd);
            Ok(())
        });

        match test {
            TestSignal::Exit => {
                let command = format!("kill -{} $$", expected_signal);
                session.exec(command.as_bytes())?.wait().await?;
            },
            TestSignal::Send => {
                session.exec("sleep 2".as_bytes())?.wait().await?;
                session.signal(expected_signal)?;
            },
        }

        drop(nursery);
        nursery_stream.try_run().await
    }).await
}

async fn test_env(socket: TcpStream) -> Result<()> {
    test_session(socket, |session, mut session_rx| async move {
        let (nursery, mut nursery_stream) = Nursery::new();

        let (stdout_tx, stdout_rx) = oneshot::channel();
        nursery.spawn(async move {
            let mut stdout = BytesMut::new();
            while let Some(event) = session_rx.recv().await? {
                if let makiko::SessionEvent::StdoutData(chunk) = event {
                    stdout.put(chunk);
                } else if let makiko::SessionEvent::Eof = event {
                    break;
                }
            }
            let _: Result<_, _> = stdout_tx.send(stdout.freeze());
            log::debug!("session was closed");
            Ok(())
        });

        nursery.spawn(async move {
            // accepted env
            session.env("TEST_1".as_bytes(), "foo".as_bytes())?.wait().await?;
            session.env("TEST_2".as_bytes(), "bar".as_bytes())?.wait().await?;

            // rejected env
            match session.env("SPAM".as_bytes(), "eggs".as_bytes())?.wait().await {
                Ok(_) => bail!("expected a failure while setting env SPAM"),
                Err(makiko::Error::ChannelReq) => {},
                Err(err) => bail!("unexpected error while setting env SPAM: {}", err),
            }

            session.exec("echo $TEST_1 $TEST_2 $SPAM".as_bytes())?.wait().await?;

            let stdout = stdout_rx.await?;
            ensure!(stdout.as_ref() == "foo bar\n".as_bytes(), "received unexpected stdout {:?}", stdout);
            Ok(())
        });

        drop(nursery);
        nursery_stream.try_run().await
    }).await
}

async fn test_close(socket: TcpStream) -> Result<()> {
    test_session(socket, |session, mut session_rx| async move {
        let (nursery, mut nursery_stream) = Nursery::new();

        nursery.spawn(async move {
            while let Some(event) = session_rx.recv().await? {
                ensure!(!matches!(event,
                    makiko::SessionEvent::StdoutData(_) |
                    makiko::SessionEvent::StderrData(_) |
                    makiko::SessionEvent::ExitSignal(_)
                ), "received unexpected event {:?}", event);
            }
            Ok(())
        });

        nursery.spawn(async move {
            session.exec("cat".as_bytes())?.wait().await?;
            session.close()?;
            Ok(())
        });

        drop(nursery);
        nursery_stream.try_run().await
    }).await
}


async fn test_session<F, Fut>(socket: TcpStream, f: F) -> Result<()>
    where F: FnOnce(makiko::Session, makiko::SessionReceiver) -> Fut + Send + Sync + 'static,
          Fut: Future<Output = Result<()>> + Send + Sync + 'static,
{
    let config = makiko::ClientConfig::default_compatible_less_secure();
    test_session_inner(socket, config, Box::new(move |s, rx| Box::pin(f(s, rx)))).await
}

async fn test_session_config<F, Fut>(socket: TcpStream, config: makiko::ClientConfig, f: F) -> Result<()>
    where F: FnOnce(makiko::Session, makiko::SessionReceiver) -> Fut + Send + Sync + 'static,
          Fut: Future<Output = Result<()>> + Send + Sync + 'static,
{
    test_session_inner(socket, config, Box::new(move |s, rx| Box::pin(f(s, rx)))).await
}

async fn test_session_inner(
    socket: TcpStream,
    config: makiko::ClientConfig,
    f: Box<dyn FnOnce(makiko::Session, makiko::SessionReceiver) 
        -> BoxFuture<'static, Result<()>> + Sync + Send>,
) -> Result<()> {
    let (nursery, mut nursery_stream) = Nursery::new();
    let (client, mut client_rx, client_fut) = makiko::Client::open(socket, config)?;

    nursery.spawn(async move {
        client_fut.await?;
        Ok(())
    });

    nursery.spawn(async move {
        while let Some(event) = client_rx.recv().await? {
            if let makiko::ClientEvent::ServerPubkey(_pubkey, accept_tx) = event {
                accept_tx.accept();
            }
        }
        Ok(())
    });

    nursery.spawn(async move {
        authenticate_alice(&client).await?;
        let (session, session_rx) = client.open_session(makiko::ChannelConfig::default()).await?;
        f(session, session_rx).await?;

        client.disconnect(makiko::DisconnectError::by_app())?;
        Ok(())
    });

    drop(nursery);
    nursery_stream.try_run().await
}
