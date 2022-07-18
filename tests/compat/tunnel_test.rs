use anyhow::{Result, bail, ensure, Context as _};
use bytes::Bytes;
use futures::future::BoxFuture;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use crate::{TestSuite, TestCase};
use crate::nursery::Nursery;
use crate::smoke_test::authenticate_alice;

pub fn collect(suite: &mut TestSuite) {
    suite.add(TestCase::new("tunnel_local_simple", test_local_simple)
        .except_servers(vec!["paramiko", "tinyssh"]));
}


async fn test_local_simple(socket: TcpStream) -> Result<()> {
    test_local(socket, |client, local_ip| async move {
        let (nursery, mut nursery_stream) = Nursery::new();

        let listener = TcpListener::bind((local_ip, 0)).await?;
        let local_port = listener.local_addr()?.port();
        nursery.spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            stream.write_all(b"server-to-client" as &[u8]).await?;
            stream.shutdown().await?;

            let mut recvd = Vec::new();
            stream.read_to_end(&mut recvd).await?;
            ensure!(&recvd == &b"client-to-server", "received {:?}", recvd);

            Ok(())
        });

        nursery.spawn(async move {
            let (tunnel, mut tunnel_rx) = client.connect_tunnel(
                makiko::ChannelConfig::default(),
                (local_ip.to_string(), local_port),
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            ).await.context("could not open tunnel")?;

            let mut recvd = Vec::new();
            loop {
                let event = tunnel_rx.recv().await?;
                match event {
                    Some(makiko::TunnelEvent::Data(data)) => recvd.extend_from_slice(&data),
                    Some(makiko::TunnelEvent::Eof) => break,
                    _ => bail!("unexpected event {:?}, expected Data or Eof", event),
                }
            }
            ensure!(recvd.as_slice() == b"server-to-client", "received {:?}", recvd);

            tunnel.send_data(Bytes::copy_from_slice(b"client-to-server" as &[u8])).await?;
            tunnel.send_eof().await?;
            match tunnel_rx.recv().await? {
                None => {},
                Some(event) => bail!("unexpected event {:?}, expected None", event),
            }

            Ok(())
        });

        drop(nursery);
        nursery_stream.try_run().await
    }).await
}

async fn test_local<F, Fut>(socket: TcpStream, f: F) -> Result<()>
    where F: FnOnce(makiko::Client, IpAddr) -> Fut + Send + Sync + 'static,
          Fut: Future<Output = Result<()>> + Send + Sync + 'static,
{
    test_local_inner(socket, Box::new(move |c, addr| Box::pin(f(c, addr)))).await
}

async fn test_local_inner(
    socket: TcpStream,
    f: Box<dyn FnOnce(makiko::Client, IpAddr) -> BoxFuture<'static, Result<()>> + Sync + Send>,
) -> Result<()> {
    let local_addr = socket.local_addr()?;
    let (nursery, mut nursery_stream) = Nursery::new();
    let config = makiko::ClientConfig::default_compatible_less_secure();
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
        authenticate_alice(&client).await?;
        f(client.clone(), local_addr.ip()).await?;
        client.disconnect(makiko::DisconnectError::by_app())?;
        Ok(())
    });

    drop(nursery);
    nursery_stream.try_run().await
}
