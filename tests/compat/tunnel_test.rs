use anyhow::{Result, bail, ensure, Context as _};
use bytes::Bytes;
use futures::future::BoxFuture;
use std::future::Future;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, mpsc};
use crate::{TestSuite, TestCase};
use crate::nursery::Nursery;
use crate::smoke_test::authenticate_alice;

pub fn collect(suite: &mut TestSuite) {
    suite.add(TestCase::new("tunnel_local_simple", test_local_simple)
        .except_servers(vec!["paramiko", "tinyssh"]));
    suite.add(TestCase::new("tunnel_remote_simple_0", 
        |socket| test_remote_simple(socket, None))
        .except_servers(vec!["paramiko", "tinyssh", "lsh"]));
    suite.add(TestCase::new("tunnel_remote_simple_5000", 
        |socket| test_remote_simple(socket, Some(5000)))
        .except_servers(vec!["paramiko", "tinyssh", "lsh"]));
}

async fn test_local_simple(socket: TcpStream) -> Result<()> {
    test_tunnel(socket, |client, local_ip, _, _| async move {
        let (nursery, mut nursery_stream) = Nursery::new();

        let listener = TcpListener::bind((local_ip, 0)).await?;
        let local_port = listener.local_addr()?.port();
        nursery.spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            socket.write_all(b"server-to-client" as &[u8]).await?;
            socket.shutdown().await?;

            let mut recvd = Vec::new();
            socket.read_to_end(&mut recvd).await?;
            ensure!(&recvd == &b"client-to-server", "received {:?}", recvd);

            Ok(())
        });

        nursery.spawn(async move {
            let (tunnel, mut tunnel_rx) = client.connect_tunnel(
                makiko::ChannelConfig::default(),
                (local_ip.to_string(), local_port),
                ("10.20.30.40".into(), 50),
            ).await.context("could not open tunnel")?;

            check_tunnel(&tunnel, &mut tunnel_rx).await
        });

        drop(nursery);
        nursery_stream.try_run().await
    }).await
}

async fn test_remote_simple(socket: TcpStream, tunnel_port: Option<u16>) -> Result<()> {
    test_tunnel(socket, move |client, _, peer_ip, mut tunnel_accept_rx| async move {
        let bind_addr = ("".into(), tunnel_port.unwrap_or(0));
        let bound_port = client.bind_tunnel(bind_addr)?.wait().await?;
        let bound_port = match tunnel_port {
            Some(port) => port,
            None => bound_port.context("expected to receive the bound port")?,
        };

        let (nursery, mut nursery_stream) = Nursery::new();

        let (socket_addr_tx, socket_addr_rx) = oneshot::channel();
        nursery.spawn(async move {
            let mut socket = TcpStream::connect((peer_ip, bound_port)).await?;
            let _: Result<_, _> = socket_addr_tx.send((socket.local_addr()?, socket.peer_addr()?));

            socket.write_all(b"server-to-client" as &[u8]).await.context("could not write to socket")?;
            socket.shutdown().await.context("could not shutdown socket")?;

            let mut recvd = Vec::new();
            socket.read_to_end(&mut recvd).await.context("could not read from socket")?;
            ensure!(&recvd == &b"client-to-server", "received {:?}", recvd);

            Ok(())
        });

        nursery.spawn(async move {
            let accept = tunnel_accept_rx.recv().await;
            let accept = accept
                .context("did not receive an AcceptTunnel")?;
            let connected_addr = accept.connected_addr.clone();
            let originator_addr = accept.originator_addr.clone();

            let (tunnel, mut tunnel_rx) = accept.accept(makiko::ChannelConfig::default()).await
                .context("could not accept tunnel")?;

            let (socket_local_addr, socket_peer_addr) = socket_addr_rx.await?;
            ensure!(
                originator_addr == (socket_local_addr.ip().to_string(), socket_local_addr.port()),
                "originator addr {:?} != {:?}", originator_addr, socket_local_addr,
            );
            ensure!(
                connected_addr.1 == socket_peer_addr.port(),
                "connected addr {:?} != {:?}", connected_addr, socket_peer_addr,
            );

            check_tunnel(&tunnel, &mut tunnel_rx).await
        });

        drop(nursery);
        nursery_stream.try_run().await
    }).await
}

async fn check_tunnel(tunnel: &makiko::Tunnel, tunnel_rx: &mut makiko::TunnelReceiver) -> Result<()> {
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
}

async fn test_tunnel<F, Fut>(socket: TcpStream, f: F) -> Result<()>
    where F: FnOnce(makiko::Client, IpAddr, IpAddr, mpsc::Receiver<makiko::AcceptTunnel>)
            -> Fut + Send + Sync + 'static,
          Fut: Future<Output = Result<()>> + Send + Sync + 'static,
{
    test_tunnel_inner(socket, Box::new(move |c, local, peer, rx| Box::pin(f(c, local, peer, rx)))).await
}

async fn test_tunnel_inner(
    socket: TcpStream,
    f: Box<dyn FnOnce(makiko::Client, IpAddr, IpAddr, mpsc::Receiver<makiko::AcceptTunnel>)
        -> BoxFuture<'static, Result<()>> + Sync + Send>,
) -> Result<()> {
    let local_addr = socket.local_addr()?;
    let peer_addr = socket.peer_addr()?;
    let (nursery, mut nursery_stream) = Nursery::new();
    let config = makiko::ClientConfig::default_compatible_less_secure();
    let (client, mut client_rx, client_fut) = makiko::Client::open(socket, config)?;

    nursery.spawn(async move {
        client_fut.await?;
        Ok(())
    });

    let (tunnel_accept_tx, tunnel_accept_rx) = mpsc::channel(1);
    nursery.spawn(async move {
        while let Some(event) = client_rx.recv().await? {
            if let makiko::ClientEvent::ServerPubkey(_pubkey, accept_tx) = event {
                accept_tx.accept();
            } else if let makiko::ClientEvent::Tunnel(tunnel_accept) = event {
                tunnel_accept_tx.send(tunnel_accept).await
                    .context("could not handle ClientEvent::Tunnel")?;
            }
        }
        Ok(())
    });

    nursery.spawn(async move {
        authenticate_alice(&client).await?;
        f(client.clone(), local_addr.ip(), peer_addr.ip(), tunnel_accept_rx).await?;
        client.disconnect(makiko::DisconnectError::by_app())?;
        Ok(())
    });

    drop(nursery);
    nursery_stream.try_run().await
}
