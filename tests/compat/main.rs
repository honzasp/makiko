use anyhow::{Result, Context as _, ensure};
use bytes::{BytesMut, BufMut as _};
use bollard::Docker;
use bollard::container::{CreateContainerOptions, RemoveContainerOptions, Config};
use enclose::enclose;
use std::collections::HashMap;
use std::mem::drop;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use crate::nursery::Nursery;

mod nursery;

#[derive(Debug)]
struct SshServer {
    name: String,
    container_id: String,
    addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let docker = Docker::connect_with_local_defaults()
        .context("could not connect to docker daemon")?;

    let openssh = start_server(&docker, "openssh").await
        .context("could not start OpenSSH server in docker")?;
    smoke_test(&openssh).await
        .context("smoke test failed")?;
    stop_server(&docker, &openssh).await
        .context("could not stop OpenSSH server in docker")?;
    
    Ok(())
}

async fn start_server(docker: &Docker, name: &str) -> Result<SshServer> {
    let container_name = format!("makiko-test-{}", name);
    let image_name = format!("makiko-test/{}", name);

    // if the container already exists, force-remove it
    let first_inspect_res = docker.inspect_container(&container_name, None).await;
    if let Ok(_inspect_res) = first_inspect_res {
        log::info!("removing a running container {:?}", container_name);
        let remove_opts = RemoveContainerOptions {
            force: true,
            .. RemoveContainerOptions::default()
        };
        docker.remove_container(&container_name, Some(remove_opts)).await
            .context("could not force-remove running container")?;
    }

    // create and start a new container
    let create_opts = CreateContainerOptions { name: container_name.as_str() };
    let create_config = Config {
        exposed_ports: Some(vec![("22/tcp", HashMap::new())].into_iter().collect()),
        image: Some(image_name.as_str()),
        .. Config::default()
    };
    let create_res = docker.create_container(Some(create_opts), create_config).await
        .context("could not create container")?;

    docker.start_container::<String>(&create_res.id, None).await
        .context("could not start container")?;

    // inspect the container to get its IP address
    let inspect_res = docker.inspect_container(&create_res.id, None).await
        .context("could not inspect started container")?;
    let ip_addr = inspect_res
        .network_settings.context("expected 'network_settings' key")?
        .ip_address.context("expected 'ip_address' key")?
        .parse().context("could not parse 'ip_address'")?;

    log::info!("started SSH server {:?} at {:?} in container {:?}", name, ip_addr, create_res.id);

    // give the SSH server some time to start up and start accept()-ing
    tokio::time::sleep(Duration::from_millis(500)).await;

    Ok(SshServer {
        name: name.into(),
        container_id: create_res.id,
        addr: SocketAddr::new(ip_addr, 22),
    })
}

async fn stop_server(docker: &Docker, server: &SshServer) -> Result<()> {
    let remove_opts = RemoveContainerOptions {
        force: true,
        .. RemoveContainerOptions::default()
    };
    docker.remove_container(&server.container_id, Some(remove_opts)).await
        .context("could not force-remove container")?;
    log::info!("stopped SSH server {:?}", server.name);

    Ok(())
}

async fn connect_to_server(server: &SshServer) -> Result<TcpStream> {
    TcpStream::connect(server.addr).await
        .context("could not connect to SSH server")
}

async fn smoke_test(server: &SshServer) -> Result<()> {
    log::info!("running a smoke test on {:?}", server.name);
    let socket = connect_to_server(server).await?;
    let (nursery, mut nursery_stream) = Nursery::new();
    let (client, mut client_rx, client_fut) = makiko::Client::open(socket)?;

    nursery.spawn(async move {
        client_fut.await.context("error while handling SSH connection")?;
        log::debug!("client future finished");
        Ok(())
    });

    nursery.spawn(async move {
        while let Some(event) = client_rx.recv().await {
            log::debug!("received {:?}", event);
            if let makiko::ClientEvent::ServerPubkey(_pubkey, accept_tx) = event {
                accept_tx.accept();
            }
        }
        log::debug!("client was closed");
        Ok(())
    });

    nursery.spawn(enclose!{(nursery) async move {
        client.auth_password("alice".into(), "alicealice".into(), None).await
            .and_then(|res| res.success_or_error())
            .context("could not authenticate")?;

        let (session, mut session_rx) = client.open_session().await?;

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
            let _ = stdout_tx.send(stdout.freeze());
            log::debug!("session was closed");
            Ok(())
        });

        session.exec("whoami".as_bytes())
            .context("could not send exec request")?
            .want_reply().await
            .context("could not execute command")?;

        let stdout = stdout_rx.await
            .context("could not get stdout")?;
        log::debug!("received stdout {:?}", stdout);
        ensure!(stdout.as_ref() == "alice\n".as_bytes(), "received stdout: {:?}", stdout);

        client.disconnect(makiko::DisconnectError::by_app())?;
        Ok(())
    }});

    drop(nursery);
    nursery_stream.try_run().await
}
