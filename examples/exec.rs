use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let sock = tokio::net::TcpStream::connect("127.0.0.1:2222").await?;

    let (client, mut client_rx, client_fut) = makiko::Client::open(sock)?;

    let client_fut_task = tokio::task::spawn(client_fut);

    let client_task = tokio::task::spawn(async move {
        while let Some(event) = client_rx.recv().await {
            match event {
                makiko::ClientEvent::ServerPubkey(pubkey, verify_tx) => {
                    log::info!("accepting server pubkey {}", pubkey);
                    verify_tx.accept();
                },
                /*
                makiko::ClientEvent::ForwardedTunnel(tunnel) => {
                    println!("forwarded tunnel from {:?} port {}",
                        tunnel.connected_host(), tunnel.connected_port());
                    let (channel, channel_rx) = tunnel.into_channel();
                },
                */
                _ => {},
            }
        }
    });

    println!("{:?}", client.auth_none("root".into()).await?);
    println!("{:?}", client.is_authenticated());

    client_fut_task.await??;
    client_task.await?;

    /*
    let (session, session_rx) = client.open_session().await?;

    let session_task = tokio::task::spawn(async move {
        while let Some(event) = session_rx.recv().await {
            makiko::SessionEvent::Data(chunk, makiko::DATA_STANDARD) =>
                println!("received {} bytes from stdout", chunk.len()),
            makiko::SessionEvent::Data(chunk, makiko::DATA_STDERR) =>
                println!("received {} bytes from stderr", chunk.len()),
            makiko::SessionEvent::Eof =>
                println!("received eof"),
            makiko::SessionEvent::XonXoff(client_can_do) =>
                println!("client can do xon-xoff: {:?}", client_can_do),
            makiko::SessionEvent::Exit(makiko::Exit::Status(status)) =>
                println!("command exited with status {}", status),
            makiko::SessionEvent::Exit(makiko::Exit::Signal(signal)) =>
                println!("command exited with signal {:?}", signal),
            _ => {},
        }
    });

    session.env("FOO", "bar").await?.want_reply().await?;
    session.env("SPAM", "eggs").await?.no_reply();
    session.exec("cat").await?.want_reply().await?;
    session.signal("KILL");

    session.send_data("foo bar", makiko::DATA_STANDARD).await?;
    session.send_data("spam eggs", makiko::DATA_STDERR).await?;
    session.send_eof().await?;
    session.close();
    */

    Ok(())
}
