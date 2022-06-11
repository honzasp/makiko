use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let sock = tokio::net::TcpStream::connect("127.0.0.1:2222").await?;

    let (client, mut client_rx, client_fut) = makiko::Client::open(sock)?;

    let client_fut_task = tokio::task::spawn(async move {
        match client_fut.await {
            Ok(_) => log::info!("client finished"),
            Err(err) => log::error!("client failed: {}", err),
        }
    });


    let client_task = tokio::task::spawn(async move {
        while let Some(event) = client_rx.recv().await {
            match event {
                makiko::ClientEvent::ServerPubkey(pubkey, verify_tx) => {
                    log::info!("accepting server pubkey {}", pubkey);
                    verify_tx.accept();
                },
                _ => {},
            }
        }
        log::info!("client was closed");
    });

    log::info!("authentication: {:?}", client.auth_none("root".into()).await?);
    log::info!("authenticated? {:?}", client.is_authenticated());

    let (session, mut session_rx) = client.open_session().await?;

    let session_task = tokio::task::spawn(async move {
        loop {
            let event = match session_rx.recv().await {
                Ok(Some(event)) => event,
                Ok(None) => {
                    log::info!("session was closed");
                    break
                },
                Err(err) => {
                    log::error!("session receive failed: {}", err);
                    break
                },
            };

            match event {
                makiko::SessionEvent::StdoutData(data) =>
                    log::info!("received stdout: {:?}", data),
                makiko::SessionEvent::StderrData(data) =>
                    log::info!("received stderr: {:?}", data),
                makiko::SessionEvent::Eof =>
                    log::info!("received eof"),
                makiko::SessionEvent::ExitStatus(status) =>
                    log::info!("command exited with status {}", status),
                makiko::SessionEvent::ExitSignal(signal) =>
                    log::info!("command exited with signal {:?}", signal),
                _ => {},
            }
        }
    });

    //session.env("FOO".as_bytes(), "bar".as_bytes())?.want_reply().await?;
    //session.env("SPAM".as_bytes(), "eggs".as_bytes())?.no_reply();
    session.exec("echo 'foo bar' && cat && ls /".as_bytes())?.want_reply().await?;

    session.send_stdin("quick brown fox\n".into()).await?;
    session.send_stdin("spam eggs".into()).await?;
    session.send_eof().await?;

    session_task.await?;
    client_task.await?;
    client_fut_task.await?;

    Ok(())
}
