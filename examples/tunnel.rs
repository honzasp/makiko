#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let sock = tokio::net::TcpStream::connect("127.0.0.1:2222").await?;

    let (client, mut client_rx, client_fut) = makiko::Client::open(sock)?;

    let client_fut_task = tokio::task::spawn(async move {
        match client_fut.await {
            Ok(_) => log::info!("client finished"),
            Err(err) => log::info!("client failed: {}", err),
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

    let mut open_payload = makiko::PacketEncode::new();
    open_payload.put_str("localhost");
    open_payload.put_u32(4000);
    open_payload.put_str("127.0.0.1");
    open_payload.put_u32(4000);
    let (channel, mut channel_rx, confirm_payload) =
        client.open_channel("direct-tcpip".into(), open_payload.finish()).await?;
    log::info!("confirm payload: {:?}", confirm_payload);

    let channel_task = tokio::task::spawn(async move {
        while let Some(event) = channel_rx.recv().await {
            match event {
                makiko::ChannelEvent::Data(data, data_type) =>
                    log::info!("received {:?}: {:?}", data_type, data),
                makiko::ChannelEvent::Eof =>
                    log::info!("received eof"),
                makiko::ChannelEvent::Request(req) =>
                    log::info!("received {:?}", req),
                _ => {},
            }
        }
        log::info!("channel was closed")
    });

    channel.send_data("a few bytes\nand some more\n".into(), makiko::DATA_STANDARD).await?;
    channel.send_eof().await?;
    log::info!("sent data to channel");
    channel.close();

    client_fut_task.await?;
    client_task.await?;
    channel_task.await?;

    Ok(())
}
