// Tutorial chapter 3: Public key authentication
//
// https://honzasp.github.io/makiko/tutorial/3-pubkey-auth.html
//
// You can run the example with
//
//     cargo run --example tutorial_3
//

#[tokio::main]
async fn main() {
    // Connect to the SSH server.
    let socket = tokio::net::TcpStream::connect(("localhost", 2222)).await
        .expect("Could not open a TCP socket");

    // Use the default secure configuration of the SSH client.
    let config = makiko::ClientConfig::default();
    //let config = makiko::ClientConfig::default_compatible_less_secure();

    // Create the SSH client.
    let (client, mut client_rx, client_fut) = makiko::Client::open(socket, config)
        .expect("Could not open client");

    // Spawn a Tokio task that polls the client.
    tokio::task::spawn(async move {
        client_fut.await.expect("Error in client future");
    });

    // Spawn another Tokio task to handle the client events.
    tokio::task::spawn(async move {
        loop {
            // Wait for the next event.
            let event = client_rx.recv().await
                .expect("Error while receiving client event");

            // Exit the loop when the client has closed.
            let Some(event) = event else {
                break
            };

            match event {
                // Handle the server public key: for now, we just accept all keys, but this makes
                // us susceptible to man-in-the-middle attacks!
                makiko::ClientEvent::ServerPubkey(pubkey, accept) => {
                    println!("Server pubkey type {}, fingerprint {}", pubkey.type_str(), pubkey.fingerprint());
                    accept.accept();
                },

                // All other events can be safely ignored
                _ => {},
            }
        }
    });

    // Decode our private key from PEM.
    let privkey = makiko::keys::decode_pem_privkey_nopass(PRIVKEY_PEM)
        .expect("Could not decode a private key from PEM")
        .privkey().cloned()
        .expect("Private key is encrypted");

    // Select an algorithm for public key authentication.
    let pubkey_algo = &makiko::pubkey::SSH_ED25519;

    // Try to authenticate with the private key
    let auth_res = client.auth_pubkey("edward".into(), privkey, pubkey_algo).await
        .expect("Error when trying to authenticate");

    // Deal with the possible outcomes of public key authentication.
    match auth_res {
        makiko::AuthPubkeyResult::Success => {
            println!("We have successfully authenticated using a private key");
        },
        makiko::AuthPubkeyResult::Failure(failure) => {
            panic!("The server rejected authentication: {:?}", failure);
        }
    }
}

const PRIVKEY_PEM: &[u8] = br#"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDyVJsRfh+NmkQKg2Dh6rPVodiQ3nC+dVoGMoMtYcbMJQAAAJBPdwHAT3cB
wAAAAAtzc2gtZWQyNTUxOQAAACDyVJsRfh+NmkQKg2Dh6rPVodiQ3nC+dVoGMoMtYcbMJQ
AAAEA5ct+xfc9qlJ4I2Jee8HIrAhN55yxmtUmvKpjT7q6QXPJUmxF+H42aRAqDYOHqs9Wh
2JDecL51WgYygy1hxswlAAAABmVkd2FyZAECAwQFBgc=
-----END OPENSSH PRIVATE KEY-----
"#;
