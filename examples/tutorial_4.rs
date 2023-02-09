// Tutorial chapter 4: Public key algorithm
//
// https://honzasp.github.io/makiko/tutorial/4-pubkey-algo.html
//
// You can run the example with
//
//     cargo run --example tutorial_4
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

                // All other events can be safely ignored.
                _ => {},
            }
        }
    });

    // Decode our private key from PEM.
    let privkey = makiko::keys::decode_pem_privkey_nopass(PRIVKEY_PEM)
        .expect("Could not decode a private key from PEM")
        .privkey().cloned()
        .expect("Private key is encrypted");

    // Get the public key from the private key.
    let pubkey = privkey.pubkey();

    // Get the public key algorithms supported by the key.
    let available_algos = pubkey.algos();

    // Try the algorithms one by one.
    let username: String = "ruth".into();
    for pubkey_algo in available_algos.iter().copied() {
        // Check whether this combination of a public key and algorithm would be acceptable to the
        // server.
        let check_ok = client.check_pubkey(username.clone(), &pubkey, pubkey_algo).await
            .expect("Error when checking a public key");

        // Skip this algorithm if the server rejected it.
        if !check_ok {
            println!("Server rejected public key and algorithm {:?}", pubkey_algo.name);
            continue;
        }

        // Try to authenticate using this algorithm.
        let auth_res = client.auth_pubkey(username.clone(), privkey.clone(), pubkey_algo).await
            .expect("Error when trying to authenticate");
        match auth_res {
            makiko::AuthPubkeyResult::Success => {
                println!("We have successfully authenticated using algorithm {:?}", pubkey_algo.name);
                break;
            },
            makiko::AuthPubkeyResult::Failure(_) => {
                println!("Authentication using public key and algorithm {:?} failed", pubkey_algo.name);
            },
        }
    }

    // Check that we have been authenticated.
    if !client.is_authenticated().unwrap() {
        panic!("Could not authenticate");
    }
}

const PRIVKEY_PEM: &[u8] = br#"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEA5y4OZWndQMr8TGCMTuO38TlWt+WzAcyNxHyeJgGbBT0PneDtSFb4
nFzyNV8IxBSG18aECmcOLqpCWn21io6Zs+Rr8pAqG2md6Wbfc097EnEpkJsuAJoQLlU/C2
g4cLEnFlabboq3B9W/UtFXXICTtQbzv1TCoj1kQCPObQ+9ihEAAAIAcCOChXAjgoUAAAAH
c3NoLXJzYQAAAIEA5y4OZWndQMr8TGCMTuO38TlWt+WzAcyNxHyeJgGbBT0PneDtSFb4nF
zyNV8IxBSG18aECmcOLqpCWn21io6Zs+Rr8pAqG2md6Wbfc097EnEpkJsuAJoQLlU/C2g4
cLEnFlabboq3B9W/UtFXXICTtQbzv1TCoj1kQCPObQ+9ihEAAAADAQABAAAAgQDM1U4EJW
zZAAHUWqd3LuXIYpmnj2qwaWIjepdV7Y5BcfzoUmdr9UOKqAAjsfS+Z8GiZk6QOQej6U+p
hkDYZ8len8g3hzxYwa3P6bomJAibRdhBu4OL5zRw8xnM9VQdJ93nc0pZokL3ltjG4hEpyV
6ltbep6mNGr8Vbf3JbSv0YwQAAAEEAl2cdVGalH2a/PWoBJmCDYcNpNKJZoZldp0p52Bqw
pCxjzOdQqWzv8xLKm/5bCh03j1mn8BwmKPtzit3Z040W6gAAAEEA/ZSEUw+UkvJjGY6SNw
cxjRslF1Rs5sPrNX6JhVUf2VpglqGtdOmrFxXhDMQcawdfmPPISCxLUsLqgiL6ohHNvQAA
AEEA6WLRFRvwAHPT7lzaiyKjsDaFzyA9r0+csRDVDe3VJ5mSq2xo3+0YoeF6rarzpSTbyQ
pshWng0o8WBTVRrNqA5QAAAARydXRoAQIDBAU=
-----END OPENSSH PRIVATE KEY-----
"#;
