// Tutorial chapter 7: Verify the server key
//
// https://honzasp.github.io/makiko/tutorial/7-verify-pubkey.md
//
// You can run the example with
//
//     cargo run --example tutorial_7
//

#[tokio::main]
async fn main() {
    // Connect to the SSH server.
    let host = "localhost";
    let port = 2222;
    let socket = tokio::net::TcpStream::connect((host, port)).await
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
                makiko::ClientEvent::ServerPubkey(pubkey, accept) => {
                    println!("Server pubkey type {}, fingerprint {}", pubkey.type_str(), pubkey.fingerprint());

                    // Read the ~/.ssh/known_hosts file.
                    let hosts_path = home::home_dir().unwrap().join(".ssh/known_hosts");
                    let hosts_data = std::fs::read(&hosts_path)
                        .expect("Could not read known_hosts file");

                    // Decode the contents of the file.
                    let mut hosts_file = makiko::host_file::File::decode(hosts_data.into());

                    // Lookup the server address in the file.
                    let key_match = hosts_file.match_host_port_key(host, port, &pubkey);

                    match key_match {
                        // The given key was found in the file, this means that it is trusted and we
                        // can accept it.
                        makiko::host_file::KeyMatch::Accepted(entries) => {
                            println!("Found the server key in known_hosts file");
                            for entry in entries.iter() {
                                println!("At line {}", entry.line());
                            }
                            accept.accept();
                        },

                        // The key was revoked in the file, so we must reject it.
                        makiko::host_file::KeyMatch::Revoked(_entry) => {
                            println!("The server key was revoked in known_hosts file");
                        },

                        // We found other keys for this server in the file, so the server changed its
                        // key, or somebody is doing a man-in-the-middle attack on us.
                        makiko::host_file::KeyMatch::OtherKeys(entries) => {
                            println!("The known_hosts file specifies other keys for this server:");
                            for entry in entries.iter() {
                                println!("At line {}, pubkey type {}, fingerprint {}",
                                    entry.line(), entry.pubkey().type_str(), entry.pubkey().fingerprint());
                            }
                            println!("Aborting, you might be target of a man-in-the-middle attack!");
                        },

                        // We did not find the key in the file, so we decide to accept the key and add
                        // it to the file.
                        makiko::host_file::KeyMatch::NotFound => {
                            println!("Did not find any key for this server in known_hosts file, \
                                adding it to the file");
                            accept.accept();

                            // Append an entry with the key to the file.
                            hosts_file.append_entry(
                                makiko::host_file::File::entry_builder()
                                    .host_port(host, port)
                                    .key(pubkey)
                            );

                            // Write the modified file back to disk.
                            let hosts_data = hosts_file.encode();
                            std::fs::write(&hosts_path, &hosts_data)
                                .expect("Could not write the modified known_hosts file");
                        },
                    }
                },

                // All other events can be safely ignored
                _ => {},
            }
        }
    });

    // Try to authenticate using a password.
    let auth_res = client.auth_password("alice".into(), "alicealice".into()).await
        .expect("Error when trying to authenticate");

    // Deal with all possible outcomes of password authentication.
    match auth_res {
        makiko::AuthPasswordResult::Success => {
            println!("We have successfully authenticated using a password");
        },
        makiko::AuthPasswordResult::ChangePassword(prompt) => {
            panic!("The server asks us to change password: {:?}", prompt);
        },
        makiko::AuthPasswordResult::Failure(failure) => {
            panic!("The server rejected authentication: {:?}", failure);
        }
    }
}
