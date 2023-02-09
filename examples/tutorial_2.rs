// Tutorial chapter 2: Password authentication
//
// https://honzasp.github.io/makiko/tutorial/2-password-auth.html
//
// You can run the example with
//
//     cargo run --example tutorial_2
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
