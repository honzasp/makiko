// Tutorial chapter 6: Open a tunnel
//
// https://honzasp.github.io/makiko/tutorial/6-open-tunnel.html
//
// You can run the example with
//
//     cargo run --example tutorial_6
//

#[tokio::main]
async fn main() {
    env_logger::init();

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

    // Open a tunnel from the server.
    let channel_config = makiko::ChannelConfig::default();
    let connect_addr = ("httpbin.org".into(), 80);
    let origin_addr = ("0.0.0.0".into(), 0);
    let (tunnel, mut tunnel_rx) = client.connect_tunnel(channel_config, connect_addr, origin_addr).await
        .expect("Could not open a tunnel");

    // Handle tunnel events asynchronously in a Tokio task.
    let tunnel_event_task = tokio::task::spawn(async move {
        loop {
            // Wait for the next event.
            let event = tunnel_rx.recv().await
                .expect("Error while receiving tunnel event");

            // Exit the loop when the tunnel has closed.
            let Some(event) = event else {
                break
            };

            match event {
                // Handle data received from the tunnel.
                makiko::TunnelEvent::Data(data) => {
                    println!("Received: {:?}", data);
                },

                // Handle EOF from the tunnel.
                makiko::TunnelEvent::Eof => {
                    println!("Received eof");
                    break
                },

                _ => {},
            }
        }
    });

    // Send data to the tunnel
    tunnel.send_data("GET /get HTTP/1.0\r\nhost: httpbin.org\r\n\r\n".into()).await
        .expect("Could not send data to the tunnel");

    // Do not close the outbound side of the tunnel, because this causes OpenSSH to prematurely
    // close the tunnel.
    /*
    tunnel.send_eof().await
        .expect("Could not send EOF to the tunnel");
    */

    // Wait for the task that handles tunnel events
    tunnel_event_task.await.unwrap();
}
