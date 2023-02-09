// Tutorial chapter 5: Execute a command
//
// https://honzasp.github.io/makiko/tutorial/5-execute-command.html
//
// You can run the example with
//
//     cargo run --example tutorial_5
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

    // Open a session on the server.
    let channel_config = makiko::ChannelConfig::default();
    let (session, mut session_rx) = client.open_session(channel_config).await
        .expect("Could not open a session");

    // Handle session events asynchronously in a Tokio task.
    let session_event_task = tokio::task::spawn(async move {
        loop {
            // Wait for the next event.
            let event = session_rx.recv().await
                .expect("Error while receiving session event");

            // Exit the loop when the session has closed.
            let Some(event) = event else {
                break
            };

            match event {
                // Handle stdout/stderr output from the process.
                makiko::SessionEvent::StdoutData(data) => {
                    println!("Process produced stdout: {:?}", data);
                },
                makiko::SessionEvent::StderrData(data) => {
                    println!("Process produced stderr: {:?}", data);
                },

                // Handle exit of the process.
                makiko::SessionEvent::ExitStatus(status) => {
                    println!("Process exited with status {}", status);
                },
                makiko::SessionEvent::ExitSignal(signal) => {
                    println!("Process exited with signal {:?}: {:?}", signal.signal_name, signal.message);
                },

                // Ignore other events
                _ => {},
            }
        }
    });

    // Execute a command on the session
    session.exec("sed s/blue/green/".as_bytes())
        .expect("Could not execute a command in the session")
        .wait().await
        .expect("Server returned an error when we tried to execute a command in the session");

    // Send some data to the standard input of the process
    session.send_stdin("blueberry jam\n".into()).await.unwrap();
    session.send_stdin("blue jeans\nsky blue".into()).await.unwrap();
    session.send_eof().await.unwrap();

    // Wait for the task that handles session events
    session_event_task.await.unwrap();
}
