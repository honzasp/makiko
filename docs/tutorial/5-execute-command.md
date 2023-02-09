---
title: Execute a command
layout: page
parent: Tutorial
nav_order: 5
---

# {{ page.title }}

In the previous chapters, we connected to the server and authenticated ourselves, so now we can finally execute some commands!

## Session

A single SSH connection can host multiple logical channels of communication. The SSH protocol defines two kinds of channels: interactive _sessions_ and TCP/IP forwarding channels (or _tunnels_). In this chapter, we will learn how to use sessions to execute commands, and the next chapter will be about tunnels.

One session corresponds to one process: you open a session, prepare the execution environment (such as environment variables), start the command or shell, and then interact with it.

## Open a session

To open a session, we use the method [`Client::open_session()`][client-open-session] (after we have authenticated successfully). To configure the underlying channel, this method needs a [`ChannelConfig`][channel-config]. You can adjust the configuration if you need to optimize the SSH flow control, but the default instance should work well for most use cases:

[client-open-session]: https://docs.rs/makiko/latest/makiko/struct.Client.html#method.open_session
[channel-config]: https://docs.rs/makiko/latest/makiko/struct.ChannelConfig.html

```rust
// Open a session on the server.
let channel_config = makiko::ChannelConfig::default();
let (session, mut session_rx) = client.open_session(channel_config).await
    .expect("Could not open a session");
```

The `open_session()` method returns two objects, a [`Session`][session] and a [`SessionReceiver`][session-rx]. This is the same pattern as with [`Client`][client] and [`ClientReceiver`][client-rx]: you use the `Session` object to invoke operations on the session, and the `SessionReceiver` object to receive events from the session.

[session]: https://docs.rs/makiko/latest/makiko/struct.Session.html
[session-rx]: https://docs.rs/makiko/latest/makiko/struct.SessionReceiver.html
[client]: https://docs.rs/makiko/latest/makiko/struct.Client.html
[client-rx]: https://docs.rs/makiko/latest/makiko/struct.ClientReceiver.html

## Handle session events

To handle events from the [`SessionReceiver`][session-rx], we will spawn another task, like we did with client events. To receive the events, we will use the method [`SessionReceiver::recv()`][session-rx-recv]. The events are represented using the enum [`SessionEvent`][session-event]. The `recv()` method returns `None` when the session is closed and no more events will be received:

[session-rx-recv]: https://docs.rs/makiko/latest/makiko/struct.SessionReceiver.html#method.recv
[session-event]: https://docs.rs/makiko/latest/makiko/enum.SessionEvent.html

```rust
tokio::task::spawn(async move {
    loop {
        // Wait for the next event.
        let event = session_rx.recv().await
            .expect("Error while receiving session event");

        // Exit the loop when the session has closed.
        let Some(event) = event else {
            break
        };

        match event {
            ... // We will handle the event here
        }
    }
});
```

{: .warning }
You have to receive the events from the `SessionReceiver` even if you don't need to handle them (which should be rare). Makiko internally uses a channel to send events to the `SessionReceiver`, and if you don't receive the events, this channel will become full and the client will block.

### Output from the process

Output from the process is received as `StdoutData` and `StderrData` variants of [`SessionEvent`][session-event]:

```rust
match event {
    // Handle stdout/stderr output from the process.
    makiko::SessionEvent::StdoutData(data) => {
        println!("Process produced stdout: {:?}", data);
    },
    makiko::SessionEvent::StderrData(data) => {
        println!("Process produced stderr: {:?}", data);
    },
    ...
}
```

The data is received as chunks of bytes, but the boundaries between the chunks are not meaningful, you should treat stdout and stderr as byte streams.

### Process exit

When the process exits, the SSH server sends an `ExitStatus` if the process exited with a status, or `ExitSignal` if it was killed by a signal:

```rust
match event {
    ...
    // Handle exit of the process.
    makiko::SessionEvent::ExitStatus(status) => {
        println!("Process exited with status {}", status);
    },
    makiko::SessionEvent::ExitSignal(signal) => {
        println!("Process exited with signal {:?}: {:?}", signal.signal_name, signal.message);
    },
    ...
}
```

### Other events

The server may also send an `Eof` event after the process closes its stdout and stderr. We will ignore this event, together with any other events that might be introduced in future versions of the library:

```rust
match event {
    ...
    // Ignore other events
    _ => {},
}
```

Note that the [`SessionEvent`][session-event] enum is marked as `#[non_exhaustive]`, so the Rust compiler will require you to add the catch-all `match` clause even if you handle all variants of the enum. This allows us to add new kinds of events to Makiko without breaking your code.

## Execute the command

The session is now ready, so we can execute the command using [`Session::exec()`][session-exec]. We will execute the command `sed s/blue/green/g`, which reads lines from the standard input, replaces `blue` with `green`, and prints the lines back to stdout:

[session-exec]: https://docs.rs/makiko/latest/makiko/struct.Session.html#method.exec

```rust
// Execute a command on the session
session.exec("sed s/blue/green/".as_bytes())
    .expect("Could not execute a command in the session")
    .wait().await
    .expect("Server returned an error when we tried to execute a command in the session");

```

The `exec()` method returns a [`SessionResp`][session-resp], which represents the server response to the execute request. We wait for the response using [`SessionResp::wait()`][session-resp-wait], but you can also ignore the response with [`SessionResp::ignore()`][session-resp-ignore]

[session-resp]: https://docs.rs/makiko/latest/makiko/struct.SessionResp.html
[session-resp-wait]: https://docs.rs/makiko/latest/makiko/struct.SessionResp.html#method.wait
[session-resp-ignore]: https://docs.rs/makiko/latest/makiko/struct.SessionResp.html#method.ignore

## Send data to the process

We will use the [`Session::send_stdin()`][session-send-stdin] method to send data to the standard input of the running process, and [`Session::send_eof()`][session-send-eof] to send end-of-file, which will close the standard input:

[session-send-stdin]: https://docs.rs/makiko/latest/makiko/struct.Session.html#method.send_stdin
[session-send-eof]: https://docs.rs/makiko/latest/makiko/struct.Session.html#method.send_eof

```rust
// Send some data to the standard input of the process
session.send_stdin("blueberry jam\n".into()).await.unwrap();
session.send_stdin("blue jeans\nsky blue".into()).await.unwrap();
session.send_eof().await.unwrap();
```

## Wait for the session

We have started the process and sent some data to it, and now we need to wait until the process terminates and the session is closed. Recall that when the session is closed, the [`SessionReceiver`][session-rx] returns `None`, we break out of the event handling loop and the task terminates. We will change the code that we have written previously to store the [`JoinHandle`][join-handle] from the `spawn()` call:

[join-handle]: https://docs.rs/tokio/latest/tokio/task/struct.JoinHandle.html

```rust
let session_event_task = tokio::task::spawn(async move {
    loop {
        let event = ...;
    }
});
```

Back on the main task, we will wait for the event-handling task to terminate:

```rust
// Wait for the task that handles session events
session_event_task.await.unwrap();
```

---

Full code for this tutorial can be found in [`examples/tutorial_5.rs`][tutorial-5]. If you don't use the [example server for this tutorial][example-server], you may need to change the code to use a different username and password.

[tutorial-5]: https://github.com/honzasp/makiko/blob/master/examples/tutorial_5.rs
[example-server]: {% link tutorial/1-connect.md %}#example-server

{% include tutorial_next.html link="tutorial/6-open-tunnel.md" title="Open a tunnel" %}
