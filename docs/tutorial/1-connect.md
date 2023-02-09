---
title: Connecting to the server
layout: page
parent: Tutorial
nav_order: 1
---

# {{ page.title }}

In this chapter, we will connect to an SSH server and print out the server public key.

## An example server
{: #example-server }

To test an SSH client, we need an SSH server! If you have Docker installed, you can run [my example SSH server][tutorial-image] in a Docker container as follows:

[tutorial-image]: https://hub.docker.com/repository/docker/honzasp/makiko-tutorial/general

```
$ docker run --rm -p 2222:22 --name example-ssh-server honzasp/makiko-tutorial
```

This command will start the container in the background and it will bind the server to port 2222 on your localhost. You can connect to this server with username `alice` and password `alicealice`:

```
$ ssh -p 2222 alice@localhost
```

To stop the container, you can run:

```
$ docker stop example-ssh-server
```

If using Docker is not convenient for you, you can follow the tutorial by connecting to another SSH server that you can access, but you will need to adjust the connection details in the code.

## Open the connection

We will put all our code in `src/main.rs`. Makiko uses Tokio and async, so our main function looks as follows:

```rust
#[tokio::main]
async fn main() {
    ... // Our code will go here
}
```

We use the [`#[tokio::main]`][tokio-main] attribute to conveniently initialize the Tokio runtime and enable async code in `main()`.

[tokio-main]: https://docs.rs/tokio/latest/tokio/attr.main.html

{: .note }
You may wonder why we don't return a `Result` from `main()`. To keep things simple in the tutorial, we will panic when we encounter an error. In real code, you should [handle errors properly][error-handling].

[error-handling]: https://doc.rust-lang.org/book/ch09-00-error-handling.html

### The socket

First, we need to open a TCP socket to the SSH server. Makiko can work with anything that implements [`AsyncRead`][async-read] and [`AsyncWrite`][async-write], so you can also use Unix domain sockets, pipes or other exotic modes of transport. However, a [`tokio::net::TcpStream`][tcp-stream] will be the most usual choice:

[async-read]: https://docs.rs/tokio/latest/tokio/io/trait.AsyncRead.html
[async-write]: https://docs.rs/tokio/latest/tokio/io/trait.AsyncWrite.html
[tcp-stream]: https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html

```rust
let socket = tokio::net::TcpStream::connect(("localhost", 2222)).await
    .expect("Could not open a TCP socket");
```

### Configuration

The SSH protocol supports many cryptographic algorithms for different aspects of the connection, such as key exchange or encryption. We need to configure the client using the [`makiko::ClientConfig`][client-config] struct, which specifies the algorithms that the client can use and other low-level details. In most cases, you can use the default configuration, which uses only very secure cryptography:

[client-config]: https://docs.rs/makiko/latest/makiko/struct.ClientConfig.html

```rust
// Recommended configuration that uses only the best crypto
let config = makiko::ClientConfig::default();
```

However, if you need to connect to older SSH servers that don't support the newest crypto, you can use configuration that allows all algorithms implemented in Makiko. None of these algorithms are known to be _broken_, but they use primitives with known weaknesses (such as HMAC with SHA-1), are considered suspicious (NIST elliptic curves) or have suboptimal implementation in Makiko (Diffie-Hellman key exchange).

```rust
// Less secure configuration compatible with almost all SSH servers
let config = makiko::ClientConfig::default_compatible_less_secure();
```

If you want more fine-grained configuration, please [see the documentation][client-config].

### The client

We now have all that is needed to open the [`makiko::Client`][client]:

[client]: https://docs.rs/makiko/latest/makiko/struct.Client.html

```rust
let (client, mut client_rx, client_fut) = makiko::Client::open(socket, config)
    .expect("Could not open client");
```

The [`Client::open()`][client-open] associated function returns three objects: a [`Client`][client], a [`ClientReceiver`][client-rx] and a [`ClientFuture`][client-fut].

[client-open]: https://docs.rs/makiko/latest/makiko/struct.Client.html#method.open
[client-rx]: https://docs.rs/makiko/latest/makiko/struct.ClientReceiver.html
[client-fut]: https://docs.rs/makiko/latest/makiko/struct.ClientFuture.html

In the next sections, we will deal with the `ClientReceiver` and `ClientFuture`, and the following chapters will make use of the `Client`.

## Polling the client

To handle the SSH connection, we need to asynchronously run the code that performs I/O on the underlying socket. This code is encapsulated in the [`ClientFuture`][client-fut], which is a Rust [`Future`][future] that you need to poll to drive the connection forward. The future is resolved when the client is closed or when the connection fails with an error.

[future]: https://doc.rust-lang.org/std/future/trait.Future.html

In this tutorial, we will simply spawn a Tokio task to poll the future in the background and panic when the connection fails:

```rust
tokio::task::spawn(async move {
    client_fut.await.expect("Error in client future");
});
```

{: .note}
When we drop the [`JoinHandle`][join-handle] returned from [`spawn()`][task-spawn], Tokio will detach the task and run it in the background. This works well in our tutorial, but in practice, [it is usually better to follow the principles of structured concurrency][go-harmful] and always `.await` all tasks that you spawn. This will make sure that errors are always handled correctly, resources are cleaned up, and your program becomes easier to reason about.

[join-handle]: https://docs.rs/tokio/latest/tokio/task/struct.JoinHandle.html
[task-spawn]: https://docs.rs/tokio/latest/tokio/task/fn.spawn.html
[go-harmful]: https://vorpus.org/blog/notes-on-structured-concurrency-or-go-statement-considered-harmful/

## Handle client events

During the lifetime of the SSH connection, the client will asynchronously produce various events. To handle these events, we will use the [`ClientReceiver`][client-rx]. This is a bit similar to channels in Tokio: Makiko sends events to this "channel", and you receive them using [`ClientReceiver::recv()`][client-rx-recv], which is like the [`Receiver::recv()`][mpsc-rx-recv] method of a Tokio channel:

[client-rx-recv]: https://docs.rs/makiko/latest/makiko/struct.ClientReceiver.html#method.recv
[mpsc-rx-recv]: https://docs.rs/tokio/latest/tokio/sync/mpsc/struct.Receiver.html#method.recv

```rust
loop {
    // Wait for the next event.
    let event = client_rx.recv().await
        .expect("Error while receiving client event");

    // Exit the loop when the client has closed.
    let Some(event) = event else {
        break
    };

    match event {
        ... // We will handle the event here
    }
}
```

### Server public key
{: #server-public-key }

The produced events are variants of the enum [`ClientEvent`][client-event]. The most important variant that you always need to handle is [`ClientEvent::ServerPubkey`][client-event-server-pubkey], which you will get when Makiko receives the server's public key during key exchange. This always happens when the connection is initialized, but you may also get this event after the connection is established if the connection is "rekeyed" to derive fresh encryption secrets.

[client-event]: https://docs.rs/makiko/latest/makiko/enum.ClientEvent.html
[client-event-server-pubkey]: https://docs.rs/makiko/latest/makiko/enum.ClientEvent.html#variant.ServerPubkey

```rust
match event {
    // Handle the server public key
    makiko::ClientEvent::ServerPubkey(pubkey, accept) => {
        ... // Verify the server public key here
    },

    ... // Handle other events here
}
```

The `ServerPubkey` variant has two fields: the server [`Pubkey`][pubkey] and an [`AcceptPubkey`][accept-pubkey] object that we will use to tell Makiko whether we accept or reject the key.

[pubkey]: https://docs.rs/makiko/latest/makiko/pubkey/enum.Pubkey.html
[accept-pubkey]: https://docs.rs/makiko/latest/makiko/struct.AcceptPubkey.html

To prevent [man-in-the-middle attacks][mitm], it is very important to verify that this public key belongs to the server that we wanted to connect to. Unfortunately, SSH does not provide any mechanism to verify identity of the server (in contrast to TLS, which is used in HTTPS to secure the Web and which provides certificate-based public key infrastructure). This means that it is up to you whether to accept or reject the public key.

[mitm]: https://en.wikipedia.org/wiki/Man-in-the-middle_attack

[Later in the tutorial]({% link tutorial/7-verify-pubkey.md %}), we will learn how to implement a [trust on first use (TOFU)][tofu] scheme using the standard `~/.ssh/known_hosts` file. But for now, we won't do any verification and we will accept any key:

[tofu]: https://en.wikipedia.org/wiki/Trust_on_first_use

```rust
match event {
    // Handle the server public key: for now, we just accept all keys, but this makes
    // us susceptible to man-in-the-middle attacks!
    makiko::ClientEvent::ServerPubkey(pubkey, accept) => {
        println!("Server pubkey type {}, fingerprint {}", pubkey.type_str(), pubkey.fingerprint());
        accept.accept();
    },

    ...
}
```

{: .warning }
If you don't verify the server public key, [it might be treated as a security vulnerability][rust-cve].

[rust-cve]: https://blog.rust-lang.org/2023/01/10/cve-2022-46176.html

### Other events

You can [read the documentation][client-event] if you want to learn about other client events, but we won't need to handle them in this tutorial, so we can just ignore them:

```rust
match event {
    ...

    // All other events can be safely ignored
    _ => {},
}
```

---

You can find the full code for this tutorial in [`examples/tutorial_1.rs`][tutorial-1]. If all works well, the program prints the fingerprint of the server public key and hangs. In the next chapter, we will continue by authenticating to the server using a password.

[tutorial-1]: https://github.com/honzasp/makiko/blob/master/examples/tutorial_1.rs

{% include tutorial_next.html link="tutorial/2-password-auth.md" title="Password authentication" %}
