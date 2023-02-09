---
title: Open a tunnel
layout: page
parent: Tutorial
nav_order: 6
---

# {{ page.title }}

SSH is most commonly used to execute commands on a remote server, but another important use of the protocol is for tunnelling TCP/IP connections. There are two ways to open a tunnel:

- _Local forwarding_ (aka [`ssh -L`][ssh-l]): the client asks the server to open a TCP connection to another host. In Makiko, this is implemented by [`Client::connect_tunnel()`][client-connect-tunnel]. In this chapter, we will learn how to use this method.
- _Remote forwarding_ (aka [`ssh -R`][ssh-r]): the client asks the server to listen on a port, and the server will open a tunnel for every TCP connection on this port. In Makiko, this is implemented by [`Client::bind_tunnel()`][client-bind-tunnel], [`Client::unbind_tunnel()`][client-unbind-tunnel] and the [`ClientEvent::Tunnel`][client-event-tunnel] variant of `ClientEvent`. We won't cover remote forwarding in this tutorial, please refer to the API documentation for details.

[ssh-l]: https://man.openbsd.org/ssh#L
[client-connect-tunnel]: https://docs.rs/makiko/latest/makiko/struct.Client.html#method.connect_tunnel
[ssh-r]: https://man.openbsd.org/ssh#R
[client-bind-tunnel]: https://docs.rs/makiko/latest/makiko/struct.Client.html#method.bind_tunnel
[client-unbind-tunnel]: https://docs.rs/makiko/latest/makiko/struct.Client.html#method.unbind_tunnel
[client-event-tunnel]: https://docs.rs/makiko/latest/makiko/enum.ClientEvent.html#variant.Tunnel

## Open a tunnel

To demonstrate the use of tunnels, we will open a TCP/IP connection from the server to [httpbin.org][httpbin] and we will manually send a simple HTTP request over this connection. To open the tunnel, we use the method [`Client::connect_tunnel()`][client-connect-tunnel], which needs:

- A [`ChannelConfig`][channel-config], which configures the underlying SSH channel. Similar to the previous chapter, you can change the configuration to tune performance, but the default configuration should be sufficient for now.
- The address that the server will connect to, given as a pair of host and port. The host can be specified as an IP address or as a domain name. We will connect to `"httpbin.org"` on port `80`.
- The address of the "originator" of the connection. This is also specified as a pair of host and port, but the host should be an IP address. For example, [`ssh -L`][ssh-l] will set this to the remote address of the local connection that is forwarded to the server, but we will use the null IP address and port in this tutorial.

[httpbin]: https://httpbin.org/
[channel-config]: https://docs.rs/makiko/latest/makiko/struct.ChannelConfig.html

```rust
// Open a tunnel from the server.
let channel_config = makiko::ChannelConfig::default();
let connect_addr = ("httpbin.org".into(), 80);
let origin_addr = ("0.0.0.0".into(), 0);
let (tunnel, mut tunnel_rx) = client.connect_tunnel(channel_config, connect_addr, origin_addr).await
    .expect("Could not open a tunnel");
```

In a direct analogy to [`Client::open_session()`][client-open-session], the `Client::connect_tunnel()` method returns a pair of objects: a [`Tunnel`][tunnel] object to send requests to the tunnel, and a [`TunnelReceiver`][tunnel-rx] to receive events from the tunnel.

[client-open-session]: https://docs.rs/makiko/latest/makiko/struct.Client.html#method.open_session
[tunnel]: https://docs.rs/makiko/latest/makiko/struct.Tunnel.html
[tunnel-rx]: https://docs.rs/makiko/latest/makiko/struct.TunnelReceiver.html

## Handle tunnel events

We will use the same pattern as before to handle events from the tunnel: we spawn a task and receive the events, represented as enum [`TunnelEvent`][tunnel-event], using [`TunnelReceiver::recv()`][tunnel-rx-recv]. This method returns `None` when the tunnel closes:

[tunnel-event]: https://docs.rs/makiko/latest/makiko/enum.TunnelEvent.html
[tunnel-rx-recv]: https://docs.rs/makiko/latest/makiko/struct.TunnelReceiver.html#method.recv

```rust
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
            ... // Handle the event
        }
    }
});
```

{: .warning }
As with all `Receiver` objects in Makiko, you must receive the events from the `TunnelReceiver` in a timely manner. Makiko uses a bounded buffer of events, which will become full if you don't receive the event, causing the client to block.

### Data received from the channel

Events on a tunnel are quite simple, you can either get a chunk of data with the `Data` variant, or an end-of-file event with the `Eof` variant:

```rust
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
```

## Send data to the channel

Back on the main task, we can use the [`Tunnel::send_data()`][tunnel-send-data] method to send bytes over the tunnel. In our case, we send a very simple HTTP request to [`httpbin.org/get`][httpbin-get]:

[tunnel-send-data]: https://docs.rs/makiko/latest/makiko/struct.Tunnel.html#method.send_data
[httpbin-get]: https://httpbin.org/#/HTTP_Methods/get_get

```rust
// Send data to the tunnel
tunnel.send_data("GET /get HTTP/1.0\r\nhost: httpbin.org\r\n\r\n".into()).await
    .expect("Could not send data to the tunnel");
```

We can also close the tunnel for sending by calling [`Tunnel::send_eof()`][tunnel-send-eof]. However, the OpenSSH server will close the tunnel prematurely if we do so, so we comment out this call:

[tunnel-send-eof]: https://docs.rs/makiko/latest/makiko/struct.Tunnel.html#method.send_eof

```rust
// Do not close the outbound side of the tunnel, because this causes OpenSSH to prematurely
// close the tunnel.
/*
tunnel.send_eof().await
    .expect("Could not send EOF to the tunnel");
*/
```

Finally, we wait until the tunnel is closed and the event handling task terminates:

```rust
// Wait for the task that handles tunnel events
tunnel_event_task.await.unwrap();
```

---

Full code for this tutorial can be found in [`examples/tutorial_6.rs`][tutorial-6]. If you don't use the [example server for this tutorial][example-server], you may need to change the code to use a different username and password.

[tutorial-6]: https://github.com/honzasp/makiko/blob/master/examples/tutorial_6.rs
[example-server]: {% link tutorial/1-connect.md %}#example-server

{% include tutorial_next.html link="tutorial/7-verify-pubkey.md" title="Verify the server key" %}
