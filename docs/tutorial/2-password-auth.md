---
title: Password authentication
layout: page
parent: Tutorial
nav_order: 2
---

# {{ page.title }}

In this chapter, we will authenticate to the SSH server using a password.

{: .note }
Public key authentication, [which is described in the next chapter][3-pubkey-auth], is considered more secure than password authentication and should be preferred whenever possible, especially if you cannot securely verify the public key of the server that you are connecting to.

[3-pubkey-auth]: {% link tutorial/3-pubkey-auth.md %}

## Handle client events in a task

In the previous chapter, we spawned a task to poll the [`ClientFuture`][client-fut] and we waited for [`ClientEvent`-s][client-event] from the [`ClientReceiver`][client-rx] on the main task. However, from now on, we will need the main task to invoke operations on the [`Client`][client], so we start by moving the event handling from the main task to another spawned task:

[client-fut]: https://docs.rs/makiko/latest/makiko/struct.ClientFuture.html
[client-event]: https://docs.rs/makiko/latest/makiko/enum.ClientEvent.html
[client-rx]: https://docs.rs/makiko/latest/makiko/struct.ClientReceiver.html
[client]: https://docs.rs/makiko/latest/makiko/struct.Client.html

```rust
// Do not handle the client events on the main task
/*
loop {
    // Wait for the next event.
    let event = client_rx.recv().await
        .expect("Error while receiving client event");

    ...
}
*/

// Instead, spawn another Tokio task to handle the client events.
tokio::task::spawn(async move {
    loop {
        // Wait for the next event.
        let event = client_rx.recv().await
            .expect("Error while receiving client event");

        ... // Handle the events as before
    }
});
```

## Authenticate

Back on the main task, we can now call the [`Client::auth_password()`][client-auth-password] method to attempt password authentication using username "alice" and password "alicealice":

[client-auth-password]: https://docs.rs/makiko/latest/makiko/struct.Client.html#method.auth_password

```rust
// Try to authenticate using a password.
let auth_res = client.auth_password("alice".into(), "alicealice".into()).await
    .expect("Error when trying to authenticate");
```

The method returns an [`AuthPasswordResult`][auth-password-result], which has these variants:

- `Success` means that we are now authenticated.
- `Failure` means that the server has not accepted the authentication and provided an [`AuthFailure`][auth-failure] with details.
- `ChangePassword` means that the password was correct, but we need to change the password to a new one. The SSH specification provides a mechanism for changing the password, but I have not found any SSH server or client that implements this feature, so Makiko does not support it either. This means that we don't need to handle the `ChangePassword` variant in practice, so we treat it as an error.

[auth-password-result]: https://docs.rs/makiko/latest/makiko/enum.AuthPasswordResult.html
[auth-failure]: https://docs.rs/makiko/latest/makiko/struct.AuthFailure.html

In this tutorial, we can simply print a message on success and panic on failure:

```rust
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
```

---

Full code for this tutorial can be found in [`examples/tutorial_2.rs`][tutorial-2]. The program will print a message if the authentication was successful, or an error if it failed. If you don't use the [example server for this tutorial][example-server], you may need to change the code to use a different username and password.

[tutorial-2]: https://github.com/honzasp/makiko/blob/master/examples/tutorial_2.rs
[example-server]: {% link tutorial/1-connect.md %}#example-server

{% include tutorial_next.html link="tutorial/3-pubkey-auth.md" title="Public key authentication" %}
