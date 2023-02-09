---
title: Public key algorithm
layout: page
parent: Tutorial
nav_order: 4
---

# {{ page.title }}

This chapter will build on the [previous chapter]({% link tutorial/3-pubkey-auth.md %}) by selecting the public key algorithm more robustly.

## Get the list of supported algorithms

We can use the [`Privkey::pubkey()`][privkey-pubkey] method to obtain the [`Pubkey`][pubkey] from the [`Privkey`][privkey] that we have read from PEM in the previous chapter:

[privkey-pubkey]: https://docs.rs/makiko/latest/makiko/pubkey/enum.Privkey.html#method.pubkey
[pubkey]: https://docs.rs/makiko/latest/makiko/pubkey/enum.Pubkey.html
[privkey]: https://docs.rs/makiko/latest/makiko/pubkey/enum.Privkey.html

```rust
// Get the public key from the private key.
let pubkey = privkey.pubkey();
```

And to obtain the list of algorithms that Makiko supports for this public key, we can use the [`Pubkey::algos()`][pubkey-algos] method:

[pubkey-algos]: https://docs.rs/makiko/latest/makiko/pubkey/enum.Pubkey.html#method.algos

```rust
// Get the public key algorithms supported by the key.
let available_algos = pubkey.algos();
```

Next, we need to find out which of these algorithms is also supported by the server.

## Check public keys and an algorithms

Armed with the private key and a list of algorithms, we could simply try to call [`Client::auth_pubkey()`][client-auth-pubkey] with each algorithm in turn. This is a reasonable approach, but it has two disadvantages:

1. SSH servers typically limit the number of failed authentication attempts to a small number and will close the connection when this limit is exceeded.
2. The signing operation that is required for authentication might be expensive in terms of CPU time.

[client-auth-pubkey]: https://docs.rs/makiko/latest/makiko/struct.Client.html#method.auth_pubkey

Fortunately, the SSH protocol provides a mechanism to ask the server whether it would accept a given combination of public key and algorithm, without actually attempting the authentication. We can use this mechanism by calling [`Client::check_pubkey()`][client-check-pubkey], which takes the username, public key and public key algorithm, and returns a bool:

[client-check-pubkey]: https://docs.rs/makiko/latest/makiko/struct.Client.html#method.check_pubkey

```rust
// Try the algorithms one by one.
let username: String = "ruth".into();
for pubkey_algo in available_algos.iter().copied() {
    // Check whether this combination of a public key and algorithm would be acceptable to the
    // server.
    let check_ok = client.check_pubkey(username.clone(), &pubkey, pubkey_algo).await
        .expect("Error when checking a public key");

    ...
}
```

If the server says that it will not accept this public key and algorithm, we can try the next algorithm:

```rust
for pubkey_algo in ... {
    let check_ok = ...;

    // Skip this algorithm if the server rejected it.
    if !check_ok {
        println!("Server rejected public key and algorithm {:?}", pubkey_algo.name);
        continue;
    }

    ...
}
```

Otherwise, we can try to authenticate:

```rust
for pubkey_algo in ... {
    ...

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
```

Finally, we can use the [`Client::is_authenticated()`][client-is-authenticated] method to check whether we have been successful:

[client-is-authenticated]: https://docs.rs/makiko/latest/makiko/struct.Client.html#method.is_authenticated

```rust
// Check that we have been authenticated.
if !client.is_authenticated().unwrap() {
    panic!("Could not authenticate");
}
```

---

Full code for this tutorial can be found in [`examples/tutorial_4.rs`][tutorial-4]. The program will print messages about the authentication attemps, and it will panic if authentication fails. If you don't use the [example server for this tutorial][example-server], you may need to change the code to use a different username and private key.

[tutorial-4]: https://github.com/honzasp/makiko/blob/master/examples/tutorial_4.rs
[example-server]: {% link tutorial/1-connect.md %}#example-server

{% include tutorial_next.html link="tutorial/5-execute-command.md" title="Execute a command" %}
