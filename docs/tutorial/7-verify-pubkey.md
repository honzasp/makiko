---
title: Verify the server key
layout: page
parent: Tutorial
---

# {{ page.title }}

[Back in chapter 1][ch1-server-public-key], we said that we should verify the public key presented by the server during the initial connection handshake (or during any follow-up key exchange). The SSH protocol does not contain any mechanism for verifying the server key, so you must do it yourself using a method that suits your application.

[ch1-server-public-key]: {% link tutorial/1-connect.md %}#server-public-key

For example, you can check that the key provided by the server belongs to an allowed set of keys configured with the client. For some applications, not verifying the key may also be a valid approach, but please make sure that you understand the implications. Reading [about man-in-the-middle attacks][rfc-mitm] in the SSH protocol architecture RFC might be a good start.

[rfc-mitm]: https://www.rfc-editor.org/rfc/rfc4251#section-9.3.4

{: .note }
The SSH protocol does not verify the public key (it does not check that it belongs to the server that you wanted to connect to), but it **does** verify that the server owns the corresponding private key.

## Trust on first use

In this chapter, we will show how you can implement the [trust-on-first-use (TOFU)][tofu] approach for verifying public keys using the well-known [`~/.ssh/known_hosts`][sshd-known-hosts] file.

[tofu]: https://en.wikipedia.org/wiki/Trust_on_first_use
[sshd-known-hosts]: https://man.openbsd.org/sshd.8#SSH_KNOWN_HOSTS_FILE_FORMAT

With this approach, when we connect to a server, we look up its address in the `known_hosts` file. If no entry in this file matches the address, it means that we are connecting to the server for the first time, so we accept the server key unconditionally ("trust on first use") and add an entry to the file.

On the other hand, if the file contains at least one entry that matches the address, we check that the key provided by the server is equal to the key from one of the matched entries. If the key fails this check, it means that the server key has changed from the last time that we connected to the server, which may mean that somebody is attempting a man-in-the-middle attack, so we reject the key, which aborts the connection. (This is the _"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!"_ error that you may have encountered when using the `ssh` client from OpenSSH.)

{: .note }
It is important to use the hostname of the SSH server as specified by the user when searching for entries in the `known_hosts` file. For example, if the user specifies a domain name, we must look up the domain name and not the resolved IP address, because an attacker can modify the DNS record of the server to point to a different IP address.

In the rest of this chapter, we will be writing code that handles the [`ClientEvent::ServerPubkey`][client-event-server-pubkey] event:

[client-event-server-pubkey]: https://docs.rs/makiko/latest/makiko/enum.ClientEvent.html#variant.ServerPubkey

```rust
match event {
    makiko::ClientEvent::ServerPubkey(pubkey, accept) => {
        println!("Server pubkey type {}, fingerprint {}", pubkey.type_str(), pubkey.fingerprint());

        ... // Verify the `pubkey` and call `accept.accept()` if it is valid
    },
}
```

## Read the `known_hosts` file

Makiko provides support for reading a `known_hosts` file using features from the [`host_file` module][host-file-mod]. Makiko can read the file, but it can also append new entries to the file and losslessly write the updated file back.

[host-file-mod]: https://docs.rs/makiko/latest/makiko/host_file/index.html

We start by locating the file and reading its contents into memory:

```rust
// Read the ~/.ssh/known_hosts file.
let hosts_path = home::home_dir().unwrap().join(".ssh/known_hosts");
let hosts_data = std::fs::read(&hosts_path)
    .expect("Could not read known_hosts file");
```

We have used the [`home`][home] crate to reliably find the user's home directory, so you may need to add it to your `Cargo.toml`:

[home]: https://docs.rs/home/latest/home/

```toml
[dependencies]
home = "0.5"
```

We can now use the [`host_file::File::decode()`][file-decode] method to parse the file and get a [`host_file::File`][file]. Note that this method does not return a `Result`: when it encounters invalid or unrecognized lines, it simply ignores them (but keeps them around, so that we can later losslessly encode the file back).

[file-decode]: https://docs.rs/makiko/latest/makiko/host_file/struct.File.html#method.decode
[file]: https://docs.rs/makiko/latest/makiko/host_file/struct.File.html

```rust
// Decode the contents of the file.
let mut hosts_file = makiko::host_file::File::decode(hosts_data.into());
```

## Lookup the server address

The `known_hosts` file is a sequence of entries ([`host_file::Entry`][host-file-entry]). Every entry stores a single public key and it contains a pattern that can match an address.

[host-file-entry]: https://docs.rs/makiko/latest/makiko/host_file/struct.Entry.html

The pattern might be a concrete hostname (such as `github.com`, `140.82.121.4` or `[localhost]:2222`), a wildcard pattern (such as `*.github.com` or `g?thub.com`) or a hash of the hostname (`|1|4n/lI1Js...my6Q=`). The hashed pattern is usually preferred, because it hides the identity of SSH servers that you have connected to, in case your `known_hosts` file is leaked.

Some entires may also be marked as revoked, which means that the public key should be rejected instead of accepted.

We can use the method [`host_file::File::match_host_port_key()`][file-match-host-port-key] to search for all entries that match the given host and port. The result of this search is a [`host_file::KeyMatch`][key-match]:

```rust
// Lookup the server address in the file.
let key_match = hosts_file.match_host_port_key(host, port, &pubkey);
```

[file-match-host-port-key]: https://docs.rs/makiko/latest/makiko/host_file/struct.File.html#method.match_host_port_key
[key-match]: https://docs.rs/makiko/latest/makiko/host_file/enum.KeyMatch.html

## Deal with the result of the lookup

There are four variants of the [`host_file::KeyMatch`][key-match] enum, so we need to handle them all:

```rust
match key_match {
    ...
}
```

### Key is present in the file

The `Accepted` variant means that the `known_hosts` file contains at least one entry that matches the hostname and which refers to the public key provided by the server. This means that we have previously decided to trust this key for this hostname, so we can call [`AcceptPubkey::accept()`][accept-pubkey-accept] to accept the key:

[accept-pubkey-accept]: https://docs.rs/makiko/latest/makiko/struct.AcceptPubkey.html#method.accept

```rust
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
    ...
}
```

### Key was revoked

The `Revoked` variant means that there was an entry that lists the key as revoked for the hostname, so we must reject the key. You can call [`AcceptPubkey::reject()`][accept-pubkey-reject] with a custom error that describes the reason for the rejection, or you can simply drop the `AcceptPubkey` object, which will reject the key with a default error:

[accept-pubkey-reject]: https://docs.rs/makiko/latest/makiko/struct.AcceptPubkey.html#method.reject

```rust
match key_match {
    ...
    // The key was revoked in the file, so we must reject it.
    makiko::host_file::KeyMatch::Revoked(_entry) => {
        println!("The server key was revoked in known_hosts file");
    },
    ...
}
```

### Other keys found in the file

The `OtherKeys` variant means that we found entries that match the hostname, but all of them specified a different public key. This means that we already know the valid keys of this server, but the server provided a different key, so we must reject the key, because a man-in-the-middle attack might be going on:

```rust
match key_match {
    ...
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
    ...
}
```

### No entry was found

Finally, the `NotFound` variant means that the file does not contain any entry matching the given hostname. In this case, we may decide to trust the key and add it to the `known_hosts` file:

```rust
match key_match {
    ...
    // We did not find the key in the file, so we decide to accept the key and add
    // it to the file.
    makiko::host_file::KeyMatch::NotFound => {
        println!("Did not find any key for this server in known_hosts file, \
            adding it to the file");
        accept.accept();

        ... // Add an entry to the file
    },
}
```

To add an entry to the [`host_file::File`][file], we can use the [`host_file::File::append_entry()`][file-append-entry] method and the [`host_file::EntryBuilder`][entry-builder]:

[file-append-entry]: https://docs.rs/makiko/latest/makiko/host_file/struct.File.html#method.append_entry
[entry-builder]: https://docs.rs/makiko/latest/makiko/host_file/struct.EntryBuilder.html

```rust
// Append an entry with the key to the file.
hosts_file.append_entry(
    makiko::host_file::File::entry_builder()
        .host_port(host, port)
        .key(pubkey)
);
```

To save the updated file to disk, we will use the [`host_file::File::encode()`][file-encode] method to get the modified contents of the file:

[file-encode]: https://docs.rs/makiko/latest/makiko/host_file/struct.File.html#method.encode

```rust
// Write the modified file back to disk.
let hosts_data = hosts_file.encode();
std::fs::write(&hosts_path, &hosts_data)
    .expect("Could not write the modified known_hosts file");
```

The `encode()` method is lossless: it faithfully preserves all existing lines, including comments or invalid lines.

---

Full code for this tutorial can be found in [`examples/tutorial_7.rs`][tutorial-7]. If you don't use the [example server for this tutorial][example-server], you may need to change the code to use a different username and password.

[tutorial-7]: https://github.com/honzasp/makiko/blob/master/examples/tutorial_7.rs
[example-server]: {% link tutorial/1-connect.md %}#example-server

This concludes the Makiko tutorial. Thank you for your interest, I hope that the library will be useful to you and that you will enjoy using it!

<p>
    <a href="https://docs.rs/makiko/latest/makiko" class="btn btn-purple">Next: API documentation</a>
</p>
