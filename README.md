# Makiko

Makiko is an asynchronous SSH client library in pure Rust.

**[Tutorial][tutorial] | [API docs][docs-rs] | [Github][github] | [Crate][crates-io]**

[tutorial]: https://honzasp.github.io/makiko/tutorial
[docs-rs]: https://docs.rs/makiko/latest/makiko
[github]: https://github.com/honzasp/makiko
[crates-io]: https://crates.io/crates/makiko

## Features

- SSH protocol 2
- Authentication methods: publickey, password, none
- Shell/exec sessions
- Remote and local tunnels
- Raw SSH channels (low-level API)
- Ciphers: chacha20-poly1305, aes128-gcm, aes256-gcm, aes128-ctr, aes192-ctr,
  aes256-ctr, aes128-cbc*, aes192-cbc*, aes256-cbc*, 3des-cbc**
- MACs: hmac-sha2-256-etm, hmac-sha2-512-etm, hmac-sha2-256, hmac-sha2-512,
  hmac-sha1-etm*, hmac-sha1*
- Public key algorithms: ssh-ed25519, rsa-sha2-256, rsa-sha2-512,
  ecdsa-sha2-nistp256*, ecdsa-sha2-nistp384*, ssh-rsa*
- Key exchange algorithms: curve25519-sha256, diffie-hellman-group14-sha1*,
  diffie-hellman-group14-sha256*, diffie-hellman-group16-sha512*,
  diffie-hellmann-group18-sha512*, diffie-hellman-group1-sha1**
- Crypto from [Rust Crypto][rust-crypto]
- Use your own sockets, spawn your own tasks
- Uses [Tokio][tokio] interfaces (but does not depend on the Tokio runtime)
- Rust all the way down: no dependency on non-Rust libraries, direct or indirect

[rust-crypto]: https://github.com/RustCrypto
[tokio]: https://tokio.rs/

(* Algorithms marked with an asterisk are not enabled by default)
(** Algorithms marked with two asterisks are only available with feature `insecure-crypto`)

## Low-level

Makiko gives you a lot of control over the SSH connection, it is meant to be a
building block for libraries and advanced applications.

> Makiko and most of the cryptography crates from [Rust Crypto][rust-crypto]
> that Makiko uses have not yet been audited by a trusted third party. Use at
> your own risk!

## Contributing

Contributions are welcome! Please contact me ([@honzasp][honzasp]) or open a
pull request.

[honzasp]: https://github.com/honzasp

## License

This software is released into the public domain. Please see [UNLICENSE](UNLICENSE).
