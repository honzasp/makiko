---
title: Home
layout: home
---

# {{ site.title }}
{: .fs-9}

{{ site.description }}
{: .fs-6 .fw-300 .text-grey-dk-200}

[Get started]({% link tutorial/index.md %}){: .btn .btn-primary }
[API docs][docs-rs]{: .btn .ml-4 }
[Github][github]{: .btn .ml-4 }
[Crate][crates-io]{: .btn .ml-4 }

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
  aes256-ctr, aes128-cbc\*, aes192-cbc\*, aes256-cbc\*
- MACs: hmac-sha2-256-etm, hmac-sha2-512-etm, hmac-sha2-256, hmac-sha2-512,
  hmac-sha1-etm\*, hmac-sha1\*
- Public key algorithms: ssh-ed25519, rsa-sha2-256, rsa-sha2-512,
  ecdsa-sha2-nistp256\*, ecdsa-sha2-nistp384\*, ssh-rsa\*
- Key exchange algorithms: curve25519-sha256, diffie-hellman-group14-sha1\*,
  diffie-hellman-group14-sha256\*, diffie-hellman-group16-sha512\*,
  diffie-hellmann-group18-sha512\*
- Crypto from [Rust Crypto][rust-crypto]
- Use your own sockets, spawn your own tasks
- Uses [Tokio][tokio] interfaces (but does not depend on the Tokio runtime)
- Rust all the way down: no dependency on non-Rust libraries, direct or indirect

[rust-crypto]: https://github.com/RustCrypto
[tokio]: https://tokio.rs/

<i>\* Algorithms marked with an asterisk are not enabled by default</i>
{: .text-grey-dk-200}

## Low-level

Makiko gives you a lot of control over the SSH connection, it is meant to be a building block for libraries and advanced applications.

{: .warning }
Makiko and most of the cryptography crates from [Rust Crypto][rust-crypto] that Makiko uses have not yet been audited by a trusted third party. Use at your own risk!
