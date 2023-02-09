---
title: Public key authentication
layout: page
parent: Tutorial
nav_order: 3
---

# {{ page.title }}

In this chapter, we will authenticate to the SSH server using a private key. With this authentication method, we send a public key to the server and we cryptographically prove that we own the corresponding private key. However, our private key is not transmitted, so it stays secure even if we connect to an untrusted server. The server then decides whether to accept the public key, for example by consulting a list of public keys stored in the [`~/.ssh/authorized_keys`][authorized-keys] file on the server.

[authorized-keys]: https://man.openbsd.org/sshd#AUTHORIZED_KEYS_FILE_FORMAT

## Get the private key

Makiko supports several types of public/private keys:

- [RSA][rsa] is the original public key cryptosystem based on integer factorization, which is still widely deployed. The theoretical algorithm is sound, but practical implementations of RSA have a long history of being subtly flawed, so using RSA is [discouraged][stop-using-rsa].
- [Elliptic curve cryptography][ecc] is a more modern class of public key algorithms that are based on elliptic curves. Makiko supports:
    - [ECDSA][ecdsa] is a standardized signature algorithm scheme based on elliptic curves. Makiko supports ECDSA with two curves, NIST P-256 and NIST P-384. However, there have been suspicions that these curves may contain a backdoor, because they are generated using parameters that have not been fully explained.
    - [EdDSA][eddsa] is a different signature algorithm scheme. Makiko supports the algorithm [Ed25519][ed25519], which uses [Curve25519][curve25519]. This algorithm is fast and is considered very secure.

[rsa]: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
[stop-using-rsa]: https://blog.trailofbits.com/2019/07/08/fuck-rsa/
[ecc]: https://en.wikipedia.org/wiki/Elliptic-curve_cryptography
[ecdsa]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
[eddsa]: https://en.wikipedia.org/wiki/EdDSA
[ed25519]: https://ed25519.cr.yp.to/
[curve25519]: https://cr.yp.to/ecdh.html

In Makiko, public keys are represented as the enum [`Pubkey`][pubkey] and private keys as the enum [`Privkey`][privkey]. You can always obtain the public key from the private key by calling [`Privkey::pubkey()`][privkey-pubkey].

[pubkey]: https://docs.rs/makiko/latest/makiko/pubkey/enum.Pubkey.html
[privkey]: https://docs.rs/makiko/latest/makiko/pubkey/enum.Privkey.html
[privkey-pubkey]: https://docs.rs/makiko/latest/makiko/pubkey/enum.Privkey.html#method.pubkey

### File formats for private keys

To authenticate with public key authentication, we need to obtain the private key. Makiko can read private keys in the following formats:

- PKCS#1: Legacy format for RSA keys, uses [ASN.1][asn1] and encodes the key using the [DER][der] encoding.
- PKCS#8: A newer format that can encode keys from different public key algorithms. This format is common when working with TLS and other cryptography applications. It is also based on ASN.1 and uses DER encoding.
- OpenSSH: A format for private keys that is used by OpenSSH. The key is not encoded using DER but with the same encoding that is used in the SSH protocol.

[asn1]: https://en.wikipedia.org/wiki/ASN.1
[der]: https://en.wikipedia.org/wiki/X.690#DER_encoding

Private keys in these formats may also be encrypted. Makiko supports decrypting private keys in PKCS#8 and OpenSSH formats; encrypted keys in the PKCS#1 format are not supported.

All these formats are binary. To make them easier to use, they are usually stored in [PEM][pem] format, which encodes the binary data in a textual form. PEM files can be easily recognized by starting with `-----BEGIN <tag>-----`, followed by base64-encoded data and ending with `-----END <tag>-----`, where `<tag>` is a string that determines the format of the binary data:

- `-----BEGIN PRIVATE KEY-----` is a private key in PKCS#8 format,
- `-----BEGIN RSA PRIVATE KEY-----` is a private key in PKCS#1 format,
- `-----BEGIN OPENSSH PRIVATE KEY-----` is a private key in OpenSSH format, and
- `-----BEGIN ENCRYPTED PRIVATE KEY-----` is an encrypted private key in PKCS#8 format.

[pem]: https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail

PEM files can also store other types of cryptographic material such as certificates (`-----BEGIN CERTIFICATE-----`).

### Decode the private key

In Makiko, the [`makiko::keys`][keys] module contains functions for decoding from all these formats, both binary and PEM. For the common case of reading an unencrypted private key from PEM, you can use the function [`decode_pem_privkey_nopass`][decode-pem-privkey-nopass], which automatically detects the format of the key from the PEM tag. This function returns an enum [`DecodedPrivkeyNopass`][decoded-privkey-nopass], which can take one of these variants:

- `Privkey` if we successfully decoded the private key.
- `Pubkey` if the private key was encrypted, but we could at least decode the public key. This is supported only by the OpenSSH format.
- `Encrypted` if the file was encrypted and we could not decode anything.

We will just use the [`DecodedPrivkeyNopass::privkey()`][decoded-privkey-nopass-privkey] convenience method to get the private key, if it is available. However, in a real application, we may want to prompt the user for the password if the key is encrypted.

[keys]: https://docs.rs/makiko/latest/makiko/keys/index.html
[decode-pem-privkey-nopass]: https://docs.rs/makiko/latest/makiko/keys/fn.decode_pem_privkey_nopass.html
[decoded-privkey-nopass]: https://docs.rs/makiko/latest/makiko/keys/enum.DecodedPrivkeyNopass.html
[decoded-privkey-nopass-privkey]: https://docs.rs/makiko/latest/makiko/keys/enum.DecodedPrivkeyNopass.html#method.privkey

```rust
// Decode our private key from PEM.
let privkey = makiko::keys::decode_pem_privkey_nopass(PRIVKEY_PEM)
    .expect("Could not decode a private key from PEM")
    .privkey().cloned()
    .expect("Private key is encrypted");
```

In this tutorial, we simply hard-coded the private key, but in practice, you would usually read the key from a file or from configuration.

```rust
const PRIVKEY_PEM: &[u8] = br#"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDyVJsRfh+NmkQKg2Dh6rPVodiQ3nC+dVoGMoMtYcbMJQAAAJBPdwHAT3cB
wAAAAAtzc2gtZWQyNTUxOQAAACDyVJsRfh+NmkQKg2Dh6rPVodiQ3nC+dVoGMoMtYcbMJQ
AAAEA5ct+xfc9qlJ4I2Jee8HIrAhN55yxmtUmvKpjT7q6QXPJUmxF+H42aRAqDYOHqs9Wh
2JDecL51WgYygy1hxswlAAAABmVkd2FyZAECAwQFBgc=
-----END OPENSSH PRIVATE KEY-----
"#;
```

{: .warning }
Never hard-code private keys or other credentials into your program in practice!

## Authenticate

Once we have the private key, we need to select the signing algorithm that we will use for authentication. For ECDSA and EdDSA keys, the algorithm is determined by the key type, but for RSA keys, multiple algorithms are applicable.

The RSA algorithms differ in the hash function that is used during signing: the original algorithm ["ssh-rsa"][ssh-rsa] uses the SHA-1 hash algorithm, which was found to be insecure, so the protocol was extended with new algorithms that replace the hash function with SHA-2 (Makiko supports ["rsa-sha2-256"][rsa-sha2-256] and ["rsa-sha2-512"][rsa-sha2-512]). These new algorithms work with the same keys as the old "ssh-rsa" algorithm, the only difference is in the mechanism that the client uses to prove to the server that it knows the private key.

[ssh-rsa]: https://docs.rs/makiko/latest/makiko/pubkey/static.SSH_RSA_SHA1.html
[rsa-sha2-256]: https://docs.rs/makiko/latest/makiko/pubkey/static.RSA_SHA2_256.html
[rsa-sha2-512]: https://docs.rs/makiko/latest/makiko/pubkey/static.RSA_SHA2_512.html

All public key algorithms supported in Makiko are listed in the [`makiko::pubkey`][supported-algos] module. In this chapter, we know that the private key that we decoded in the previous section is [an Ed25519 key][ed25519-privkey], so there is just a single applicable algorithm, ["ssh-ed25519"][ssh-ed25519]. In the next chapter, we will see how to select the algorithm more robustly.

[supported-algos]: https://docs.rs/makiko/latest/makiko/pubkey/index.html#supported-algorithms
[ed25519-privkey]: https://docs.rs/makiko/latest/makiko/pubkey/struct.Ed25519Privkey.html
[ssh-ed25519]: https://docs.rs/makiko/latest/makiko/pubkey/static.SSH_ED25519.html

```rust
// Select an algorithm for public key authentication.
let pubkey_algo = &makiko::pubkey::SSH_ED25519;
```

We can now call the [`Client::auth_pubkey()`][client-auth-pubkey] method to authenticate with username "edward" and the private key:

[client-auth-pubkey]: https://docs.rs/makiko/latest/makiko/struct.Client.html#method.auth_pubkey

```rust
// Try to authenticate with the private key
let auth_res = client.auth_pubkey("edward".into(), privkey, pubkey_algo).await
    .expect("Error when trying to authenticate");
```

The method returns an [`AuthPubkeyResult`][auth-pubkey-result], which is either a `Success` or `Failure`:

[auth-pubkey-result]: https://docs.rs/makiko/latest/makiko/enum.AuthPubkeyResult.html

```rust
// Deal with the possible outcomes of public key authentication.
match auth_res {
    makiko::AuthPubkeyResult::Success => {
        println!("We have successfully authenticated using a private key");
    },
    makiko::AuthPubkeyResult::Failure(failure) => {
        panic!("The server rejected authentication: {:?}", failure);
    }
}
```

---

Full code for this tutorial can be found in [`examples/tutorial_3.rs`][tutorial-3]. The program will print a message if the authentication was successful, or an error if it failed. If you don't use the [example server for this tutorial][example-server], you may need to change the code to use a different username and private key.

[tutorial-3]: https://github.com/honzasp/makiko/blob/master/examples/tutorial_3.rs
[example-server]: {% link tutorial/1-connect.md %}#example-server

{% include tutorial_next.html link="tutorial/4-pubkey-algo.md" title="Public key algorithm" %}
