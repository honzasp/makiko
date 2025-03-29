# Makiko changelog

## 0.2.5 (2025-03-29)

- Add `TunnelReader`, `TunnelWriter` and `TunnelStream`

## 0.2.4 (2024-11-09)

- Add support for `diffie-hellman-group1-sha1` key exchange under `insecure-crypto` feature.
- Add support for `3des-cbc` cipher under `insecure-crypto` feature.

## 0.2.3 (2024-07-22)

- Add `Client::send_keepalive()` to send an OpenSSH-compatible keepalive request.
- Upgraded dependencies.

## 0.2.2 (2023-06-04)

- Replace the `guard` crate with (now stabilized) `let else` expressions
  supported directly by the compiler. Fixes compatibility with Rust 1.70.0.
- Upgraded dependencies.

## 0.2.1 (2023-02-09)

- Deprecated `Pubkey::algos_secure()` and
  `Pubkey::algos_compatible_less_secure()`, replace with
  `Pubkey::algos()`

## 0.2.0 (2022-10-01)

The first generally usable version.
