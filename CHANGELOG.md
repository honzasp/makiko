# Makiko changelog

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
