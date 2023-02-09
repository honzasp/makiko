---
title: Tutorial
layout: page
has_children: true
---

# {{ page.title }}

Makiko is an asynchronous SSH client library for Rust. It gives you a lot of control over the SSH connection, but this means that it is quite low-level.

In this tutorial, we will to connect to a server, authenticate with a password or a public key, execute a command and open a tunnel. I will assume that you know [Rust][rust], have some experience with [Tokio][tokio] and have used SSH previously.

[rust]: https://www.rust-lang.org/
[tokio]: https://tokio.rs/

## The code

If you want to follow along with the tutorial, create a new Rust project using Cargo:

```
$ cargo new hello_makiko
$ cd hello_makiko
```

And add the dependencies to Makiko and Tokio into your `Cargo.toml`:

```toml
[dependencies]
makiko = "0.2.1"
tokio = {version = "1.25", features = ["full"]}
```

You can also find complete code for each chapter in this tutorial [in the `examples/` directory][examples] in the Makiko repository.

[examples]: https://github.com/honzasp/makiko/tree/master/examples

In the next chapter, we will start writing the code in `src/main.rs`.

{% include tutorial_next.html link="tutorial/1-connect.md" title="Connecting to the server" %}
