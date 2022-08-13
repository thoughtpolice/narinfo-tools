# `narinfo-tools`

This tool takes `.narinfo` files, and does things with them. Right now it can:

- Convert a `.narinfo` file to JSON. This is a very disgusting hack, because at
the time I originally wrote it I was awful at Rust, but it works.
- Can sign a `.narinfo` file and produce a new `.narinfo` file with a proper
`Sig:` field. This is slightly less awful but still not good, because I'm only
marginally better at Rust now.

It'll do more than that, one day.

This tool is implemented in Rust and targets **[WebAssembly System
Interface][WASI]** by default for portability. So in practice, it takes input on
`stdin` and output on `stdout`, like a Unix program.

There is no documentation. Read the source code to see how it works, it's fairly
simple. You mostly just provide `stdin` and some environment variables, and read
`stdout`.

## Motivation

The goal is to allow its use in a wide array of contexts: there are WebAssembly
engines available for almost all major programming languages, so you can just
embed the `.wasm` binary into your program and run it as a program. Consider
this an experimental alternative to the "normal" foreign interface method of
using the C ABI.

More specifically, I wanted to manipulate nar files in "serverless" computing
environments like Cloudflare Workers and Fastly Compute@Edge.

By default, **[Wasmtime]** is used for executing programs.

[Nix]: https://nixos.org/nix
[WASI]: https://wasi.dev
[Wasmtime]: https://wasmtime.dev

## License & Acknowledgements

&copy; 2022 Austin Seipp. Dually available under the MIT/Apache-2.0 licenses, like most Rust projects.
