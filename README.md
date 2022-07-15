# `narinfo-tools`

This tool takes `.narinfo` files, and does things with them. Right now it can
convert `.narinfo` files to JSON records and also will one day sign things with
a Nix key. And maybe more.

It's implemented in Rust and targets **[WebAssembly System Interface][WASI]** by
default for portability — which allows its use even in more contexts (for
example, you can use it for foreign interfacing in any language with a WASI
implementation).

By default, **[Wasmtime]** is used for executing programs.

[Nix]: https://nixos.org/nix
[WASI]: https://wasi.dev
[Wasmtime]: https://wasmtime.dev

## License & Acknowledgements

&copy; 2022 Austin Seipp. Dually available under the MIT/Apache-2.0 licenses, like most Rust projects.
