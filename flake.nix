{
  description = "A tool for signing narinfo files offline";

  inputs = {
    nixpkgs.url      = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-utils.url  = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    let
      rust-version = "1.62.0";

      systems = with flake-utils.lib; [
        system.x86_64-linux
      ];
    in flake-utils.lib.eachSystem systems (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rust-bin = pkgs.rust-bin.stable."${rust-version}".default.override
          { targets = [ "wasm32-wasi" ];
          };

        rustPlatform = pkgs.makeRustPlatform { cargo = rust-bin; rustc = rust-bin; };
      in rec {
        apps = rec {
          default = run-app;
          run-app = { type = "app"; program = "${packages.narinfo-tools}/bin/narinfo-tools"; };
        };

        packages = flake-utils.lib.flattenTree rec {
          default = narinfo-tools;

          narinfo-tools = rustPlatform.buildRustPackage rec {
            pname = "narinfo-tools";
            version = "0.1.0";
            src = ./.;

            nativeBuildInputs = [ pkgs.wasmtime ];

            buildPhase = "cargo build -j $NIX_BUILD_CORES --target wasm32-wasi --frozen --release";
            installPhase = ''
              mkdir -p $out/{bin,share}
              mv target/wasm32-wasi/release/${pname}.wasm $out/share

              touch $out/bin/${pname} && chmod +x $out/bin/${pname}
              echo "#!${pkgs.bash}/bin/bash" >> $out/bin/${pname}
              echo "exec ${pkgs.wasmtime}/bin/wasmtime $out/share/${pname}.wasm \$@" >> $out/bin/${pname}
            '';

            cargoHash = "sha256-8LZXKhG+lRjhLeUEXDXavrsZV4HfrWSiMWljSKjDec0=";
          };
        };
      });
}
