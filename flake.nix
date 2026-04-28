{
  description = "rageveil — git+age password manager (drop-in passveil replacement)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        rageveil = pkgs.rustPlatform.buildRustPackage {
          pname = "rageveil";
          version = "0.1.0";
          src = ./.;

          cargoLock.lockFile = ./Cargo.lock;

          # Tests spawn `git` subprocesses (round_trip, sharing,
          # delete_flow, git_sync, …). The nix build sandbox has
          # no git on PATH and disallows network — tests would
          # fail spuriously. They pass under `cargo test` in a
          # dev shell; that's where we run them.
          doCheck = false;

          meta = with pkgs.lib; {
            description = "git+age password manager (drop-in passveil replacement)";
            license = licenses.agpl3Plus;
            mainProgram = "rageveil";
            platforms = platforms.unix;
          };
        };
      in
      {
        packages.default = rageveil;
        packages.rageveil = rageveil;

        # `nix develop` — same toolchain the project compiles
        # under, plus tools test runs need.
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.cargo
            pkgs.rustc
            pkgs.rustfmt
            pkgs.clippy
            pkgs.git
          ];
        };
      }
    );
}
