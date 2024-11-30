{
  description = "logstash-exporter nix packaged";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system: 
    let
      # Helper to provide system-specific attributes
      pkgs = import nixpkgs { inherit system; };

    in {
        devShells.default = pkgs.callPackage ./shell.nix {inherit pkgs; };
    }
  );
}

