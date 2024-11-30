{
    pkgs,
    ...
}:
pkgs.mkShell {
    nativeBuildInputs = with pkgs; [
      makeWrapper
      bashInteractive
    ];

    buildInputs = with pkgs; [
      go
      gopls
    ];

    shellHook = ''
      echo "Hello from shell!"
    '';
}

