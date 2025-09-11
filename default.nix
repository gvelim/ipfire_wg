{
  pkgs ? import <nixpkgs> {}
} :
pkgs.mkShellNoCC {
  packages = [
    pkgs.shellcheck
    pkgs.shfmt
  ];
 }
