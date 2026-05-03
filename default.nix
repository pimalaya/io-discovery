{
  nixpkgs ? <nixpkgs>,
  pimalaya ? import (fetchTarball "https://github.com/pimalaya/nix/archive/master.tar.gz"),
  ...
}@args:

pimalaya.mkDefault (
  {
    src = ./.;
    version = "1.2.0";
    mkPackage = (
      {
        lib,
        pkgs,
        buildPackages,
        rustPlatform,
        defaultFeatures,
        features,
      }:

      pkgs.callPackage ./package.nix {
        inherit lib rustPlatform buildPackages;
        apple-sdk = pkgs.apple-sdk;
        installShellCompletions = false;
        installManPages = false;
        buildNoDefaultFeatures = !defaultFeatures;
        buildFeatures = lib.splitString "," features;
      }
    );

  }
  // removeAttrs args [ "pimalaya" ]
)
