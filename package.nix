# TODO: move this to nixpkgs
# This file aims to be a replacement for the nixpkgs derivation.

{
  lib,
  rustPlatform,
  fetchFromGitHub,
  buildPackages,
  stdenv,
  installShellFiles,
  installShellCompletions ? stdenv.buildPlatform.canExecute stdenv.hostPlatform,
  installManPages ? stdenv.buildPlatform.canExecute stdenv.hostPlatform,
  buildNoDefaultFeatures ? false,
  buildFeatures ? [ ],
  ...
}:

let
  version = "1.0.0";
  hash = "";
  cargoHash = "";

in
rustPlatform.buildRustPackage {
  inherit cargoHash version buildNoDefaultFeatures;

  pname = "discovery";

  src = fetchFromGitHub {
    inherit hash;
    owner = "pimalaya";
    repo = "io-discovery";
    rev = "v${version}";
  };

  nativeBuildInputs = lib.optional (installManPages || installShellCompletions) installShellFiles;

  buildFeatures = [ "cli" ] ++ buildFeatures;

  doCheck = false;

  postInstall =
    let
      emulator = stdenv.hostPlatform.emulator buildPackages;
      exe = stdenv.hostPlatform.extensions.executable;
    in
    lib.optionalString (lib.hasInfix "wine" emulator) ''
      export WINEPREFIX="''${WINEPREFIX:-$(mktemp -d)}"
      mkdir -p $WINEPREFIX
    ''
    + ''
      mkdir -p $out/share/{completions,man}
      ${emulator} "$out"/bin/discovery${exe} manuals "$out"/share/man
      ${emulator} "$out"/bin/discovery${exe} completions -d "$out"/share/completions bash elvish fish powershell zsh
    ''
    + lib.optionalString installManPages ''
      installManPage "$out"/share/man/*
    ''
    + lib.optionalString installShellCompletions ''
      installShellCompletion --bash "$out"/share/completions/discovery.bash
      installShellCompletion --fish "$out"/share/completions/discovery.fish
      installShellCompletion --zsh "$out"/share/completions/_discovery
    '';

  meta = rec {
    description = "CLI to manage timers";
    mainProgram = "discovery";
    homepage = "https://github.com/pimalaya/io-discovery";
    changelog = "${homepage}/blob/v${version}/CHANGELOG.md";
    license = lib.licenses.agpl3Plus;
    maintainers = with lib.maintainers; [ soywod ];
  };
}
