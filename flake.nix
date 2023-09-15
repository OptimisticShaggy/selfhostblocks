{
  description = "SelfHostBlocks module";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    sops-nix.url = "github:Mic92/sops-nix";
  };

  outputs = inputs@{ self, nixpkgs, sops-nix, ... }: {
    nixosModules.default = { config, ... }: {
      imports = [
        modules/authelia.nix
        modules/backup.nix
        modules/hledger.nix
        modules/home-assistant.nix
        modules/jellyfin.nix
        modules/ldap.nix
        modules/monitoring.nix
        modules/nextcloud-server.nix
        modules/nginx.nix
        modules/ssl.nix
      ];
    };

    # templates.default = {};  Would be nice to have a template

    # Follows https://blog.thalheim.io/2023/01/08/how-to-use-nixos-testing-framework-with-flakes/
    checks = nixpkgs.lib.genAttrs [ "x86_64-linux" ] (system:
      let
        checkArgs = {
          pkgs = nixpkgs.legacyPackages.${system};
          inherit self;
        };
      in {
        ssl = import ./tests/ssl.nix checkArgs;
      });
  };
}
