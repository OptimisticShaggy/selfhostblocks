(import ./lib.nix) {
  name = "deluge";

  nodes = {
    machine = { self, config, pkgs, ... }: {

      imports = [
        self.nixosModules.default
        self.inputs.sops-nix.nixosModules.default
      ];

      services.openssh.enable = true;
      services.openssh.hostKeys = [{
        type = "rsa";
        bits = 4096;
        path = ./assets/machine-ssh-key;
      }];

      shb.ssl = {
        enable = true;
        domain = "local.test";
        adminEmail = "shb@local.test";
        dnsProvider = "linode";
        sopsFile = ./assets/secrets.yaml;
      };
    };
  };

  testScript = ''
  start_all()

  machine.wait_for_unit("acme-local.test")
  '';
}
