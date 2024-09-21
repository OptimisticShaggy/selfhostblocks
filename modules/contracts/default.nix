{ lib }:
{
  backup = import ./backup.nix { inherit lib; };
  mount = import ./mount.nix { inherit lib; };
  secret = import ./secret.nix { inherit lib; };
  ssl = import ./ssl.nix { inherit lib; };
}
