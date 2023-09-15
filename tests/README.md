# Tests

## Run Tests

```bash
nix flake check -L
```

## Create secret

```bash
mkdir assets
```

Create the age key:
```bash
nix shell nixpkgs#age -c age-keygen -o assets/keys.txt
```

Create a ssh key for the local client and the machine.
```bash
nix shell nixpkgs#openssh -c ssh-keygen -t ed25519 -b 4096 -f assets/ssh-key
nix shell nixpkgs#openssh -c ssh-keygen -t ed25519 -b 4096 -f assets/machine-ssh-key
```

Convert the public ssh key to age keys.
```bash
cat assets/machine-ssh-key.pub | nix run nixpkgs#ssh-to-age
```

Add both keys to the `sops.yaml` respectively as the admin and machine keys.

Create or edit the `secrets.yaml` file:
```bash
SOPS_AGE_KEY_FILE=assets/keys.txt nix run nixpkgs#sops -- --config assets/sops.yaml assets/secrets.yaml
```


