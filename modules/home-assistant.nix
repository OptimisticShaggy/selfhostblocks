{ config, pkgs, lib, ... }:

let
  cfg = config.shb.home-assistant;

  fqdn = "${cfg.subdomain}.${cfg.domain}";

  ldap_auth_script_repo = pkgs.fetchFromGitHub {
    owner = "lldap";
    repo = "lldap";
    rev = "7d1f5abc137821c500de99c94f7579761fc949d8";
    sha256 = "sha256-8D+7ww70Ja6Qwdfa+7MpjAAHewtCWNf/tuTAExoUrg0=";
  };

  ldap_auth_script = pkgs.writeShellScriptBin "ldap_auth.sh" ''
    export PATH=${pkgs.gnused}/bin:${pkgs.curl}/bin:${pkgs.jq}/bin
    exec ${pkgs.bash}/bin/bash ${ldap_auth_script_repo}/example_configs/lldap-ha-auth.sh $@
  '';

  oidc_auth_script_raw = pkgs.writeText "oidc_auth.sh" (builtins.readFile ./home-assistant-oidc.sh);

  oidc_auth_script = pkgs.writeShellScriptBin "oidc_auth.sh" ''
    export PATH=${pkgs.gnused}/bin:${pkgs.curl}/bin:${pkgs.jq}/bin:${pkgs.coreutils}/bin
    exec ${pkgs.bash}/bin/bash ${oidc_auth_script_raw} $@
  '';
in
{
  options.shb.home-assistant = {
    enable = lib.mkEnableOption "selfhostblocks.home-assistant";

    subdomain = lib.mkOption {
      type = lib.types.str;
      description = "Subdomain under which home-assistant will be served.";
      example = "ha";
    };

    domain = lib.mkOption {
      type = lib.types.str;
      description = "domain under which home-assistant will be served.";
      example = "mydomain.com";
    };

    ldapEndpoint = lib.mkOption {
      type = lib.types.str;
      description = "host serving the LDAP server";
      example = "http://127.0.0.1:389";
    };

    sopsFile = lib.mkOption {
      type = lib.types.path;
      description = "Sops file location";
      example = "secrets/homeassistant.yaml";
    };

    backupCfg = lib.mkOption {
      type = lib.types.anything;
      description = "Backup configuration for home-assistant";
      default = {};
      example = {
        backend = "restic";
        repositories = [];
      };
    };

    oidcEndpoint = lib.mkOption {
      type = lib.types.str;
      description = "OIDC endpoint for SSO";
      example = "https://authelia.example.com";
    };
  };

  config = lib.mkIf cfg.enable {
    services.home-assistant = {
      enable = true;
      # Find them at https://github.com/NixOS/nixpkgs/blob/master/pkgs/servers/home-assistant/component-packages.nix
      extraComponents = [
        # Components required to complete the onboarding
        "met"
        "radio_browser"
      ];
      configDir = "/var/lib/hass";
      # If you can't find a component in component-packages.nix, you can add them manually with something similar to:
      # extraPackages = python3Packages: [
      #   (python3Packages.simplisafe-python.overrideAttrs (old: rec {
      #     pname = "simplisafe-python";
      #     version = "5b003a9fa1abd00f0e9a0b99d3ee57c4c7c16bda";
      #     format = "pyproject";

      #     src = pkgs.fetchFromGitHub {
      #       owner = "bachya";
      #       repo = pname;
      #       rev = "${version}";
      #       hash = "sha256-Ij2e0QGYLjENi/yhFBQ+8qWEJp86cgwC9E27PQ5xNno=";
      #     };
      #   }))
      # ];
      config = {
        # Includes dependencies for a basic setup
        # https://www.home-assistant.io/integrations/default_config/
        default_config = {};
        http = {
          use_x_forwarded_for = true;
          server_host = "127.0.0.1";
          server_port = 8123;
          trusted_proxies = "127.0.0.1";
        };
        logger.default = "info";
        homeassistant = {
          external_url = "https://${cfg.subdomain}.${cfg.domain}";
          country = "!secret country";
          latitude = "!secret latitude_home";
          longitude = "!secret longitude_home";
          time_zone = "America/Los_Angeles";
          auth_providers = [
            # Ensure you have the homeassistant provider enabled if you want to continue using your existing accounts
            { type = "homeassistant"; }
            { type = "command_line";
              command = oidc_auth_script + "/bin/oidc_auth.sh";
              # Only allow users in the 'homeassistant_user' group to login.
              # Change to ["https://lldap.example.com"] to allow all users
              # args = [ cfg.ldapEndpoint "homeassistant_user" ];
              args = [ cfg.oidcEndpoint ];
              meta = true;
            }
          ];
        };
        "automation ui" = "!include automations.yaml";
        "scene ui" = "!include scenes.yaml";
        "script ui" = "!include scripts.yaml";

        "automation manual" = [
          {
            alias = "Create Backup on Schedule";
            trigger = [
              {
                platform = "time_pattern";
                minutes = "5";
              }
            ];
            action = [
              {
                service = "shell_command.delete_backups";
                data = {};
              }
              {
                service = "backup.create";
                data = {};
              }
            ];
            mode = "single";
          }
        ];

        shell_command = {
          delete_backups = "find ${config.services.home-assistant.configDir}/backups -type f -delete";
        };
      };
    };

    services.nginx.virtualHosts."${fqdn}" = {
      forceSSL = true;
      http2 = true;
      sslCertificate = "/var/lib/acme/${cfg.domain}/cert.pem";
      sslCertificateKey = "/var/lib/acme/${cfg.domain}/key.pem";
      # https://www.authelia.com/integration/proxies/nginx/
      extraConfig = ''
        proxy_buffering off;
      '';
      locations."/" = {
        proxyPass = "http://${toString config.services.home-assistant.config.http.server_host}:${toString config.services.home-assistant.config.http.server_port}/";
        proxyWebsockets = true;

        extraConfig =
          # From https://www.authelia.com/integration/proxies/nginx/#authelia-authrequestconf
          ''
          ## Send a subrequest to Authelia to verify if the user is authenticated and has permission to access the resource.
          auth_request /authelia;

          ## Set the $target_url variable based on the original request.

          ## Comment this line if you're using nginx without the http_set_misc module.
          # set_escape_uri $target_url $scheme://$http_host$request_uri;

          ## Uncomment this line if you're using NGINX without the http_set_misc module.
          set $target_url $scheme://$http_host$request_uri;
 
          ## Save the upstream response headers from Authelia to variables.
          auth_request_set $user $upstream_http_remote_user;
          auth_request_set $groups $upstream_http_remote_groups;
          auth_request_set $name $upstream_http_remote_name;
          auth_request_set $email $upstream_http_remote_email;
 
          ## Inject the response headers from the variables into the request made to the backend.
          proxy_set_header Remote-User $user;
          proxy_set_header Remote-Groups $groups;
          proxy_set_header Remote-Name $name;
          proxy_set_header Remote-Email $email;

          ## If the subreqest returns 200 pass to the backend, if the subrequest returns 401 redirect to the portal.
          error_page 401 =302 https://${cfg.oidcEndpoint}/?rd=$target_url;
          ''
          # From https://www.authelia.com/integration/proxies/nginx/#proxyconf
          + ''
          ## Headers
          proxy_set_header Host $host;
          proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
          proxy_set_header X-Forwarded-Proto $scheme;
          proxy_set_header X-Forwarded-Host $http_host;
          proxy_set_header X-Forwarded-Uri $request_uri;
          proxy_set_header X-Forwarded-Ssl on;
          proxy_set_header X-Forwarded-For $remote_addr;
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header Connection "";

          ## Basic Proxy Configuration
          client_body_buffer_size 128k;
          proxy_next_upstream error timeout invalid_header http_500 http_502 http_503; ## Timeout if the real server is dead.
          proxy_redirect  http://  $scheme://;
          proxy_cache_bypass $cookie_session;
          proxy_no_cache $cookie_session;
          proxy_buffers 64 256k;

          ## Trusted Proxies Configuration
          ## Please read the following documentation before configuring this:
          ##     https://www.authelia.com/integration/proxies/nginx/#trusted-proxies
          # set_real_ip_from 10.0.0.0/8;
          # set_real_ip_from 172.16.0.0/12;
          # set_real_ip_from 192.168.0.0/16;
          # set_real_ip_from fc00::/7;
          # set_real_ip_from 127.0.0.1;
          real_ip_header X-Forwarded-For;
          real_ip_recursive on;

          ## Advanced Proxy Configuration
          send_timeout 5m;
          proxy_read_timeout 360;
          proxy_send_timeout 360;
          proxy_connect_timeout 360;
          '';
      };

      locations."/authelia" = {
        proxyPass = "${cfg.oidcEndpoint}/api/verify";

        # From https://www.authelia.com/integration/proxies/nginx/#authelia-locationconf
        extraConfig = ''
          internal;

          proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
          proxy_set_header X-Original-Method $request_method;
          proxy_set_header X-Forwarded-Method $request_method;
          proxy_set_header X-Forwarded-Proto $scheme;
          proxy_set_header X-Forwarded-Host $http_host;
          proxy_set_header X-Forwarded-Uri $request_uri;
          proxy_set_header X-Forwarded-For $remote_addr;
          proxy_set_header Content-Length "";
          proxy_set_header Connection "";

          proxy_pass_request_body off;
          proxy_next_upstream error timeout invalid_header http_500 http_502 http_503; # Timeout if the real server is dead
          proxy_redirect http:// $scheme://;
          proxy_http_version 1.1;
          proxy_cache_bypass $cookie_session;
          proxy_no_cache $cookie_session;
          proxy_buffers 4 32k;
          client_body_buffer_size 128k;

          send_timeout 5m;
          proxy_read_timeout 240;
          proxy_send_timeout 240;
          proxy_connect_timeout 240;
        '';
      };
    };

    # Rules from https://community.home-assistant.io/t/anyone-have-authelia-working-with-ha-to-handle-authentication/321233/18
    shb.authelia.rules = [
      {
        domain = fqdn;
        policy = "bypass";
        resources = [
          "^/api.*"
          "^/auth/token.*"
          "^/.external_auth=."
          "^/service_worker.js"
          "^/static/.*"
        ];
      }
      {
        domain = fqdn;
        policy = "two_factor";
      }
    ];

    sops.secrets."home-assistant" = {
      inherit (cfg) sopsFile;
      mode = "0440";
      owner = "hass";
      group = "hass";
      path = "${config.services.home-assistant.configDir}/secrets.yaml";
      restartUnits = [ "home-assistant.service" ];
    };

    systemd.tmpfiles.rules = [
      "f ${config.services.home-assistant.configDir}/automations.yaml 0755 hass hass"
      "f ${config.services.home-assistant.configDir}/scenes.yaml      0755 hass hass"
      "f ${config.services.home-assistant.configDir}/scripts.yaml     0755 hass hass"
    ];

    shb.backup.instances.home-assistant = lib.mkIf (cfg.backupCfg != {}) (
      cfg.backupCfg
      // {
        sourceDirectories = [
          "${config.services.home-assistant.configDir}/backups"
        ];

        # No need for backup hooks as we use an hourly automation job in home assistant directly with a cron job.
      }
    );

    # Adds the "backup" user to the "hass" group.
    users.groups.hass = {
      members = [ "backup" ];
    };

    # This allows the "backup" user, member of the "backup" group, to access what's inside the home
    # folder, which is needed for accessing the "backups" folder. It allows to read (r), enter the
    # directory (x) but not modify what's inside.
    users.users.hass.homeMode = "0750";

    systemd.services.home-assistant.serviceConfig = {
      # This allows all members of the "hass" group to read files, list directories and enter
      # directories created by the home-assistant service. This is needed for the "backup" user,
      # member of the "hass" group, to backup what is inside the "backup/" folder.
      UMask = lib.mkForce "0027";
    };
  };
}
