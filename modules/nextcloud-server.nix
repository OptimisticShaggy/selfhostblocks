{ config, pkgs, lib, ... }:

let
  cfg = config.shb.nextcloud;

  fqdn = "${cfg.subdomain}.${cfg.domain}";
in
{
  options.shb.nextcloud = {
    enable = lib.mkEnableOption "selfhostblocks.nextcloud-server";

    subdomain = lib.mkOption {
      type = lib.types.str;
      description = "Subdomain under which home-assistant will be served.";
      example = "nextcloud";
    };

    domain = lib.mkOption {
      description = lib.mdDoc "Domain to serve sites under.";
      type = lib.types.str;
      example = "domain.com";
    };

    sopsFile = lib.mkOption {
      type = lib.types.path;
      description = "Sops file location";
      example = "secrets/nextcloud.yaml";
    };
  };

  config = lib.mkIf cfg.enable {
    users.users = {
      nextcloud = {
        name = "nextcloud";
        group = "nextcloud";
        isSystemUser = true;
      };
    };

    users.groups = {
      nextcloud = {
        members = [ "backup" ];
      };
    };

    # LDAP is manually configured through
    # https://github.com/lldap/lldap/blob/main/example_configs/nextcloud.md, see also
    # https://docs.nextcloud.com/server/latest/admin_manual/configuration_user/user_auth_ldap.html
    services.nextcloud = {
      enable = true;
      package = pkgs.nextcloud26;

      # Enable php-fpm and nginx which will be behind the shb haproxy instance.
      hostName = fqdn;

      config = {
        dbtype = "pgsql";
        adminuser = "root";
        adminpassFile = "/run/secrets/nextcloud/adminpass";
        # Not using dbpassFile as we're using socket authentication.
        defaultPhoneRegion = "US";
        trustedProxies = [ "127.0.0.1" ];
      };
      database.createLocally = true;

      # Enable caching using redis https://nixos.wiki/wiki/Nextcloud#Caching.
      configureRedis = true;
      caching.apcu = false;
      # https://docs.nextcloud.com/server/26/admin_manual/configuration_server/caching_configuration.html
      caching.redis = true;

      # Adds appropriate nginx rewrite rules.
      webfinger = true;

      extraOptions = {
        "overwrite.cli.url" = "https://" + fqdn;
        "overwritehost" = fqdn;
        "overwriteprotocol" = "https"; # Needed at least for oidc redirect_url to work, see https://github.com/nextcloud/user_oidc/issues/323
        "overwritecondaddr" = ""; # We need to set it to empty otherwise overwriteprotocol does not work.

        # Config for Authelia from https://www.authelia.com/integration/openid-connect/nextcloud/
        "allow_user_to_change_display_name" = "false";
        "lost_password_link" = "disabled";
        "oidc_login_provider_url" = "https://authelia.${cfg.domain}";
        "oidc_login_client_id" = "nextcloud";
        "oidc_login_client_secret" = "02e8d63ac076b45f08be778c2be2be1e6498dd69860230e6b9ad9b874f2519446e1ec0d981b41ae68f311f5a3ca9529f66d9bdbd52d4f171e86569471ec2c440";
        "oidc_login_auto_redirect" = "false";
        "oidc_login_end_session_redirect" = "false";
        "oidc_login_button_text" = "Log in with Authelia";
        "oidc_login_hide_password_form" = "false";
        "oidc_login_use_id_token" = "true";
        "oidc_login_attributes" = {
          "id" = "preferred_username";
          "name" = "name";
          "mail" = "email";
          "groups" = "groups";
        };
        "oidc_login_default_group" = "oidc";
        "oidc_login_allowed_groups" = ["nextcloud_user"];
        "oidc_login_use_external_storage" = "false";
        "oidc_login_scope" = "openid profile email groups";
        "oidc_login_proxy_ldap" = "true";
        "oidc_login_disable_registration" = "true";
        "oidc_login_redir_fallback" = "false";
        "oidc_login_alt_login_page" = "assets/login.php";
        "oidc_login_tls_verify" = "true";
        "oidc_create_groups" = "true";
        "oidc_login_webdav_enabled" = "false";
        "oidc_login_password_authentication" = "false";
        "oidc_login_public_key_caching_time" = 86400;
        "oidc_login_min_time_between_jwks_requests" = 10;
        "oidc_login_well_known_caching_time" = 86400;
        "oidc_login_update_avatar" = "false";
      };

      phpOptions = {
        # The OPcache interned strings buffer is nearly full with 8, bump to 16.
        catch_workers_output = "yes";
        display_errors = "stderr";
        error_reporting = "E_ALL & ~E_DEPRECATED & ~E_STRICT";
        expose_php = "Off";
        "opcache.enable_cli" = "1";
        "opcache.fast_shutdown" = "1";
        "opcache.interned_strings_buffer" = "16";
        "opcache.max_accelerated_files" = "10000";
        "opcache.memory_consumption" = "128";
        "opcache.revalidate_freq" = "1";
        "openssl.cafile" = "/etc/ssl/certs/ca-certificates.crt";
        short_open_tag = "Off";

        # Needed to avoid corruption per https://docs.nextcloud.com/server/21/admin_manual/configuration_server/caching_configuration.html#id2
        "redis.session.locking_enabled" = "1";
        "redis.session.lock_retries" = "-1";
        "redis.session.lock_wait_time" = "10000";
      };
    };

    # Secret needed for services.nextcloud.config.adminpassFile.
    sops.secrets."nextcloud/adminpass" = {
      inherit (cfg) sopsFile;
      mode = "0440";
      owner = "nextcloud";
      group = "nextcloud";
    };

    services.nginx.virtualHosts.${fqdn} = {
      # listen = [ { addr = "0.0.0.0"; port = 443; } ];
      sslCertificate = "/var/lib/acme/${cfg.domain}/cert.pem";
      sslCertificateKey = "/var/lib/acme/${cfg.domain}/key.pem";
      forceSSL = true;
    };

    systemd.services.phpfpm-nextcloud.serviceConfig = {
      # Setup permissions needed for backups, as the backup user is member of the jellyfin group.
      UMask = lib.mkForce "0027";
    };

    # Sets up backup for Nextcloud.
    shb.backup.instances.nextcloud = {
      sourceDirectories = [
        config.services.nextcloud.datadir
      ];
      excludePatterns = [".rnd"];
    };

    shb.authelia.oidcClients = [
      {
        id = "nextcloud";
        description = "NextCloud";
        secret = "02e8d63ac076b45f08be778c2be2be1e6498dd69860230e6b9ad9b874f2519446e1ec0d981b41ae68f311f5a3ca9529f66d9bdbd52d4f171e86569471ec2c440";
        public = "false";
        authorization_policy = "one_factor";
        redirect_uris = [ "https://${cfg.subdomain}.${cfg.domain}/apps/oidc_login/oidc" ];
        scopes = [
          "openid"
          "profile"
          "email"
          "groups"
        ];
        userinfo_signing_algorithm = "none";
      }
    ];
  };
}
