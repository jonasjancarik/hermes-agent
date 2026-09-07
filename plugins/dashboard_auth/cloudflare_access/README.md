# Cloudflare Access dashboard authentication

This is a personal-fork integration. It verifies Cloudflare Access assertions
on every protected dashboard request and never treats a dashboard cookie or
bearer token as an alternative identity.

Configure its behavioural settings in `~/.hermes/config.yaml` before starting
the dashboard. The plugin key is `dashboard_auth/cloudflare_access`:

```yaml
plugins:
  entries:
    dashboard_auth/cloudflare_access:
      settings:
        enabled: true
        team_domain: https://example.cloudflareaccess.com
        audience: replace-with-your-access-application-audience
        public_origin: https://dashboard.example.com
```

`public_origin` is checked exactly for browser write requests and its host is
required on every authenticated request. Values must be HTTPS origins without a
path.

For a direct-only deployment, also set
`HERMES_CLOUDFLARE_ACCESS_DIRECT=1`. This temporary fail-closed sentinel keeps
the dashboard unavailable if the provider cannot load before it registers. A
configuration error after the plugin loads likewise returns 503 for protected
requests. `HERMES_CLOUDFLARE_ACCESS_TEAM_DOMAIN` and
`HERMES_CLOUDFLARE_ACCESS_AUD` remain supported only when the corresponding
`config.yaml` value is absent. A follow-up should move the remaining
direct-mode sentinel from the generic middleware into the plugin configuration
contract.

An upstream contribution should keep the generic request-identity and logout
mechanisms separate from this vendor-specific standalone plugin.
