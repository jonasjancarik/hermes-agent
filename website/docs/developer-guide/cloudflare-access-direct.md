# Direct Cloudflare Access dashboard authentication

The bundled `cloudflare-access` dashboard provider can verify the Cloudflare Access assertion on every protected dashboard request. It does not accept Hermes cookies or bearer tokens, so an enabled direct provider remains authoritative for the dashboard.

Enable it only behind Cloudflare Access and set all four variables for the same dashboard:

```sh
HERMES_CLOUDFLARE_ACCESS_DIRECT=1
HERMES_CLOUDFLARE_ACCESS_TEAM_DOMAIN=https://team.example.com
HERMES_CLOUDFLARE_ACCESS_AUD=test-audience
HERMES_DASHBOARD_PUBLIC_URL=https://dashboard.example.com
```

`HERMES_CLOUDFLARE_ACCESS_TEAM_DOMAIN` is the Access team URL used for the issuer check and signing-key endpoint. `HERMES_CLOUDFLARE_ACCESS_AUD` must be the audience for the protected application. `HERMES_DASHBOARD_PUBLIC_URL` supplies the exact HTTPS origin and Host accepted for authenticated writes.

The provider fails closed when direct mode is enabled but any required value is missing or malformed. It accepts only the `Cf-Access-Jwt-Assertion` request header, verifies an RS256 signature against the team JWKS, and requires the configured issuer, audience, `type: app`, subject, email, and expiry claims. It does not retain the assertion after verification.

The dashboard signs out through a same-origin form POST rather than `fetch`. That permits Cloudflare Access to complete its logout redirect while the server still checks the configured Origin for the request.
