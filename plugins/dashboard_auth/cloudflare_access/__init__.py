"""Direct Cloudflare Access assertion authentication for the dashboard."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Mapping, Optional
from urllib.parse import urlsplit

from hermes_cli.dashboard_auth import (
    DashboardAuthProvider,
    LoginStart,
    ProviderError,
    RefreshExpiredError,
    Session,
)

logger = logging.getLogger(__name__)
_HEADER = "cf-access-jwt-assertion"
LAST_SKIP_REASON = ""


@dataclass(frozen=True)
class CloudflareAccessSettings:
    team_domain: str
    audience: str
    dashboard_origin: str
    dashboard_host: str


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required when direct Cloudflare Access mode is enabled")
    return value


def _team_domain(raw: str) -> str:
    parsed = urlsplit(raw.rstrip("/"))
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "HERMES_CLOUDFLARE_ACCESS_TEAM_DOMAIN must be an HTTPS Cloudflare Access team URL"
        )
    host = parsed.hostname.lower()
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return f"https://{host}"


def _dashboard_target(raw: str) -> tuple[str, str]:
    parsed = urlsplit(raw.rstrip("/"))
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "HERMES_DASHBOARD_PUBLIC_URL must be an HTTPS dashboard URL without credentials, query, or fragment"
        )
    host = parsed.hostname.lower()
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return f"https://{host}", host


def _settings_from_env() -> CloudflareAccessSettings:
    team_domain = _team_domain(_required_env("HERMES_CLOUDFLARE_ACCESS_TEAM_DOMAIN"))
    audience = _required_env("HERMES_CLOUDFLARE_ACCESS_AUD")
    dashboard_origin, dashboard_host = _dashboard_target(
        _required_env("HERMES_DASHBOARD_PUBLIC_URL")
    )
    return CloudflareAccessSettings(team_domain, audience, dashboard_origin, dashboard_host)


class CloudflareAccessProvider(DashboardAuthProvider):
    """Verify the per-request assertion injected by Cloudflare Access.

    It intentionally does not recognise Hermes cookies or bearer tokens: an
    enabled direct provider is authoritative for the protected dashboard.
    """

    name = "cloudflare-access"
    display_name = "Cloudflare Access"
    supports_session = False
    supports_request_identity = True

    def __init__(self, settings: CloudflareAccessSettings) -> None:
        import jwt

        self._jwt = jwt
        self._settings = settings
        self._jwks_client = jwt.PyJWKClient(
            f"{settings.team_domain}/cdn-cgi/access/certs",
            cache_keys=False,
            cache_jwk_set=True,
            lifespan=300,
            timeout=5,
            headers={"Accept": "application/json", "User-Agent": "HermesAccess/1.0"},
        )

    def start_login(self, *, redirect_uri: str) -> LoginStart:
        raise ProviderError("Cloudflare Access uses the protected application route")

    def complete_login(
        self, *, code: str, state: str, code_verifier: str, redirect_uri: str
    ) -> Session:
        raise ProviderError("Cloudflare Access does not accept OAuth callbacks")

    def verify_session(self, *, access_token: str) -> Optional[Session]:
        return None

    def refresh_session(self, *, refresh_token: str) -> Session:
        raise RefreshExpiredError("Cloudflare Access assertion sessions do not refresh here")

    def revoke_session(self, *, refresh_token: str) -> None:
        return None

    def logout_redirect(self) -> Optional[str]:
        return "/cdn-cgi/access/logout"

    def request_identity_target(self) -> tuple[str, str]:
        return self._settings.dashboard_origin, self._settings.dashboard_host

    def verify_request_identity(self, *, headers: Mapping[str, str]) -> Optional[Session]:
        values = headers.getlist(_HEADER) if hasattr(headers, "getlist") else [headers.get(_HEADER, "")]
        if len(values) != 1:
            return None
        token = values[0].strip()
        if not token:
            return None
        jwt = self._jwt
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
        except jwt.PyJWKClientConnectionError as exc:
            raise ProviderError("Cloudflare Access signing keys are unavailable") from exc
        except (jwt.PyJWKClientError, jwt.InvalidTokenError):
            return None
        except Exception:
            return None
        try:
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._settings.audience,
                issuer=self._settings.team_domain,
                options={"require": ["aud", "email", "exp", "iat", "nbf", "iss", "sub", "type"]},
            )
        except jwt.InvalidTokenError:
            return None
        if claims.get("type") != "app":
            return None
        sub, email, exp = claims.get("sub"), claims.get("email"), claims.get("exp")
        if (
            not isinstance(sub, str)
            or not sub.strip()
            or not isinstance(email, str)
            or not email.strip()
            or not isinstance(exp, int)
        ):
            return None
        # Never retain or expose the Access JWT: every request is rechecked.
        return Session(
            user_id=sub,
            email=email,
            display_name=email,
            org_id="",
            provider=self.name,
            expires_at=exp,
            access_token="",
            refresh_token="",
        )


def register(ctx) -> None:
    """Register only when direct Access mode has a complete target configuration."""
    global LAST_SKIP_REASON
    LAST_SKIP_REASON = ""
    if os.environ.get("HERMES_CLOUDFLARE_ACCESS_DIRECT", "").strip() != "1":
        LAST_SKIP_REASON = "direct Cloudflare Access mode is disabled"
        return
    try:
        ctx.register_dashboard_auth_provider(CloudflareAccessProvider(_settings_from_env()))
    except (ImportError, ValueError, ProviderError) as exc:
        LAST_SKIP_REASON = f"Cloudflare Access provider was not configured: {exc}"
        logger.warning("dashboard-auth-cloudflare-access: %s", LAST_SKIP_REASON)
