"""Header-only Cloudflare Access authentication for the Hermes dashboard.

The Access assertion is the only identity input. Cookies and bearer tokens are
never accepted as a fallback once this provider is active.
"""
from __future__ import annotations

import logging
import os
from typing import Mapping, Optional
from urllib.parse import urlparse

from hermes_cli.dashboard_auth import (
    DashboardAuthProvider,
    LoginStart,
    ProviderError,
    RefreshExpiredError,
    Session,
)

logger = logging.getLogger(__name__)

_HEADER = "cf-access-jwt-assertion"
_LEGACY_ENABLED_ENV = "HERMES_CLOUDFLARE_ACCESS_DIRECT"
_LEGACY_TEAM_DOMAIN_ENV = "HERMES_CLOUDFLARE_ACCESS_TEAM_DOMAIN"
_LEGACY_AUDIENCE_ENV = "HERMES_CLOUDFLARE_ACCESS_AUD"
LAST_SKIP_REASON = ""


def _normalise_team_domain(value: str) -> str:
    parsed = urlparse(value.strip().rstrip("/"))
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path not in ("", "/")
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ValueError("team_domain must be an HTTPS origin")
    return f"https://{parsed.netloc}"


def _normalise_public_origin(value: str) -> tuple[str, str]:
    parsed = urlparse(value.strip().rstrip("/"))
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path not in ("", "/")
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ValueError("public_origin must be an HTTPS origin")
    return f"https://{parsed.netloc}", parsed.netloc.lower()


class CloudflareAccessProvider(DashboardAuthProvider):
    name = "cloudflare-access"
    display_name = "Cloudflare Access"
    supports_session = False
    supports_request_identity = True

    def __init__(self, *, team_domain: str, audience: str, public_origin: str) -> None:
        import jwt

        self._jwt = jwt
        self._team_domain = _normalise_team_domain(team_domain)
        self._audience = audience.strip()
        if not self._audience:
            raise ValueError("audience is required")
        self.request_identity_origin, self.request_identity_host = _normalise_public_origin(
            public_origin
        )
        certs_url = f"{self._team_domain}/cdn-cgi/access/certs"
        self._jwks_client = jwt.PyJWKClient(
            certs_url,
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
                audience=self._audience,
                issuer=self._team_domain,
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
        # Never retain or expose the Access JWT: every HTTP request is rechecked.
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


class _UnavailableCloudflareAccessProvider(CloudflareAccessProvider):
    """Fail closed when direct mode was explicitly enabled but is malformed."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        self.request_identity_origin = ""
        self.request_identity_host = ""

    def verify_request_identity(self, *, headers: Mapping[str, str]) -> Optional[Session]:
        raise ProviderError(self.reason)


def _setting(ctx, key: str, legacy_env: str = ""):
    configured = ctx.get_config(key, None)
    if configured is not None:
        return configured
    return os.environ.get(legacy_env, "") if legacy_env else None


def _enabled(ctx) -> bool:
    configured = ctx.get_config("enabled", None)
    if configured is not None:
        return configured is True or (
            isinstance(configured, str) and configured.strip().lower() in {"1", "true", "yes"}
        )
    return os.environ.get(_LEGACY_ENABLED_ENV, "").strip() == "1"


def register(ctx) -> None:
    """Register only after explicit configuration; malformed direct mode is closed."""
    global LAST_SKIP_REASON
    LAST_SKIP_REASON = ""
    if not _enabled(ctx):
        LAST_SKIP_REASON = "direct Cloudflare Access mode is disabled"
        return
    try:
        provider = CloudflareAccessProvider(
            team_domain=str(_setting(ctx, "team_domain", _LEGACY_TEAM_DOMAIN_ENV) or ""),
            audience=str(_setting(ctx, "audience", _LEGACY_AUDIENCE_ENV) or ""),
            public_origin=str(_setting(ctx, "public_origin") or ""),
        )
    except (ImportError, ValueError, ProviderError) as exc:
        LAST_SKIP_REASON = f"Cloudflare Access provider was not configured: {exc}"
        logger.warning("dashboard-auth-cloudflare-access: %s", LAST_SKIP_REASON)
        ctx.register_dashboard_auth_provider(_UnavailableCloudflareAccessProvider(LAST_SKIP_REASON))
        return
    ctx.register_dashboard_auth_provider(provider)
