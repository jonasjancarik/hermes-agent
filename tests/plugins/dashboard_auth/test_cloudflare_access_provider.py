"""Behavioural coverage for the personal-fork Cloudflare Access provider."""
from __future__ import annotations

import asyncio
import types
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.responses import Response
from starlette.requests import Request

import hermes_cli.dashboard_auth.middleware as middleware
import hermes_cli.dashboard_auth.routes as routes
from hermes_cli.dashboard_auth.base import ProviderError, Session
from plugins.dashboard_auth import cloudflare_access

_TEAM_DOMAIN = "https://team.example.cloudflareaccess.com"
_AUDIENCE = "example-audience"
_PUBLIC_ORIGIN = "https://dashboard.example.com"


class StaticKeys:
    def __init__(self, key):
        self.key = key

    def get_signing_key_from_jwt(self, _token):
        return types.SimpleNamespace(key=self.key)


class OfflineKeys:
    def get_signing_key_from_jwt(self, _token):
        raise jwt.PyJWKClientConnectionError("offline")


def request(path, headers=None, method="GET"):
    app = FastAPI()
    app.state.auth_required = True
    all_headers = {"host": "dashboard.example.com", **(headers or {})}
    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [(key.lower().encode(), value.encode()) for key, value in all_headers.items()],
            "client": ("127.0.0.1", 1),
            "server": ("dashboard.example.com", 443),
            "scheme": "https",
            "app": app,
        }
    )


async def ready(_request=None):
    return Response(status_code=204)


@pytest.fixture
def provider():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    instance = cloudflare_access.CloudflareAccessProvider(
        team_domain=_TEAM_DOMAIN,
        audience=_AUDIENCE,
        public_origin=_PUBLIC_ORIGIN,
    )
    instance._jwks_client = StaticKeys(key.public_key())
    return instance, key


def mint_token(key, **overrides):
    claims = {
        "aud": _AUDIENCE,
        "email": "alice@example.com",
        "exp": 4_000_000_000,
        "iat": 1_700_000_000,
        "nbf": 1_700_000_000,
        "iss": _TEAM_DOMAIN,
        "type": "app",
        "sub": "user-123",
    }
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "offline"})


def test_valid_signed_assertion_maps_session_without_retaining_token(provider):
    instance, key = provider
    session = instance.verify_request_identity(headers={"cf-access-jwt-assertion": mint_token(key)})
    assert (session.user_id, session.email, session.provider) == (
        "user-123",
        "alice@example.com",
        "cloudflare-access",
    )
    assert (session.access_token, session.refresh_token) == ("", "")


def test_cookie_and_bearer_are_not_identity_inputs(provider):
    instance, _ = provider
    assert instance.verify_request_identity(
        headers={"cookie": "CF_Authorization=ignored", "authorization": "Bearer ignored"}
    ) is None


def test_rejects_duplicate_access_headers(provider):
    instance, key = provider
    headers = types.SimpleNamespace(getlist=lambda _name: [mint_token(key), mint_token(key)])
    assert instance.verify_request_identity(headers=headers) is None


def test_rejects_invalid_signature_algorithm_claims_and_identity(provider):
    instance, key = provider
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bad_signature = jwt.encode(
        {
            "aud": _AUDIENCE,
            "email": "alice@example.com",
            "exp": 4_000_000_000,
            "iat": 1_700_000_000,
            "nbf": 1_700_000_000,
            "iss": _TEAM_DOMAIN,
            "type": "app",
            "sub": "user-123",
        },
        other,
        algorithm="RS256",
    )
    bad_algorithm = jwt.encode(
        {
            "aud": _AUDIENCE,
            "email": "alice@example.com",
            "exp": 4_000_000_000,
            "iat": 1_700_000_000,
            "nbf": 1_700_000_000,
            "iss": _TEAM_DOMAIN,
            "type": "app",
            "sub": "user-123",
        },
        "wrong",
        algorithm="HS256",
    )
    rejected = [
        "not.a.jwt",
        bad_signature,
        bad_algorithm,
        mint_token(key, exp=1),
        mint_token(key, nbf=4_000_000_000),
        mint_token(key, iss="https://other.cloudflareaccess.com"),
        mint_token(key, aud="other"),
        mint_token(key, type="org"),
        mint_token(key, email=""),
        mint_token(key, sub=""),
    ]
    assert all(
        instance.verify_request_identity(headers={"cf-access-jwt-assertion": token}) is None
        for token in rejected
    )


def test_requires_every_verified_claim_and_distinguishes_jwks_outage(provider):
    instance, key = provider
    for missing in ("aud", "email", "exp", "iat", "nbf", "iss", "sub", "type"):
        claims = jwt.decode(mint_token(key), options={"verify_signature": False})
        del claims[missing]
        token = jwt.encode(claims, key, algorithm="RS256")
        assert instance.verify_request_identity(headers={"cf-access-jwt-assertion": token}) is None
    instance._jwks_client = OfflineKeys()
    with pytest.raises(ProviderError):
        instance.verify_request_identity(headers={"cf-access-jwt-assertion": mint_token(key)})


@pytest.fixture
def direct_provider(monkeypatch):
    session = Session(
        "user-123", "alice@example.com", "alice@example.com", "", "cloudflare-access", 4_000_000_000, "", ""
    )
    provider = types.SimpleNamespace(
        name="cloudflare-access",
        supports_request_identity=True,
        request_identity_origin=_PUBLIC_ORIGIN,
        request_identity_host="dashboard.example.com",
        verify_request_identity=lambda *, headers: session if headers.get("cf-access-jwt-assertion") == "valid" else None,
        logout_redirect=lambda: "/cdn-cgi/access/logout",
    )
    monkeypatch.setattr(middleware, "list_request_identity_providers", lambda: [provider])
    monkeypatch.setattr(routes, "list_request_identity_providers", lambda: [provider])
    return provider


def test_valid_header_sets_session_and_bad_header_never_falls_back(direct_provider, monkeypatch):
    async def next_handler(req):
        assert req.state.session.email == "alice@example.com"
        return Response(status_code=204)

    valid = middleware.gated_auth_middleware(
        request("/api/auth/me", {"cf-access-jwt-assertion": "valid"}), next_handler
    )
    assert asyncio.run(valid).status_code == 204
    monkeypatch.setattr(middleware, "read_session_cookies", lambda _request: pytest.fail("cookie fallback used"))
    for headers in ({}, {"authorization": "Bearer old"}, {"cf-access-jwt-assertion": "bad"}):
        response = asyncio.run(
            middleware.gated_auth_middleware(
                request("/api/auth/me", headers), lambda _request: pytest.fail("protected route passed")
            )
        )
        assert response.status_code == 401
        assert b"/cdn-cgi/access/logout" in response.body


def test_token_auth_seam_cannot_bypass_direct_access(direct_provider):
    for headers in ({}, {"cf-access-jwt-assertion": "bad"}):
        req = request("/api/auth/me", headers)
        req.state.token_authenticated = True
        response = asyncio.run(
            middleware.gated_auth_middleware(req, lambda _request: pytest.fail("bearer bypass used"))
        )
        assert response.status_code == 401


def test_legacy_direct_mode_fails_closed_if_provider_cannot_register(monkeypatch):
    monkeypatch.setattr(middleware, "list_request_identity_providers", lambda: [])
    monkeypatch.setenv("HERMES_CLOUDFLARE_ACCESS_DIRECT", "1")
    req = request("/api/auth/me")
    req.state.token_authenticated = True
    response = asyncio.run(
        middleware.gated_auth_middleware(req, lambda _request: pytest.fail("registration fallback used"))
    )
    assert response.status_code == 503


def test_public_status_and_ws_ticket_module_stay_available(direct_provider):
    response = asyncio.run(middleware.gated_auth_middleware(request("/api/status"), ready))
    assert response.status_code == 204
    import hermes_cli.dashboard_auth.ws_tickets as tickets

    assert callable(tickets.mint_ticket)
    assert callable(tickets.consume_ticket)


def test_ws_ticket_keeps_identity_is_single_use_and_expires(direct_provider):
    import hermes_cli.dashboard_auth.ws_tickets as tickets

    tickets._reset_for_tests()
    req = request("/api/auth/ws-ticket", {"cf-access-jwt-assertion": "valid"})
    asyncio.run(middleware.gated_auth_middleware(req, ready))
    minted = asyncio.run(routes.api_auth_ws_ticket(req))
    assert minted["ttl_seconds"] == 30
    assert tickets.consume_ticket(minted["ticket"])["user_id"] == "user-123"
    with pytest.raises(tickets.TicketInvalid):
        tickets.consume_ticket(minted["ticket"])
    with patch("hermes_cli.dashboard_auth.ws_tickets.time.time", return_value=100):
        expired = tickets.mint_ticket(user_id="user-123", provider="cloudflare-access")
    with patch("hermes_cli.dashboard_auth.ws_tickets.time.time", return_value=131):
        with pytest.raises(tickets.TicketInvalid):
            tickets.consume_ticket(expired)


def test_login_and_logout_use_access_without_local_login_loop(direct_provider):
    valid = request("/login", {"cf-access-jwt-assertion": "valid"})
    asyncio.run(middleware.gated_auth_middleware(valid, ready))
    assert asyncio.run(routes.login_page(valid)).headers["location"] == "/chat"
    assert asyncio.run(routes.login_page(request("/login"))).headers["location"] == "/cdn-cgi/access/logout"
    assert asyncio.run(routes.auth_logout(request("/auth/logout"))).headers["location"] == "/cdn-cgi/access/logout"


def test_auth_me_never_returns_a_token(direct_provider):
    req = request("/api/auth/me", {"cf-access-jwt-assertion": "valid"})
    asyncio.run(middleware.gated_auth_middleware(req, ready))
    payload = asyncio.run(routes.api_auth_me(req))
    assert "access_token" not in payload
    assert "refresh_token" not in payload


def test_direct_access_rejects_cross_origin_and_missing_origin_writes(direct_provider):
    for origin in ("https://evil.example", "null", ""):
        req = request(
            "/api/gateway/restart",
            {
                "cf-access-jwt-assertion": "valid",
                "authorization": "Bearer old-hermes-token",
                "origin": origin,
            },
            "POST",
        )
        response = asyncio.run(
            middleware.gated_auth_middleware(req, lambda _request: pytest.fail("cross-origin write passed"))
        )
        assert response.status_code == 403
    same_origin = request(
        "/api/gateway/restart",
        {"cf-access-jwt-assertion": "valid", "origin": _PUBLIC_ORIGIN},
        "POST",
    )
    assert asyncio.run(middleware.gated_auth_middleware(same_origin, ready)).status_code == 204


def test_cross_origin_logout_is_rejected_before_provider_logout(direct_provider, monkeypatch):
    for headers in ({"origin": "https://evil.example"}, {}):
        req = request("/auth/logout", headers, "POST")
        response = asyncio.run(
            middleware.gated_auth_middleware(req, lambda _request: pytest.fail("logout CSRF passed"))
        )
        assert response.status_code == 403

    # A failed direct-provider configuration uses an empty expected origin;
    # it must not turn a missing Origin into an allowed logout POST.
    unavailable = types.SimpleNamespace(request_identity_origin="")
    monkeypatch.setattr(middleware, "list_request_identity_providers", lambda: [unavailable])
    response = asyncio.run(
        middleware.gated_auth_middleware(
            request("/auth/logout", method="POST"), lambda _request: pytest.fail("logout CSRF passed")
        )
    )
    assert response.status_code == 403


def test_direct_session_requires_the_public_host(direct_provider):
    req = request(
        "/api/auth/me", {"cf-access-jwt-assertion": "valid", "host": "evil.example"}
    )
    response = asyncio.run(
        middleware.gated_auth_middleware(req, lambda _request: pytest.fail("wrong host passed"))
    )
    assert response.status_code == 403
