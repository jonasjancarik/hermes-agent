"""End-to-end coverage for the bundled direct Cloudflare Access provider."""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.responses import Response
from starlette.requests import Request

from hermes_cli.dashboard_auth import clear_providers, get_provider
from hermes_cli.dashboard_auth.middleware import gated_auth_middleware
from hermes_cli.plugins import PluginManager


class _StaticKeys:
    def __init__(self, key):
        self.key = key

    def get_signing_key_from_jwt(self, _token):
        return SimpleNamespace(key=self.key)


def _request(path: str, headers: dict[str, str] | None = None, method: str = "GET") -> Request:
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


async def _ready(_request=None):
    return Response(status_code=204)


@pytest.fixture(autouse=True)
def _direct_access_environment(monkeypatch):
    clear_providers()
    for name in (
        "HERMES_CLOUDFLARE_ACCESS_DIRECT",
        "HERMES_CLOUDFLARE_ACCESS_TEAM_DOMAIN",
        "HERMES_CLOUDFLARE_ACCESS_AUD",
        "HERMES_DASHBOARD_PUBLIC_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    yield
    clear_providers()


def _enable_direct_plugin(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HERMES_CLOUDFLARE_ACCESS_DIRECT", "1")
    monkeypatch.setenv("HERMES_CLOUDFLARE_ACCESS_TEAM_DOMAIN", "https://team.example.com")
    monkeypatch.setenv("HERMES_CLOUDFLARE_ACCESS_AUD", "test-audience")
    monkeypatch.setenv("HERMES_DASHBOARD_PUBLIC_URL", "https://dashboard.example.com")
    monkeypatch.setenv("HERMES_BUNDLED_PLUGINS", str(Path(__file__).resolve().parents[2] / "plugins"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))

    # Use the real plugin discovery path with a temporary Hermes home. The
    # direct provider is bundled but still follows the normal enable allowlist.
    from hermes_cli.config import load_config, save_config

    config = load_config()
    config.setdefault("plugins", {})["enabled"] = ["dashboard_auth/cloudflare_access"]
    save_config(config)
    manager = PluginManager(scope_key=str(tmp_path / "hermes-home"))
    manager.discover_and_load()
    provider = get_provider("cloudflare-access")
    assert provider is not None, manager._plugins
    return provider


def _assertion(provider, key, **overrides) -> str:
    claims = {
        "aud": provider._settings.audience,
        "email": "member@example.com",
        "exp": 4_000_000_000,
        "iat": 1_700_000_000,
        "nbf": 1_700_000_000,
        "iss": provider._settings.team_domain,
        "type": "app",
        "sub": "test-user",
    }
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test"})


def test_discovery_registers_direct_provider_and_the_gate_requires_its_assertion(monkeypatch, tmp_path):
    provider = _enable_direct_plugin(monkeypatch, tmp_path)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    provider._jwks_client = _StaticKeys(key.public_key())
    token = _assertion(provider, key)

    async def verified(request):
        assert request.state.session.email == "member@example.com"
        assert request.state.session.access_token == ""
        return Response(status_code=204)

    accepted = _request("/api/auth/me", {"cf-access-jwt-assertion": token})
    assert asyncio.run(gated_auth_middleware(accepted, verified)).status_code == 204

    for invalid in (
        _assertion(provider, key, aud="other-audience"),
        _assertion(provider, key, iss="https://other.example.com"),
    ):
        denied = _request("/api/auth/me", {"cf-access-jwt-assertion": invalid})
        assert asyncio.run(gated_auth_middleware(denied, _ready)).status_code == 401

    # The direct mode is authoritative: stale cookies, bearer values, and the
    # outer token-auth marker cannot bypass a missing or invalid assertion.
    for headers in ({}, {"authorization": "Bearer stale"}, {"cf-access-jwt-assertion": "invalid"}):
        denied = _request("/api/auth/me", headers)
        denied.state.token_authenticated = True
        assert asyncio.run(gated_auth_middleware(denied, _ready)).status_code == 401


def test_direct_gate_binds_writes_and_host_to_the_configured_dashboard(monkeypatch, tmp_path):
    provider = _enable_direct_plugin(monkeypatch, tmp_path)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    provider._jwks_client = _StaticKeys(key.public_key())
    token = _assertion(provider, key)

    wrong_origin = _request(
        "/api/gateway/restart",
        {"cf-access-jwt-assertion": token, "origin": "https://other.example.com"},
        "POST",
    )
    assert asyncio.run(gated_auth_middleware(wrong_origin, _ready)).status_code == 403

    wrong_host = _request(
        "/api/auth/me", {"cf-access-jwt-assertion": token, "host": "other.example.com"}
    )
    assert asyncio.run(gated_auth_middleware(wrong_host, _ready)).status_code == 403

    same_origin = _request(
        "/api/gateway/restart",
        {"cf-access-jwt-assertion": token, "origin": "https://dashboard.example.com"},
        "POST",
    )
    assert asyncio.run(gated_auth_middleware(same_origin, _ready)).status_code == 204
