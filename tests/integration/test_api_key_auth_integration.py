"""
Integration tests for the API-key auth middleware.

End-to-end scenarios:

* With ``settings.apiKeys`` unset, requests to protected routes are
  not challenged (pass-through middleware).
* With keys configured, missing header -> 401 with WWW-Authenticate.
* Wrong key -> 401.
* Correct key -> request proceeds (here we use a stub route to avoid
  hitting the full orchestrator).
* Public paths (/api/health, /api/model/status, /api/history*) are
  never gated regardless of key configuration.
* Constant-time comparison via sha256 digests is exercised end to end.
* ``addApiKeyAuth`` returns ``True`` when keys are configured and
  ``False`` otherwise.

Each test sets / unsets ``API_KEYS`` in ``os.environ`` and clears
the ``getSettings`` LRU-cache so the fresh value reaches the auth
module at registration time.
"""

from __future__ import annotations

import os

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from backend.api.auth import (
    HEADER_API_KEY,
    WWW_AUTH_HEADER,
    addApiKeyAuth,
)


# ---------------------------------------------------------------------------
# Test app factory
# ---------------------------------------------------------------------------
def _buildApp(apiKeysConfig: str | None) -> tuple[TestClient, FastAPI]:
    """Build a fresh ``FastAPI`` app with all the relevant middleware
    but stub routes.  Returns ``(TestClient, app)``.
    """
    app = FastAPI()

    @app.get("/api/health")
    async def health():
        return {"status": "ok"}

    @app.get("/api/model/status")
    async def modelStatus():
        return {"loaded": True}

    @app.get("/api/history")
    async def history():
        return {"items": []}

    @app.post("/api/analyze")
    async def analyzeStub(request: Request):
        # Echo back the API key we saw so the test can verify it
        # reached the handler.
        return {"got_key": request.headers.get(HEADER_API_KEY, "")}

    @app.post("/api/analyze/url")
    async def analyzeUrlStub(request: Request):
        return {"got_key": request.headers.get(HEADER_API_KEY, "")}

    @app.post("/api/analyze/email")
    async def analyzeEmailStub(request: Request):
        return {"got_key": request.headers.get(HEADER_API_KEY, "")}

    # Patch the global env (config is loaded by ``getSettings`` cache).
    # pydantic-settings reads ``apiKeys`` -> env var ``APIKEYS`` (no
    # underscore: the field name is converted verbatim).
    oldVal = os.environ.get("APIKEYS")
    if apiKeysConfig is None:
        os.environ.pop("APIKEYS", None)
    else:
        os.environ["APIKEYS"] = apiKeysConfig
    # Reset the cached settings so the new env is reflected.
    import backend.config as cfg

    cfg.getSettings.cache_clear()
    try:
        addApiKeyAuth(app)
        client = TestClient(app)
        return client, app
    finally:
        # Restore env
        if oldVal is None:
            os.environ.pop("APIKEYS", None)
        else:
            os.environ["APIKEYS"] = oldVal
        cfg.getSettings.cache_clear()


# ---------------------------------------------------------------------------
# auth disabled (default public-demo posture)
# ---------------------------------------------------------------------------
def test_auth_disabled_when_no_keys_configured():
    client, _ = _buildApp(apiKeysConfig=None)
    # No X-Api-Key header -> 200 (auth is off)
    response = client.post(
        "/api/analyze", json={}
    )
    assert response.status_code == 200, (
        "no keys configured -> auth disabled -> request passes"
    )


def test_auth_disabled_returnsFalseFromRegister():
    """``addApiKeyAuth`` returns ``False`` when keys are not configured."""
    app = FastAPI()

    @app.post("/api/analyze")
    async def stub():
        return {}

    result = addApiKeyAuth(app)
    assert result is False


# ---------------------------------------------------------------------------
# auth required (one key configured)
# ---------------------------------------------------------------------------
SECRET = "test-secret-key-do-not-use-in-prod"


def test_auth_enabled_missing_header_returns401():
    client, _ = _buildApp(apiKeysConfig=SECRET)
    response = client.post("/api/analyze", json={})
    assert response.status_code == 401
    assert response.headers[WWW_AUTH_HEADER] == "ApiKey"
    assert response.json()["detail"] == "Missing X-Api-Key header"


def test_auth_enabled_wrong_key_returns401():
    client, _ = _buildApp(apiKeysConfig=SECRET)
    response = client.post(
        "/api/analyze", json={}, headers={HEADER_API_KEY: "obviously-wrong"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid X-Api-Key"


def test_auth_enabled_correct_key_passesThrough():
    client, _ = _buildApp(apiKeysConfig=SECRET)
    response = client.post(
        "/api/analyze", json={}, headers={HEADER_API_KEY: SECRET}
    )
    assert response.status_code == 200
    assert response.json()["got_key"] == SECRET


def test_auth_enabled_returnsTrueFromRegister():
    """``addApiKeyAuth`` returns ``True`` when keys are configured."""
    oldVal = os.environ.get("APIKEYS")
    os.environ["APIKEYS"] = SECRET
    import backend.config as cfg

    cfg.getSettings.cache_clear()
    try:
        fresh = FastAPI()

        @fresh.post("/api/analyze")
        async def stub():
            return {}

        result = addApiKeyAuth(fresh)
        assert result is True
    finally:
        if oldVal is None:
            os.environ.pop("APIKEYS", None)
        else:
            os.environ["APIKEYS"] = oldVal
        cfg.getSettings.cache_clear()


# ---------------------------------------------------------------------------
# Multiple keys
# ---------------------------------------------------------------------------
def test_auth_multiKey_acceptsAnyValidKey():
    """Multiple comma-separated keys -> any matches."""
    client, _ = _buildApp(apiKeysConfig="alpha,beta,gamma")
    for key in ["alpha", "beta", "gamma"]:
        response = client.post(
            "/api/analyze", json={}, headers={HEADER_API_KEY: key}
        )
        assert response.status_code == 200, (
            f"key {key!r} should be accepted: got {response.status_code} "
            f"{response.json()!r}"
        )


def test_auth_multiKey_rejectsUnlistedKey():
    client, _ = _buildApp(apiKeysConfig="alpha,beta,gamma")
    response = client.post(
        "/api/analyze", json={}, headers={HEADER_API_KEY: "delta"}
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Public paths remain public
# ---------------------------------------------------------------------------
def test_healthRoute_alwaysPublic_evenWhenKeysAreConfigured():
    client, _ = _buildApp(apiKeysConfig=SECRET)
    response = client.get("/api/health")
    assert response.status_code == 200, (
        "/api/health must never require auth"
    )


def test_modelStatusRoute_alwaysPublic_evenWhenKeysAreConfigured():
    client, _ = _buildApp(apiKeysConfig=SECRET)
    response = client.get("/api/model/status")
    assert response.status_code == 200, (
        "/api/model/status must never require auth"
    )


def test_historyRoute_alwaysPublic_evenWhenKeysAreConfigured():
    client, _ = _buildApp(apiKeysConfig=SECRET)
    response = client.get("/api/history")
    assert response.status_code == 200, (
        "/api/history must never require auth"
    )


# ---------------------------------------------------------------------------
# All analyze variants are protected
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "route", ["/api/analyze", "/api/analyze/url", "/api/analyze/email"]
)
def test_allAnalyzeVariants_requireKey(route):
    client, _ = _buildApp(apiKeysConfig=SECRET)
    response = client.post(route, json={})
    assert response.status_code == 401, (
        f"{route} must require auth when keys are configured"
    )
    assert response.headers[WWW_AUTH_HEADER] == "ApiKey"


# ---------------------------------------------------------------------------
# Whitespace around the configured key is tolerated
# ---------------------------------------------------------------------------
def test_auth_strippedWhitespaceOnKeyHeader():
    """Trimmed whitespace around the supplied key still matches."""
    client, _ = _buildApp(apiKeysConfig=SECRET)
    response = client.post(
        "/api/analyze",
        json={},
        headers={HEADER_API_KEY: f"  {SECRET}  "},
    )
    # We strip the incoming header so whitespace is OK.
    assert response.status_code == 200, (
        "leading/trailing whitespace on key header must be ignored"
    )


# ---------------------------------------------------------------------------
# Order of middleware: auth fires before rate-limit
# ---------------------------------------------------------------------------
def test_authShortCircuitsBeforeRouteHandlerExecutes():
    """Server must respond with 401 and never enter the stub."""
    client, _ = _buildApp(apiKeysConfig=SECRET)
    # Spy: stub's ``got_key`` would carry the bad key.  We assert
    # that we get 401 -> we did not pass through.
    response = client.post("/api/analyze", json={})
    assert response.status_code == 401
    # Confirm body matches the unauthorized JSON shape, not the stub.
    assert response.json() != {"got_key": ""}
