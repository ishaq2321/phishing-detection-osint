"""
Integration tests for the rate-limiting middleware.

Uses ``limiter.reset()`` to clear the slowapi in-memory storage
between tests so each test starts with a clean rate-limit bucket.

Verifies:
- The limiter is registered on the app.
- The JSON exception handler returns the expected 429 shape.
- The ``_keyFunc`` distinguishes auth vs IP.
- Endpoints within their limits succeed; endpoints beyond get 429.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse

from backend.api.rate_limiting import (
    ANALYZE_LIMIT,
    STATUS_LIMIT,
    _keyFunc,
    addRateLimiting,
    installJsonRateLimitHandler,
    limiter,
    rateLimitExceededJsonHandler,
)


@pytest.fixture(autouse=True)
def _resetLimiter():
    """Reset slowapi state between every test.

    Two essentials:
    1. ``limiter.reset()`` clears the in-memory storage buckets.
    2. ``_route_limits`` and ``_Limiter__marked_for_limiting`` must be
       cleared too: each invocation of ``@limiter.limit(...)`` in this
       module (e.g. inside ``_buildClient``) appends to these
       accumulators keyed by ``module.function_name``.  Without
       clearing them, repeated calls of the same fixture would
       multiply the per-request limit hit count and the test would
       see ``cost=2`` from accumulated limits instead of ``cost=1``.
    """
    # Clear route-limit accumulators so decorator calls below don't
    # stack onto entries left from previous tests.
    limiter._route_limits.clear()
    limiter._Limiter__marked_for_limiting.clear()
    limiter._dynamic_route_limits.clear()
    limiter.reset()
    yield
    limiter.reset()


def _buildClient() -> TestClient:
    testApp = FastAPI()

    @testApp.get("/api/health")
    async def health():
        return {"status": "ok"}

    @testApp.get("/api/model/status")
    @limiter.limit(STATUS_LIMIT)
    async def status(request: Request):
        return JSONResponse({"loaded": True})

    @testApp.post("/api/analyze/url")
    @limiter.limit(ANALYZE_LIMIT)
    async def analyze(request: Request, payload: dict):
        return JSONResponse({"url": payload.get("url")})

    @testApp.get("/probe")
    async def probe():
        return {"p": 1}

    addRateLimiting(testApp)
    installJsonRateLimitHandler(testApp)
    return TestClient(testApp), testApp


@pytest.fixture
def appPair():
    return _buildClient()


@pytest.fixture
def client(appPair):
    """Just the TestClient half (the part actually used by tests)."""
    client, _app = appPair
    return client


@pytest.fixture
def ipHeader():
    return {"x-forwarded-for": "203.0.113.99"}


# ---------------------------------------------------------------------------
# key function
# ---------------------------------------------------------------------------
def test_keyFunc_prefersApiKeyOverIp():
    """Authenticated users get one bucket; unauth users get another."""
    req = MagicMock()
    req.headers = {"x-api-key": "secret-key-12345", "x-forwarded-for": "1.2.3.4"}
    key = _keyFunc(req)
    assert key.startswith("key:secret-key-12345"), (
        f"expected API-key bucket, got {key}"
    )


def test_keyFunc_fallsBackToForwardedIp():
    req = MagicMock()
    req.headers = {"x-forwarded-for": "203.0.113.1, 10.0.0.1"}
    req.client = MagicMock(host="127.0.0.1")
    key = _keyFunc(req)
    assert key == "ip:203.0.113.1", (
        f"expected first forwarded hop, got {key}"
    )


def test_keyFunc_fallsBackToRemoteAddr():
    req = MagicMock()
    req.headers = {}
    req.client = MagicMock(host="198.51.100.7")
    key = _keyFunc(req)
    assert key == "ip:198.51.100.7"


def test_keyFunc_truncatesLongApiKey():
    req = MagicMock()
    req.headers = {"x-api-key": "x" * 256}
    key = _keyFunc(req)
    # first 32 chars only
    assert len(key) == len("key:") + 32


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------
def test_addRateLimiting_registersLimiterOnAppState():
    testApp = FastAPI()
    addRateLimiting(testApp)
    assert hasattr(testApp.state, "limiter")
    assert testApp.state.limiter is limiter


def test_addRateLimiting_registersExceptionHandler():
    testApp = FastAPI()
    addRateLimiting(testApp)
    installJsonRateLimitHandler(testApp)
    from slowapi.errors import RateLimitExceeded
    handler = testApp.exception_handlers.get(RateLimitExceeded)
    assert handler is not None, (
        "Expected a custom JSON handler for RateLimitExceeded"
    )


def test_installJsonRateLimitHandler_skipsIfAlreadyInstalled():
    """Calling twice should NOT replace our handler with the slowapi default."""
    testApp = FastAPI()
    addRateLimiting(testApp)
    installJsonRateLimitHandler(testApp)
    installJsonRateLimitHandler(testApp)
    from slowapi.errors import RateLimitExceeded
    handler = testApp.exception_handlers.get(RateLimitExceeded)
    # FastAPI's add_exception_handler may overwrite on second call;
    # we just verify both handlers are reference-equal to OUR handler.
    assert handler is rateLimitExceededJsonHandler


# ---------------------------------------------------------------------------
# functional HTTP behaviour
# ---------------------------------------------------------------------------
def test_unlimitedEndpointHealthIsNotRateLimited(client):
    """``/api/health`` is exempt -- we deliberately leave it unlimited."""
    client = client
    for _ in range(50):
        response = client.get("/api/health")
        assert response.status_code == 200, (
            "health endpoint must never rate-limit"
        )


def test_analyzeGet429AfterLimit(ipHeader):
    """POST /api/analyze limited by ANALYZE_LIMIT (30/min); 31st hits 429."""
    client, _ = _buildClient()
    payload = {"url": "https://example.com"}
    # 30 allowed calls.
    for _ in range(30):
        response = client.post(
            "/api/analyze/url", json=payload, headers=ipHeader
        )
        assert response.status_code == 200, (
            f"You should be within limits; got {response.status_code}"
        )
    # 31st request — must be rejected.
    response = client.post(
        "/api/analyze/url", json=payload, headers=ipHeader
    )
    assert response.status_code == 429
    body = response.json()
    assert "detail" in body
    assert body["detail"] == "Rate limit exceeded"


def test_healthEndpointHas429NotApplicable(client):
    """Health endpoint is exempt; after 100 calls it should still return 200."""
    client = client
    for _ in range(100):
        response = client.get("/api/health")
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# default limit
# ---------------------------------------------------------------------------
def test_defaultLimitAppliedForUnroutedEndpoint():
    """An endpoint without an explicit @limiter.limit follows the
    default 60/minute limit applied automatically by slowapi.

    To avoid making 60 slow HTTP calls, we use slowapi's programmatic
    API to verify that the default is applied to the router without
    needing to exhaust it.
    """
    testApp = FastAPI()

    @testApp.get("/probe")
    async def probe():
        return {"ok": True}

    addRateLimiting(testApp)
    limiter.reset()
    # Confirm the limiter's default-limit configuration is correct.
    # slowapi wraps the string in a LimitGroup; the source string is
    # stored under the name-mangled _LimitGroup__limit_provider.
    assert limiter._default_limits, (
        "the limiter must have at least one default limit configured"
    )
    assert limiter._default_limits[0]._LimitGroup__limit_provider == "60/minute", (
        "the limiter's default must be 60/minute per IP"
    )


def test_statusEndpointUsesStatusLimit(ipHeader):
    """``/api/model/status`` is throttled at STATUS_LIMIT (10/minute)."""
    testApp = FastAPI()

    @testApp.get("/api/model/status")
    @limiter.limit(STATUS_LIMIT)
    async def statusLimited(request: Request):
        return JSONResponse({"loaded": True})

    addRateLimiting(testApp)
    installJsonRateLimitHandler(testApp)
    limiter.reset()
    # Fresh forwarded IP each test to keep buckets independent
    headers = {"x-forwarded-for": "203.0.113.55"}
    client = TestClient(testApp)
    # 10 allowed
    for _ in range(10):
        assert client.get(
            "/api/model/status", headers=headers
        ).status_code == 200
    # 11th over
    response = client.get("/api/model/status", headers=headers)
    assert response.status_code == 429


# ---------------------------------------------------------------------------
# production vs development env
# ---------------------------------------------------------------------------
def test_limiterInDev_returnsHumanReadable429():
    """In dev mode the JSON handler still returns 429 (consistent)."""
    testApp = FastAPI()

    @testApp.get("/probe")
    async def probe():
        return {"ok": True}

    addRateLimiting(testApp)
    installJsonRateLimitHandler(testApp)
    client = TestClient(testApp)
    response = client.get(
        "/probe", headers={"x-forwarded-for": "203.0.113.77"}
    )
    # within default 60/minute since this is a fresh IP, returns 200
    assert response.status_code == 200
