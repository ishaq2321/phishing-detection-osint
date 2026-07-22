"""
Integration tests for the request-id middleware end-to-end behaviour.

Customers

* When a client does not send an X-Request-ID header, the response
  carries a server-generated 12-char hex id.
* When a client sends an X-Request-ID header, that exact value is
  echoed back on the response.
* Inside the route, ``request.state.request_id`` is set to the id.
* The id is preserved when other middleware (security headers,
  rate limiting) is registered before the request-id middleware.
"""

from __future__ import annotations

import re

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from backend.api.rate_limiting import addRateLimiting, installJsonRateLimitHandler
from backend.api.security_headers import addSecurityHeaders
from backend.logging_config import (
    HEADER_REQUEST_ID,
    addRequestIdMiddleware,
)

_HEX12 = re.compile(r"^[0-9a-f]{12}$")


def _buildApp() -> FastAPI:
    """Build a fresh app with the request-id middleware and a probe route."""
    app = FastAPI()

    @app.get("/probe")
    async def probe(request: Request):
        return {"request_id": getattr(request.state, "request_id", None)}

    @app.get("/api/health")
    async def health(request: Request):
        return {"ok": True, "request_id": getattr(request.state, "request_id", None)}

    return app


# ---------------------------------------------------------------------------
# Header round-trip
# ---------------------------------------------------------------------------
def test_requestIdHeader_generatedWhenAbsent():
    """No client header --> server generates 12-char hex id."""
    app = _buildApp()
    addRequestIdMiddleware(app)
    client = TestClient(app)
    response = client.get("/probe")
    rid = response.headers.get(HEADER_REQUEST_ID)
    assert rid is not None
    assert _HEX12.match(rid), (
        f"server-generated id must be 12 hex chars, got {rid!r}"
    )


def test_requestIdHeader_echoedWhenSupplied():
    """Client header --> exact value echoed back."""
    app = _buildApp()
    addRequestIdMiddleware(app)
    client = TestClient(app)
    supplied = "operator-supplied-trace-id"
    response = client.get("/probe", headers={HEADER_REQUEST_ID: supplied})
    assert response.headers[HEADER_REQUEST_ID] == supplied


def test_requestIdHeader_blankHeaderTriggersGeneration():
    """Whitespace-only header must be treated as absent and replaced."""
    app = _buildApp()
    addRequestIdMiddleware(app)
    client = TestClient(app)
    response = client.get("/probe", headers={HEADER_REQUEST_ID: "   "})
    rid = response.headers.get(HEADER_REQUEST_ID)
    assert rid is not None
    assert rid != "   "
    assert _HEX12.match(rid), (
        f"server-generated id must be 12 hex chars, got {rid!r}"
    )


# ---------------------------------------------------------------------------
# request.state propagation
# ---------------------------------------------------------------------------
def test_requestId_propagatesToRequestState():
    """The route handler sees the id on ``request.state``."""
    app = _buildApp()
    addRequestIdMiddleware(app)
    client = TestClient(app)
    response = client.get(
        "/probe", headers={HEADER_REQUEST_ID: "abc-trace-1"}
    )
    body = response.json()
    assert body["request_id"] == "abc-trace-1"


def test_requestId_stateHasGeneratedIdWhenClientOmitsHeader():
    app = _buildApp()
    addRequestIdMiddleware(app)
    client = TestClient(app)
    response = client.get("/probe")
    body = response.json()
    assert body["request_id"] is not None
    assert _HEX12.match(body["request_id"])


# ---------------------------------------------------------------------------
# Co-existence with other middlewares
# ---------------------------------------------------------------------------
def test_requestIdWorksAlongsideSecurityHeaders():
    """Request-id + security headers coexist on the same response."""
    app = _buildApp()
    addSecurityHeaders(app)
    addRequestIdMiddleware(app)
    client = TestClient(app)
    response = client.get("/probe")
    assert response.headers.get(HEADER_REQUEST_ID) is not None
    # X-Frame-Options is set by security headers
    assert response.headers.get("X-Frame-Options") == "DENY"


def test_requestIdWorksAlongsideRateLimiting():
    """Request-id + slowapi rate limiting coexist."""
    app = _buildApp()
    addRateLimiting(app)
    installJsonRateLimitHandler(app)
    addRequestIdMiddleware(app)
    client = TestClient(app)
    response = client.get("/probe", headers={HEADER_REQUEST_ID: "rl-test"})
    assert response.status_code == 200
    assert response.headers.get(HEADER_REQUEST_ID) == "rl-test"


def test_requestIdAndAllMiddlewaresCanBeCombined():
    """All Tier 1 middlewares + request-id -> good response, all headers present."""
    app = _buildApp()
    addSecurityHeaders(app)
    addRateLimiting(app)
    installJsonRateLimitHandler(app)
    addRequestIdMiddleware(app)
    client = TestClient(app)
    response = client.get(
        "/api/health", headers={HEADER_REQUEST_ID: "all-stack"}
    )
    assert response.status_code == 200
    assert response.headers.get(HEADER_REQUEST_ID) == "all-stack"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"


def test_requestIdDifferentPerRequest():
    """Two requests without client ids get distinct server ids."""
    app = _buildApp()
    addRequestIdMiddleware(app)
    client = TestClient(app)
    r1 = client.get("/probe")
    r2 = client.get("/probe")
    rid1 = r1.headers[HEADER_REQUEST_ID]
    rid2 = r2.headers[HEADER_REQUEST_ID]
    assert rid1 != rid2, (
        "every request must produce a distinct server-generated id"
    )
