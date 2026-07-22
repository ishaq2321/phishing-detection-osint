"""
Unit tests for the security headers middleware.

Verifies that every response carries the expected hardened headers
and that HSTS is only emitted in production.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.security_headers import (
    HEADER_CSP,
    HEADER_HSTS,
    HEADER_PERMISSIONS,
    HEADER_REFERRER,
    HEADER_XCTO,
    HEADER_XFO,
    _API_CSP_DEFAULT,
    _API_CSP_DOCS,
    _HSTS_VALUE,
    _NOSNIFF_VALUE,
    _PERMISSIONS_VALUE,
    _REFERRER_VALUE,
    _XFO_VALUE,
    _makeMiddleware,
    addSecurityHeaders,
)


def _buildTestClient(isProduction: bool, environment: str = "testing") -> TestClient:
    """Build a FastAPI app with security headers, env patched at the
    env-var level (the only reliable way to switch isProduction in
    pydantic-settings without re-importing the module)."""
    # CRITICAL: clear the cached settings BEFORE we build the app so the
    # securityHeadersMiddleware closure captures the right isProduction
    # value when it is created. The cache lives on backend.config.getSettings.
    import backend.config as config_mod
    config_mod.getSettings.cache_clear()

    # Also confirm by re-reading: in tests, the os.environ must be set,
    # but we are being extra defensive in case the autouse fixture
    # interleaves with this fixture. Override directly.
    import os
    os.environ["ENVIRONMENT"] = environment

    testApp = FastAPI()

    @testApp.get("/probe")
    async def probe():
        return {"ok": True}

    @testApp.get("/docs/oauth2-redirect")
    async def docsProbe():
        return {"docs": True}

    @testApp.get("/openapi.json")
    async def openApiProbe():
        return {"openapi": "3.1.0"}

    @testApp.get("/redoc")
    async def redocProbe():
        return {"redoc": "ok"}

    addSecurityHeaders(testApp)
    return TestClient(testApp)


@pytest.fixture
def clientProd(monkeypatch):
    """TestClient with isProduction=True."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("LOG_LEVEL", "INFO")
    return _buildTestClient(isProduction=True)


@pytest.fixture
def clientDev(monkeypatch):
    """TestClient with isProduction=False."""
    monkeypatch.setenv("ENVIRONMENT", "testing")
    monkeypatch.setenv("LOG_LEVEL", "INFO")
    return _buildTestClient(isProduction=False, environment="testing")


def test_XContentTypeOptions_emitted(clientDev: TestClient):
    """nosniff must always be present regardless of env."""
    response = clientDev.get("/probe")
    assert response.status_code == 200
    assert response.headers.get(HEADER_XCTO) == _NOSNIFF_VALUE


def test_XFrameOptions_denied(clientDev: TestClient):
    response = clientDev.get("/probe")
    assert response.headers.get(HEADER_XFO) == _XFO_VALUE


def test_ReferrerPolicy_strictOriginWhenCrossOrigin(clientDev: TestClient):
    response = clientDev.get("/probe")
    assert response.headers.get(HEADER_REFERRER) == _REFERRER_VALUE


def test_PermissionsPolicy_empty(clientDev: TestClient):
    response = clientDev.get("/probe")
    policy = response.headers.get(HEADER_PERMISSIONS, "")
    assert policy
    # Permissions-Policy MUST disable camera and microphone (zero tolerance)
    assert "camera=()" in policy
    assert "microphone=()" in policy
    # And the geolocation too; the policy is restrictive.
    assert "geolocation=()" in policy


def test_CSP_apiEndpoint_getsRestrictivePolicy(clientDev: TestClient):
    response = clientDev.get("/probe")
    csp = response.headers.get(HEADER_CSP, "")
    assert csp == _API_CSP_DEFAULT


def test_CSP_docsPath_getsMorePermissivePolicy(clientDev: TestClient):
    response = clientDev.get("/docs/oauth2-redirect")
    csp = response.headers.get(HEADER_CSP, "")
    assert csp == _API_CSP_DOCS
    # Must explicitly include the CDN that fastapi supplies to /docs page
    assert "cdn.jsdelivr.net" in csp


def test_CSP_openApiPath_getsLooserPolicy(clientDev: TestClient):
    response = clientDev.get("/openapi.json")
    csp = response.headers.get(HEADER_CSP, "")
    assert csp == _API_CSP_DOCS


def test_HSTS_onlySetInProduction(clientDev: TestClient):
    developmentResponse = clientDev.get("/probe")
    assert HEADER_HSTS not in developmentResponse.headers, (
        "HSTS must NOT be set in development/testing env "
        "(otherwise HTTP clients would silently re-route to HTTPS) "
        "during local development"
    )


def test_securityHeadersOnErrorResponseToo(clientDev: TestClient):
    """404s should still carry security headers."""
    response = clientDev.get("/does-not-exist")
    assert response.status_code == 404
    assert response.headers.get(HEADER_XCTO) == _NOSNIFF_VALUE
    assert response.headers.get(HEADER_XFO) == _XFO_VALUE


def test_allRequiredHeadersPresent(clientDev: TestClient):
    """Hammer-test: every probe endpoint must carry the full default set."""
    for path in ("/probe", "/docs/oauth2-redirect", "/openapi.json"):
        response = clientDev.get(path)
        assert response.headers.get(HEADER_XCTO) == _NOSNIFF_VALUE, (
            f"missing X-CTO on {path}"
        )
        assert response.headers.get(HEADER_XFO) == _XFO_VALUE, (
            f"missing X-FO on {path}"
        )
        assert response.headers.get(HEADER_REFERRER) == _REFERRER_VALUE, (
            f"missing Referrer-Policy on {path}"
        )
        assert HEADER_CSP in response.headers, f"missing CSP on {path}"
        assert HEADER_PERMISSIONS in response.headers, (
            f"missing Permissions-Policy on {path}"
        )


def test_addSecurityHeaders_doesNotDoubleApply(clientDev: TestClient):
    """Headers should not be duplicated when addSecurityHeaders is called twice."""
    clientDev.app.middleware("http")(_makeMiddleware(False))
    r = clientDev.get("/probe")
    headers = r.headers
    assert headers.get(HEADER_XCTO) == _NOSNIFF_VALUE


def test_correctHeadersAfterAccidentalDoubleRegistration(clientDev: TestClient):
    """End-to-end: registering twice does not break the response."""
    for _ in range(3):
        clientDev.app.middleware("http")(_makeMiddleware(False))
    r = clientDev.get("/probe")
    assert r.status_code == 200
    assert r.headers.get(HEADER_XCTO) == _NOSNIFF_VALUE
    assert r.headers.get(HEADER_XFO) == _XFO_VALUE
    csp = r.headers.get(HEADER_CSP, "")
    assert "default-src 'none'" in csp


def test_middlewareFactory_invokedWithFalseDoesNotEmitHSTS():
    """Direct unit test of the middleware function: no HSTS when isProduction=False."""
    from fastapi import FastAPI
    testApp = FastAPI()

    @testApp.get("/probe")
    async def probe():
        return {}

    middleware = _makeMiddleware(isProduction=False)
    testApp.middleware("http")(middleware)
    from fastapi.testclient import TestClient
    client = TestClient(testApp)
    assert HEADER_HSTS not in client.get("/probe").headers


def test_middlewareFactory_invokedWithTrueEmitsHSTS():
    """Direct unit test: HSTS when isProduction=True."""
    from fastapi import FastAPI
    testApp = FastAPI()

    @testApp.get("/probe")
    async def probe():
        return {}

    middleware = _makeMiddleware(isProduction=True)
    testApp.middleware("http")(middleware)
    from fastapi.testclient import TestClient
    client = TestClient(testApp)
    response = client.get("/probe")
    assert response.headers.get(HEADER_HSTS) == _HSTS_VALUE
