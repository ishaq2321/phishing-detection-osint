"""
Integration tests for Tier 1.6's liveness/readiness split.

Customers

* ``GET /api/health/live`` is a 200 that returns within 50 ms and
  carries only ``status`` + ``uptimeSeconds``.
* ``GET /api/health/ready`` returns the deep check envelope and
  collapses to ``healthy`` in normal environments.
* ``GET /api/health`` (the legacy path) keeps working as an alias
  for ``/ready`` -- so the existing Render
  ``healthCheckPath: /api/health`` configuration continues to
  function.
* The three endpoints share the same ``services`` map shape when
  they have any.
* Render-relevant ``X-Request-ID`` header round-trip works on
  all three probe paths.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from backend.main import app


@pytest.fixture
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# /api/health/live
# ---------------------------------------------------------------------------
def test_liveness_returns200_withAliveShape(client):
    r = client.get("/api/health/live")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "alive"
    assert "uptimeSeconds" in body
    assert isinstance(body["uptimeSeconds"], (int, float))


def test_liveness_omitsDeepChecks(client):
    """/live must not run probes; therefore must not have 'checks'."""
    body = client.get("/api/health/live").json()
    # Probe-shaped keys must be absent.
    for k in ("checks", "services", "version"):
        assert k not in body, (
            f"liveness endpoint must not include {k!r} (that's "
            f"the readiness contract)"
        )


def test_liveness_completesWithin50ms(client):
    """The whole point of splitting live/ready is that live is
    cheap -- fail loudly if it's not."""
    started = time.perf_counter()
    r = client.get("/api/health/live")
    elapsed = (time.perf_counter() - started) * 1000.0
    assert r.status_code == 200
    assert elapsed < 50.0, (
        f"/api/health/live took {elapsed:.1f} ms -- too slow for "
        f"a per-second Render liveness probe"
    )


# ---------------------------------------------------------------------------
# /api/health/ready
# ---------------------------------------------------------------------------
def test_readiness_returns200_whenHealthy(client):
    r = client.get("/api/health/ready")
    body = r.json()
    assert r.status_code == 200
    assert body["status"] in {"healthy", "degraded"}
    assert "checks" in body
    assert "services" in body
    assert body["ready"] is True
    assert "uptimeSeconds" in body


def test_readiness_carriesDeepChecks(client):
    body = client.get("/api/health/ready").json()
    for section in ("dns", "ml", "imports"):
        assert section in body["checks"], (
            f"missing {section!r} probe in /ready"
        )
        assert body["checks"][section]["status"] in {"up", "down"}


def test_readiness_aggregatesStatusMatchingLegacy(client):
    """``/ready`` status must equal ``/api/health`` status."""
    readyStatus = client.get("/api/health/ready").json()["status"]
    legacyStatus = client.get("/api/health").json()["status"]
    assert readyStatus == legacyStatus


# ---------------------------------------------------------------------------
# Legacy /api/health (back-compat alias)
# ---------------------------------------------------------------------------
def test_legacyHealth_returns200(client):
    r = client.get("/api/health")
    assert r.status_code == 200


def test_legacyHealth_hasSameServicesMapShape(client):
    legacy = client.get("/api/health").json()
    for sub in ("osint", "analyzer", "ml"):
        assert sub in legacy["services"]


def test_legacyHealth_andReadiness_shareServiceMap(client):
    legacyServices = client.get("/api/health").json()["services"]
    readyServices = client.get("/api/health/ready").json()["services"]
    assert legacyServices == readyServices


# ---------------------------------------------------------------------------
# 503 path on /ready (degraded still OK, only unhealthy 503)
# ---------------------------------------------------------------------------
def test_readiness_returns503_whenUnhealthy(client, monkeypatch):
    import backend.health as health_mod
    from fastapi import status

    def _allDown(_checks):
        return "unhealthy"

    monkeypatch.setattr(health_mod, "_aggregateStatus", _allDown)
    r = client.get("/api/health/ready")
    assert r.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


def test_legacyHealth_returns503_whenUnhealthy(client, monkeypatch):
    import backend.health as health_mod
    from fastapi import status

    def _allDown(_checks):
        return "unhealthy"

    monkeypatch.setattr(health_mod, "_aggregateStatus", _allDown)
    r = client.get("/api/health")
    assert r.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


# ---------------------------------------------------------------------------
# X-Request-ID round-trip across all three probes
# ---------------------------------------------------------------------------
def test_requestId_roundTripsOnLive(client):
    r = client.get("/api/health/live", headers={"X-Request-ID": "liv-1"})
    assert r.status_code == 200
    assert r.headers.get("X-Request-ID") == "liv-1"


def test_requestId_roundTripsOnReady(client):
    r = client.get("/api/health/ready", headers={"X-Request-ID": "rdy-1"})
    assert r.status_code == 200
    assert r.headers.get("X-Request-ID") == "rdy-1"


def test_requestId_roundTripsOnLegacy(client):
    r = client.get("/api/health", headers={"X-Request-ID": "leg-1"})
    assert r.headers.get("X-Request-ID") == "leg-1"
