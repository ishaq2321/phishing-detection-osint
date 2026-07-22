"""
Integration tests for the deep ``/api/health`` endpoint.

Customers

* Endpoint returns 200 when healthy and a checks map is present.
* Top-level ``status`` collapses from the per-check statuses.
* Backwards-compatible keys (``status``, ``version``, ``timestamp``,
  ``services``) remain populated.
* New keys (``checks``, ``uptimeSeconds``, ``ready``) appear.
* The endpoint returns 503 when the underlying checks indicate
  ``unhealthy``.
* It returns 200 even when status is ``degraded`` so uptime
  monitors see OK.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import backend.health as health_mod
from backend.main import app


@pytest.fixture
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# Happy-path shape
# ---------------------------------------------------------------------------
def test_health_response_is200_whenAllUp(client):
    response = client.get("/api/health")
    assert response.status_code in (200, 503), (
        f"unexpected status code {response.status_code}; body={response.text}"
    )


def test_health_response_carriesBackwardCompatibleKeys(client):
    """Legacy keys must remain present for upstream consumers."""
    response = client.get("/api/health")
    body = response.json()
    for key in ("status", "version", "timestamp", "services"):
        assert key in body, f"missing required key {key!r}"
    # The sub-keys of `services` are also required.
    services = body["services"]
    for sub in ("osint", "analyzer", "ml"):
        assert sub in services


def test_health_response_carriesDeepChecksKey(client):
    """The new tier-1.5 fields appear on every response."""
    response = client.get("/api/health")
    body = response.json()
    assert "checks" in body, "missing checks key"
    assert "uptimeSeconds" in body, "missing uptimeSeconds key"
    assert "ready" in body, "missing ready key"
    assert body["ready"] is True


def test_health_checksHasExpectedSubsections(client):
    """The checks dict must contain dns, ml, imports subsections."""
    response = client.get("/api/health")
    body = response.json()
    checks = body["checks"]
    for section in ("dns", "ml", "imports"):
        assert section in checks, f"missing {section!r} check"
        assert "status" in checks[section]
        assert checks[section]["status"] in {"up", "down"}
        assert "latencyMs" in checks[section]


def test_health_uptimeIsReasonableNumber(client):
    """``uptimeSeconds`` is a non-negative float."""
    response = client.get("/api/health")
    body = response.json()
    assert isinstance(body["uptimeSeconds"], (int, float))
    assert body["uptimeSeconds"] >= 0.0


# ---------------------------------------------------------------------------
# Top-level status logic
# ---------------------------------------------------------------------------
def test_health_statusValid(client):
    """Top-level status is one of the three documented values."""
    response = client.get("/api/health")
    body = response.json()
    assert body["status"] in {"healthy", "degraded", "unhealthy"}


def test_health_returns200WhenStatusIsDegraded(client, monkeypatch):
    """Degraded states still return 200 -- only ``unhealthy`` gets 503."""
    monkeypatch.setattr(
        health_mod,
        "_aggregateStatus",
        lambda checks: "degraded",
    )
    response = client.get("/api/health")
    assert response.status_code == 200, (
        "degraded should NOT trigger 503; uptime monitors expect OK"
    )
    body = response.json()
    assert body["status"] == "degraded"


def test_health_returns503WhenStatusIsUnhealthy(client, monkeypatch):
    """``unhealthy`` must surface as HTTP 503 for render/uptime alerts."""
    monkeypatch.setattr(
        health_mod,
        "_aggregateStatus",
        lambda checks: "unhealthy",
    )
    response = client.get("/api/health")
    assert response.status_code == 503, (
        "unhealthy MUST map to HTTP 503"
    )
    body = response.json()
    assert body["status"] == "unhealthy"


# ---------------------------------------------------------------------------
# Aggregation invariants
# ---------------------------------------------------------------------------
def test_health_aggregationMatchesChecks(client):
    """The top-level status matches the per-check aggregation."""
    response = client.get("/api/health")
    body = response.json()
    expected = health_mod._aggregateStatus(body["checks"])
    assert body["status"] == expected


def test_health_servicesMapMatchesChecks(client):
    """The legacy services dict is a faithful projection of checks."""
    response = client.get("/api/health")
    body = response.json()
    expectedServices = health_mod.servicesFromChecks(body["checks"])
    assert body["services"] == expectedServices
