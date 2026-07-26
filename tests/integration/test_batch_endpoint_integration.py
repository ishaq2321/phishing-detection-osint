"""
Integration tests for ``POST /api/analyze/batch`` (Tier 3 end-to-end).

Customers

* A small batch returns 200 with all-success entries and a
  positive ``analysisTime`` (in ms).
* Validation surfaces the size cap (51 items -> 422).
* Validation rejects an empty items list (422).
* Mixed batch (some URL, some email, some invalid) preserves
  per-item failure semantics in the response payload.
* Successful items are persisted in the history store (the same
  FIFO dequeue as the single routes).
* Rate-limit ``x-ratelimit-*`` headers are emitted.
* X-Request-ID round-trips through the batch endpoint.
* 50-item batch is the upper bound (matches the schema cap).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import backend.api.rate_limiting as rl
from backend.api import historyStore as hs
from backend.main import app


# Auto-reset rate-limit storage between tests so per-IP buckets
# don't leak.
@pytest.fixture(autouse=True)
def _resetRateLimiter():
    rl.limiter._route_limits.clear()
    rl.limiter._Limiter__marked_for_limiting.clear()
    rl.limiter._dynamic_route_limits.clear()
    rl.limiter.reset()
    yield
    rl.limiter.reset()


@pytest.fixture
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
def test_batchEndpoint_presentInOpenAPI(client):
    """The endpoint shows up under the documented tags."""
    r = client.get("/openapi.json")
    spec = r.json()
    assert "/api/analyze/batch" in spec["paths"]
    op = spec["paths"]["/api/analyze/batch"]["post"]
    # response_model and tag surfaced
    assert op["tags"] == ["phishing-detection"]
    assert "BatchAnalyzeResponse" in op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------
def test_batchAllUrlSuccess(client):
    body = {
        "items": [
            {"type": "url", "url": "https://example.com"},
            {"type": "url", "url": "https://example.org"},
        ]
    }
    r = client.post("/api/analyze/batch", json=body)
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is True
    assert data["total"] == 2
    assert data["succeeded"] == 2
    assert data["failed"] == 0
    assert isinstance(data["analysisTime"], (int, float))
    assert data["analysisTime"] >= 0.0
    for offset, item in enumerate(data["results"]):
        assert item["index"] == offset
        assert item["status"] == "ok"
        assert item["response"]["verdict"]["isPhishing"] is False


def test_batchMixedUrlAndEmail(client):
    body = {
        "items": [
            {"type": "url", "url": "https://example.com"},
            {"type": "email", "content": "hello world", "subject": "ping"},
        ]
    }
    r = client.post("/api/analyze/batch", json=body)
    assert r.status_code == 200
    data = r.json()
    assert data["succeeded"] == 2
    assert data["failed"] == 0
    # Order preserved
    assert data["results"][0]["index"] == 0
    assert data["results"][1]["index"] == 1


def test_batchAutoDetection(client):
    """``type=auto`` items get heuristic detection server-side."""
    body = {
        "items": [
            {"type": "auto", "url": "https://example.com"},
            {"type": "auto", "content": "Hi there!"},
        ]
    }
    r = client.post("/api/analyze/batch", json=body)
    assert r.status_code == 200
    assert r.json()["succeeded"] == 2


# ---------------------------------------------------------------------------
# Per-item failure semantics
# ---------------------------------------------------------------------------
def test_batchPerItemFailure_keepsOthersSucceeding(client):
    """One bad URL does not poison the whole batch."""
    body = {
        "items": [
            {"type": "url", "url": "https://example.com"},  # ok
            {"type": "url", "url": ""},                        # validation error
            {"type": "url", "url": "https://example.org"},  # ok
        ]
    }
    r = client.post("/api/analyze/batch", json=body)
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 3
    assert data["succeeded"] == 2
    assert data["failed"] == 1
    statuses = [item["status"] for item in data["results"]]
    assert statuses == ["ok", "error", "ok"]
    # The error entry carries a message
    assert data["results"][1]["error"]


# ---------------------------------------------------------------------------
# Size cap validation
# ---------------------------------------------------------------------------
def test_batchRejects51Items(client):
    body = {
        "items": [
            {"type": "url", "url": f"https://e{i}.com"} for i in range(51)
        ]
    }
    r = client.post("/api/analyze/batch", json=body)
    # FastAPI's Pydantic validator surfaces this as 422.
    assert r.status_code == 422


def test_batchRejectsEmptyItems(client):
    r = client.post("/api/analyze/batch", json={"items": []})
    assert r.status_code == 422


def test_batchAcceptsExactly50Items(client):
    body = {
        "items": [
            {"type": "url", "url": f"https://e{i}.com"} for i in range(50)
        ]
    }
    r = client.post("/api/analyze/batch", json=body)
    assert r.status_code == 200
    assert r.json()["total"] == 50


# ---------------------------------------------------------------------------
# History persistence
# ---------------------------------------------------------------------------
def test_batchSuccessfulItemsPersistInHistory(client):
    historyBefore = hs.historyStore.count
    body = {
        "items": [
            {"type": "url", "url": "https://example.com"},
            {"type": "url", "url": "https://example.org"},
        ]
    }
    r = client.post("/api/analyze/batch", json=body)
    assert r.status_code == 200
    historyAfter = hs.historyStore.count
    # The successful items appear as history entries.
    assert historyAfter - historyBefore == 2


def test_batchFailedItemsDoNotIncrementHistory(client):
    """A failed validation does NOT add a history entry."""
    historyBefore = hs.historyStore.count
    body = {
        "items": [
            {"type": "url", "url": ""},  # validation fails
            {"type": "url", "url": "https://example.com"},  # ok
        ]
    }
    r = client.post("/api/analyze/batch", json=body)
    assert r.status_code == 200
    historyAfter = hs.historyStore.count
    # Only the successful one persists; the validation failure does NOT.
    assert historyAfter - historyBefore == 1


# ---------------------------------------------------------------------------
# Rate-limit / X-Request-ID round-trips
# ---------------------------------------------------------------------------
def test_batchEndpointEmitsRatelimitHeaders(client):
    """slowapi's ``headers_enabled=True`` config emits a header trio on
    every limited response.  The header values reflect the most
    restrictive applicable limit (the route-specific one wins)."""
    r = client.post(
        "/api/analyze/batch",
        json={"items": [{"type": "url", "url": "https://example.com"}]},
        headers={"X-Forwarded-For": "203.0.113.55"},
    )
    assert "x-ratelimit-limit" in {k.lower() for k in r.headers.keys()}
    # Must be a positive integer (30/min route cap or 60/min default).
    limit = int(r.headers.get("x-ratelimit-limit"))
    assert limit > 0
    remaining = r.headers.get("x-ratelimit-remaining")
    assert remaining is not None
    assert int(remaining) >= 0


def test_batchRequestIdRoundTrip(client):
    r = client.post(
        "/api/analyze/batch",
        json={"items": [{"type": "url", "url": "https://example.com"}]},
        headers={"X-Request-ID": "batch-trace-1"},
    )
    assert r.status_code == 200
    assert r.headers.get("X-Request-ID") == "batch-trace-1"
