"""
Integration tests for the history export endpoints (Tier 4 B end-to-end).

Customers

* ``GET /api/history/export.csv`` returns 200 ``text/csv`` with a
  Content-Disposition attachment header.
* ``GET /api/history/export.json`` returns 200 ``application/json``
  with a Content-Disposition attachment header.
* Both reflect whatever is in the history store (persisted analyses).
* Route-order regression: ``/history/export.csv`` must resolve to the
  export handler, NOT to ``/history/{entryId}`` with id ``export.csv``
  (which would 404).
* ``/history/{entryId}`` still works for real UUIDs.
"""

from __future__ import annotations

import csv
import io
import json

import pytest
from fastapi.testclient import TestClient

from backend.api import historyStore as hs
from backend.main import app


@pytest.fixture(autouse=True)
def _emptyHistoryStore():
    """Start every test with a clean store (module-level singleton)."""
    hs.historyStore.clear()
    yield
    hs.historyStore.clear()


@pytest.fixture
def client():
    return TestClient(app)


def _seedStore() -> str:
    """Add one entry through the public store API; return its id."""
    entry = hs.historyStore.add(
        content="https://examp1e-login.tk/verify",
        contentType="url",
        response={
            "success": True,
            "verdict": {
                "isPhishing": True,
                "confidenceScore": 0.87,
                "threatLevel": "dangerous",
                "reasons": ["Suspicious URL structure"],
                "recommendation": "Do not interact.",
            },
            "features": {"totalRiskIndicators": 5},
            "analysisTime": 12.3,
        },
    )
    return entry.id


# ---------------------------------------------------------------------------
# OpenAPI presence
# ---------------------------------------------------------------------------

def test_exportEndpoints_presentInOpenAPI(client):
    r = client.get("/openapi.json")
    paths = r.json()["paths"]
    assert "/api/history/export.csv" in paths
    assert "/api/history/export.json" in paths


# ---------------------------------------------------------------------------
# CSV endpoint
# ---------------------------------------------------------------------------

def test_csv_export_returnsAttachment(client):
    _seedStore()
    r = client.get("/api/history/export.csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    assert "phishguard-history.csv" in r.headers["content-disposition"]


def test_csv_export_contains_seeded_row(client):
    entryId = _seedStore()
    r = client.get("/api/history/export.csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 1
    assert rows[0]["id"] == entryId
    assert rows[0]["content"] == "https://examp1e-login.tk/verify"
    assert rows[0]["isPhishing"] == "true"


def test_csv_export_empty_store_header_only(client):
    r = client.get("/api/history/export.csv")
    rows = list(csv.reader(io.StringIO(r.text)))
    assert len(rows) == 1  # header only


# ---------------------------------------------------------------------------
# JSON endpoint
# ---------------------------------------------------------------------------

def test_json_export_returnsAttachment(client):
    _seedStore()
    r = client.get("/api/history/export.json")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert "attachment" in r.headers["content-disposition"]
    assert "phishguard-history.json" in r.headers["content-disposition"]


def test_json_export_contains_seeded_entry(client):
    entryId = _seedStore()
    r = client.get("/api/history/export.json")
    payload = json.loads(r.text)
    assert isinstance(payload, list)
    assert len(payload) == 1
    assert payload[0]["id"] == entryId


def test_json_export_empty_store_is_empty_array(client):
    r = client.get("/api/history/export.json")
    assert json.loads(r.text) == []


# ---------------------------------------------------------------------------
# Route-order regression: export.csv must NOT be captured by {entryId}
# ---------------------------------------------------------------------------

def test_exportCsv_is_not_swallowed_by_entryId_route(client):
    """The specific export route must win over /history/{entryId}."""
    _seedStore()
    r = client.get("/api/history/export.csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")


def test_entryIdRoute_still_works_for_real_uuids(client):
    entryId = _seedStore()
    r = client.get(f"/api/history/{entryId}")
    assert r.status_code == 200
    assert r.json()["id"] == entryId


def test_unknown_entryId_still_404s(client):
    r = client.get("/api/history/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404
