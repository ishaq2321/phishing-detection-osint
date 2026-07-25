"""
Integration tests for the Tier 2.3 feedback loop (HTTP layer).

Customers

* ``POST /api/feedback`` accepts a valid record and returns 200
  with a freshly-minted ``feedbackId``.
* The sink file actually contains the appended record after the
  POST (we read it from disk).
* Repeated POSTs land as multiple distinct lines on disk.
* Invalid ``verdict`` returns HTTP 422.
* Empty ``historyId`` returns HTTP 422 (Pydantic validation).
* ``GET /api/feedback`` returns the parsed list, newest-first.
* ``GET /api/feedback`` is NOT rate-limited (operators batch
  corrections without aggressive throttling).
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import backend.api.feedback as fb
from backend.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Configure a fresh feedback log under ``tmp_path`` and a fresh
    ``TestClient`` against a freshly-imported ``app`` so the
    feedback sink picks up the env-overridden path."""
    logPath = str(tmp_path / "fb.jsonl")
    monkeypatch.setenv("PHISHGUARD_FEEDBACK_LOG", logPath)
    # Force a fresh build of ``backend.main`` so the env vars are
    # re-read and the feedback router mounts against the new path.
    import importlib
    import backend.main as main_mod

    importlib.reload(main_mod)
    yield TestClient(main_mod.app), logPath


def _registerOnApp(app):
    """Helper to (re-)register feedback routes on a FastAPI app."""
    # The router mounts itself with prefix='/api', so /api/feedback.
    return fb.registerFeedbackEndpoints(app)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def _post(client, *, historyId="abc", verdict="false_negative",
           comment="x", reporter=None):
    body = {
        "historyId": historyId,
        "verdict": verdict,
        "comment": comment,
    }
    if reporter is not None:
        body["reporter"] = reporter
    return client.post("/api/feedback", json=body)


# ---------------------------------------------------------------------------
# POST
# ---------------------------------------------------------------------------
def test_postFeedback_acceptedReturns200(client):
    api, logPath = client
    r = api.post(
        "/api/feedback",
        json={
            "historyId": "h-1",
            "verdict": "false_negative",
            "comment": "missed a credential-harvesting URL",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] is True
    assert "feedbackId" in body
    assert uuid.UUID(body["feedbackId"])  # uuid-parseable
    assert body["historyId"] == "h-1"


def test_postFeedback_appendsLineToDisk(client):
    api, logPath = client
    r = api.post(
        "/api/feedback",
        json={"historyId": "h-1", "verdict": "correct", "comment": "okay"},
    )
    assert r.status_code == 200
    # Disk file now has exactly one line.
    contents = Path(logPath).read_text(encoding="utf-8")
    lines = [s for s in contents.split("\n") if s]
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["historyId"] == "h-1"
    assert parsed["verdict"] == "correct"


def test_postFeedback_multipleLandAsDistinctLines(client):
    api, logPath = client
    for i in range(5):
        r = api.post(
            "/api/feedback",
            json={"historyId": f"h-{i}", "verdict": "false_negative"},
        )
        assert r.status_code == 200
    contents = Path(logPath).read_text(encoding="utf-8")
    lines = [s for s in contents.split("\n") if s]
    assert len(lines) == 5
    historyIds = [json.loads(s)["historyId"] for s in lines]
    # All five IDs landed, none duplicated
    assert sorted(historyIds) == sorted(f"h-{i}" for i in range(5))


def test_postFeedback_invalidVerdictReturns422(client):
    api, _ = client
    r = api.post(
        "/api/feedback",
        json={
            "historyId": "h-1",
            "verdict": "NOT_A_VALID_VERDICT",
            "comment": "should 422",
        },
    )
    assert r.status_code == 422


def test_postFeedback_emptyHistoryIdReturns422(client):
    api, _ = client
    r = api.post(
        "/api/feedback",
        json={"historyId": "", "verdict": "correct"},
    )
    assert r.status_code == 422


def test_postFeedback_missingHistoryIdReturns422(client):
    api, _ = client
    r = api.post(
        "/api/feedback",
        json={"verdict": "correct"},
    )
    assert r.status_code == 422


def test_postFeedback_optionalReporterFieldAccepted(client):
    api, logPath = client
    r = api.post(
        "/api/feedback",
        json={
            "historyId": "h-1",
            "verdict": "correct",
            "reporter": "alice@ops.example.com",
        },
    )
    assert r.status_code == 200
    contents = Path(logPath).read_text(encoding="utf-8")
    parsed = json.loads(contents.split("\n")[0])
    assert parsed["reporter"] == "alice@ops.example.com"


# ---------------------------------------------------------------------------
# GET
# ---------------------------------------------------------------------------
def test_getFeedback_emptyReturnsEmptyList(client):
    api, _ = client
    r = api.get("/api/feedback")
    assert r.status_code == 200
    body = r.json()
    assert body["feedback"] == []
    assert body["total"] == 0


def test_getFeedback_afterPostsReturnsRecords(client):
    api, _ = client
    api.post("/api/feedback", json={"historyId": "h-1", "verdict": "correct"})
    api.post("/api/feedback", json={"historyId": "h-2", "verdict": "false_negative"})
    r = api.get("/api/feedback")
    body = r.json()
    assert body["total"] == 2
    # Newest-first ordering
    assert body["feedback"][0]["historyId"] == "h-2"
    assert body["feedback"][1]["historyId"] == "h-1"


def test_getFeedback_pagination(client):
    api, _ = client
    for i in range(10):
        api.post("/api/feedback", json={"historyId": f"h-{i}", "verdict": "correct"})
    body = api.get("/api/feedback?limit=3&offset=2").json()
    assert len(body["feedback"]) == 3
    assert body["total"] == 10


# ---------------------------------------------------------------------------
# X-Request-ID round-trip across feedback endpoints
# ---------------------------------------------------------------------------
def test_postCarriesRequestIdHeader(client):
    api, _ = client
    r = api.post(
        "/api/feedback",
        json={"historyId": "x", "verdict": "correct"},
        headers={"X-Request-ID": "fb-trace"},
    )
    assert r.headers.get("X-Request-ID") == "fb-trace"


def test_getCarriesRequestIdHeader(client):
    api, _ = client
    r = api.get("/api/feedback", headers={"X-Request-ID": "fb-trace-get"})
    assert r.headers.get("X-Request-ID") == "fb-trace-get"
