"""
End-to-end integration test for the Tier 2.3 -> Tier 4 J loop.

Exercises the complete operator workflow against the real FastAPI app
(no OSINT network):

1. ``POST /api/analyze/url``            -- analysis lands in history
2. ``GET  /api/history``                -- operator picks the entry id
3. ``POST /api/feedback``               -- operator flags a verdict
4. ``retrainFromFeedback.convert_feedback`` -- bridge emits the CSV

This proves the two halves of the loop (feedback sink + retrain bridge)
agree on the log location, the history lookup, and the label mapping.
"""

from __future__ import annotations

import csv
import importlib
import os

import pytest
from fastapi.testclient import TestClient

from backend.api.orchestrator import AnalysisOrchestrator
from backend.ml.training.retrainFromFeedback import convert_feedback


@pytest.fixture(autouse=True)
def _noOsint(monkeypatch):
    """Keep the loop offline -- the URL pipeline must not touch the net."""

    async def _noOsint(self, domain: str, url: str = "") -> None:
        return None

    monkeypatch.setattr(AnalysisOrchestrator, "_collectOsintData", _noOsint)


@pytest.fixture
def loopEnvironment(tmp_path, monkeypatch):
    """Point history persistence + feedback log at a throwaway dir, then
    force a fresh build of ``backend.main`` so the feedback sink and the
    SQLite history store pick up the overridden env vars (the same pattern
    ``test_feedback_integration.py`` uses)."""
    logPath = tmp_path / "feedback.jsonl"
    monkeypatch.setenv("PHISHGUARD_PERSIST_HISTORY", "1")
    monkeypatch.setenv("PHISHGUARD_HISTORY_DB", str(tmp_path / "history.db"))
    monkeypatch.setenv("PHISHGUARD_FEEDBACK_LOG", str(logPath))

    import backend.main as main_mod

    importlib.reload(main_mod)

    return {
        "client": TestClient(main_mod.app),
        "logPath": logPath,
        "tmpPath": tmp_path,
    }


def test_historyPersistenceThroughApi_writesToSqlite(loopEnvironment):
    """Regression guard: with ``PHISHGUARD_PERSIST_HISTORY=1`` the API
    routes must write to the SQLite store -- not to the in-memory
    singleton they captured at import time (a real bug that silently
    defeated the opt-in persistence feature)."""
    env = loopEnvironment
    client = env["client"]

    from backend.api.historyStore import open_history_store

    with client:
        r = client.post(
            "/api/analyze/url",
            json={"url": "https://example.com"},
        )
        assert r.status_code == 200

    # A brand-new store instance (same env, same db file) must see the
    # row the router just wrote.  Before the fix this returned 0 rows.
    fresh = open_history_store()
    assert fresh.list().total == 1
    assert fresh.list().entries[0].content == "https://example.com"


def test_feedbackLoop_endToEnd(loopEnvironment):
    env = loopEnvironment
    client = env["client"]
    outCsv = env["tmpPath"] / "feedback_features.csv"
    summaryJson = env["tmpPath"] / "feedback_ingest_summary.json"

    with client:
        # 1. Analyse a safe URL.
        r = client.post(
            "/api/analyze/url",
            json={"url": "https://example.com"},
        )
        assert r.status_code == 200
        assert r.json()["verdict"]["isPhishing"] is False

        # 2. Grab the history entry id (newest first).
        history = client.get("/api/history").json()
        entry = history["entries"][0]
        assert entry["content"] == "https://example.com"

        # 3. Operator confirms the verdict (correct).
        fb = client.post(
            "/api/feedback",
            json={
                "historyId": entry["id"],
                "verdict": "correct",
                "reporter": "e2e-test",
            },
        )
        assert fb.status_code == 200
        assert fb.json()["historyId"] == entry["id"]

    # The feedback JSONL must have been written where the bridge reads it.
    assert os.path.exists(env["logPath"])

    # 4. Bridge: JSONL -> labelled feature CSV (env-resolved paths).
    summary = convert_feedback(
        outputCsv=outCsv,
        summaryJson=summaryJson,
    )

    assert summary["recordsRead"] == 1
    assert summary["rowsWritten"] == 1
    assert summary["labelSplit"] == {"0": 1, "1": 0}

    with open(outCsv, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    assert rows[0][-1] == "label"  # schema header
    assert rows[1][-1] == "0"      # 'correct' on a safe URL -> label 0
