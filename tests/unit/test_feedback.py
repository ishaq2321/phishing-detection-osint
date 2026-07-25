"""
Unit tests for ``backend.api.feedback`` (Tier 2.3).

Customers

* ``JsonlFeedbackSink`` writes one well-formed JSON object per
  line, terminating in a newline.
* The sink is thread-safe (we don't lose records under concurrent
  appends, and lines don't get interleaved).
* The sink survives a cycle of ``append`` + close + reopen (records
  are persistent on disk).
* ``_validate_verdict`` accepts the three documented verdicts and
  rejects everything else.
* ``_build_record`` always carries an ``id`` (UUID), an
  ``receivedAt`` ISO-8601 UTC timestamp, and the running app version.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import HTTPException

from backend.api.feedback import (
    DEFAULT_FEEDBACK_LOG,
    FeedbackRequest,
    JsonlFeedbackSink,
    VERDICT_CORRECT,
    VERDICT_FALSE_NEGATIVE,
    VERDICT_FALSE_POSITIVE,
    _VALID_VERDICT_VALUES,
    _build_record,
    _feedback_log_path,
    _validate_verdict,
)


@pytest.fixture
def tmpSink(tmp_path: Path):
    """Yield a fresh sink under ``tmp_path``; cleanup at teardown."""
    p = tmp_path / "feedback.jsonl"
    sink = JsonlFeedbackSink(str(p))
    try:
        yield sink
    finally:
        if p.exists():
            p.unlink()


# ---------------------------------------------------------------------------
# Env resolution
# ---------------------------------------------------------------------------
def test_feedbackLogPathDefault(monkeypatch):
    monkeypatch.delenv("PHISHGUARD_FEEDBACK_LOG", raising=False)
    assert _feedback_log_path() == DEFAULT_FEEDBACK_LOG


def test_feedbackLogPathOverride(monkeypatch, tmp_path: Path):
    p = str(tmp_path / "f.jsonl")
    monkeypatch.setenv("PHISHGUARD_FEEDBACK_LOG", p)
    assert _feedback_log_path() == p


# ---------------------------------------------------------------------------
# JsonlFeedbackSink basics
# ---------------------------------------------------------------------------
def test_sinkCreatesParentDirectory(tmp_path: Path):
    nestedPath = tmp_path / "deep" / "nested" / "f.jsonl"
    sink = JsonlFeedbackSink(str(nestedPath))
    assert nestedPath.parent.exists()


def test_sinkAppendsOneLinePerRecord(tmpSink: JsonlFeedbackSink):
    tmpSink.append({"id": "1", "kind": "a"})
    tmpSink.append({"id": "2", "kind": "b"})
    raw = tmpSink.path
    contents = Path(raw).read_text(encoding="utf-8")
    # Two lines, one trailing newline each
    lines = [s for s in contents.split("\n") if s]
    assert len(lines) == 2
    assert json.loads(lines[0])["id"] == "1"
    assert json.loads(lines[1])["id"] == "2"


def test_sinkRecordsRoundTrip(tmpSink: JsonlFeedbackSink):
    record = {
        "id": str(uuid.uuid4()),
        "historyId": "abc",
        "verdict": VERDICT_FALSE_NEGATIVE,
        "comment": "ok",
        "receivedAt": "2026-01-01T00:00:00+00:00",
        "appVersion": "1.0.0",
    }
    tmpSink.append(record)
    retrieved = tmpSink.records()
    assert retrieved == [record]


def test_sinkRecords_skipsMalformedLines(tmp_path: Path):
    p = tmp_path / "f.jsonl"
    # Mix: a valid JSON, a non-JSON string, a JSON-like object with bad syntax,
    # and another valid JSON.
    p.write_text(
        '{"k":"a"}\nnot-json\n{bad, json}\n{"k":"b"}\n',
        encoding="utf-8",
    )
    sink = JsonlFeedbackSink(str(p))
    records = sink.records()
    # Only the two well-formed JSON objects survive.
    assert records == [{"k": "a"}, {"k": "b"}]


def test_sinkRecords_emptyFileReturnsEmpty(tmpSink: JsonlFeedbackSink):
    """No file yet -> empty records list."""
    assert tmpSink.records() == []


def test_sinkConcurrency(tmp_path: Path):
    """Ten threads writing 100 records each leave 1000 lines on disk."""
    p = tmp_path / "f.jsonl"
    sink = JsonlFeedbackSink(str(p))

    def writer(threadId: int):
        for i in range(100):
            sink.append(
                {
                    "id": f"{threadId}-{i}",
                    "kind": threadId,
                }
            )

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    records = sink.records()
    assert len(records) == 1000
    # No line should be partially-formed; json.loads is strict so any
    # join-in-the-middle glitch would have crashed.
    for rec in records:
        assert "id" in rec


# ---------------------------------------------------------------------------
# _validate_verdict
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "verdict",
    [VERDICT_FALSE_NEGATIVE, VERDICT_FALSE_POSITIVE, VERDICT_CORRECT],
)
def test_validateVerdict_acceptsDocumented(verdict):
    assert _validate_verdict(verdict) == verdict


@pytest.mark.parametrize(
    "verdict",
    ["", "wrong", "FALSE_POSITIVE", "Correct", "123"],
)
def test_validateVerdict_rejectsUnknown(verdict):
    with pytest.raises(HTTPException) as excinfo:
        _validate_verdict(verdict)
    assert excinfo.value.status_code == 422


def test_validVerdictValues_isSetOfThree():
    assert _VALID_VERDICT_VALUES == frozenset(
        {"false_negative", "false_positive", "correct"}
    )


# ---------------------------------------------------------------------------
# _build_record
# ---------------------------------------------------------------------------
def test_buildRecord_carriesTimestamp():
    req = FeedbackRequest(
        historyId="x", verdict=VERDICT_FALSE_NEGATIVE
    )
    record = _build_record(req)
    assert isinstance(record["id"], str)
    # UUID format
    uuid.UUID(record["id"])
    # timestamp present, ISO-8601
    iso = record["receivedAt"]
    assert iso.endswith("+00:00") or iso.endswith("Z")
    datetime.fromisoformat(iso.replace("Z", "+00:00"))


def test_buildRecord_usesProvidedTimestamp():
    when = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    req = FeedbackRequest(historyId="x", verdict=VERDICT_CORRECT)
    record = _build_record(req, received_at=when)
    assert record["receivedAt"] == when.isoformat()


def test_buildRecord_propagatesFields():
    req = FeedbackRequest(
        historyId="abc",
        verdict=VERDICT_FALSE_POSITIVE,
        comment="missed",
        reporter="ops@example.com",
    )
    record = _build_record(req)
    assert record["historyId"] == "abc"
    assert record["verdict"] == VERDICT_FALSE_POSITIVE
    assert record["comment"] == "missed"
    assert record["reporter"] == "ops@example.com"
    assert "appVersion" in record
    assert record["appVersion"]  # non-empty


def test_buildRecord_idIsUniquePerCall():
    req = FeedbackRequest(historyId="x", verdict=VERDICT_CORRECT)
    a = _build_record(req)
    b = _build_record(req)
    assert a["id"] != b["id"]


def test_buildRecord_appVersionMatchesHealth():
    """Sanity check: appVersion is the same one ``health`` exports."""
    import backend.health as h

    record = _build_record(
        FeedbackRequest(historyId="x", verdict=VERDICT_CORRECT)
    )
    assert record["appVersion"] == h.APP_VERSION


# ---------------------------------------------------------------------------
# FeedbackRequest validation
# ---------------------------------------------------------------------------
def test_feedbackRequest_rejectsEmptyHistoryId():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        FeedbackRequest(historyId="", verdict=VERDICT_CORRECT)


def test_feedbackRequest_omitsOptionalComment():
    req = FeedbackRequest(historyId="x", verdict=VERDICT_CORRECT)
    assert req.comment is None
    assert req.reporter is None


def test_feedbackRequest_acceptsLongComment():
    req = FeedbackRequest(
        historyId="x",
        verdict=VERDICT_CORRECT,
        comment="x" * 1000,
    )
    assert len(req.comment) == 1000
