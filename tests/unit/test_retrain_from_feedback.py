"""
Unit tests for the Tier 4 J retrain-from-feedback bridge
(``backend.ml.training.retrainFromFeedback``).

Customers

* ``convert_feedback`` turns a JSONL feedback log + history store into a
  CSV whose header is exactly ``FEATURE_NAMES + label`` (the same schema as
  ``data/processed/features_raw.csv``), so the output concatenates with the
  original corpus and flows through ``prepareDataset`` unchanged.
* Label mapping: ``false_negative`` -> 1, ``false_positive`` -> 0,
  ``correct`` -> the original verdict.
* The 12 OSINT columns are emitted as NaN ("unknown") because live
  lookups are not re-run.
* Every skip path is counted, not silently dropped: missing history,
  non-URL content, unknown verdict, malformed line, missing log file.
"""

from __future__ import annotations

import csv
import json

import pytest

from backend.api.historyStore import HistoryStore
from backend.api.schemas import (
    AnalysisResponse,
    FeatureSummary,
    VerdictResult,
)
from backend.ml import OSINT_FEATURE_NAMES, URL_FEATURE_NAMES
from backend.ml.training.retrainFromFeedback import (
    DEFAULT_FEEDBACK_LOG,
    convert_feedback,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _response(isPhishing: bool) -> AnalysisResponse:
    return AnalysisResponse(
        success=True,
        verdict=VerdictResult(
            isPhishing=isPhishing,
            confidenceScore=0.9 if isPhishing else 0.1,
            threatLevel="critical" if isPhishing else "safe",
            reasons=["fixture"],
            recommendation="fixture",
        ),
        features=FeatureSummary(),
        analysisTime=1.0,
    )


def _populated_store() -> tuple[HistoryStore, dict[str, str]]:
    """Store with one phishing and one safe URL entry; returns ids."""
    store = HistoryStore()
    phish = store.add(
        content="https://paypal-secure-login.com/verify",
        contentType="url",
        response=_response(isPhishing=False),  # model missed it (FN case)
    )
    safe = store.add(
        content="https://example.com",
        contentType="url",
        response=_response(isPhishing=False),
    )
    return store, {"phish": phish.id, "safe": safe.id}


def _write_feedback(tmp_path, lines: list[str]) -> object:
    path = tmp_path / "feedback.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _record(historyId: str, verdict: str) -> str:
    return json.dumps(
        {
            "id": "feedback-id",
            "historyId": historyId,
            "verdict": verdict,
            "comment": None,
            "reporter": "tester",
            "receivedAt": "2026-08-14T00:00:00+00:00",
            "appVersion": "1.0.0",
        }
    )


def _read_csv(path) -> list[list[str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.reader(f))


def _is_numeric(value: str) -> bool:
    try:
        float(value)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Schema and label mapping
# ---------------------------------------------------------------------------

def test_headerMatchesFeaturesRawSchema(tmp_path):
    store, ids = _populated_store()
    logPath = _write_feedback(tmp_path, [_record(ids["safe"], "correct")])
    outCsv = tmp_path / "out.csv"
    summaryJson = tmp_path / "summary.json"

    summary = convert_feedback(logPath, outCsv, summaryJson, store)

    rows = _read_csv(outCsv)
    assert rows[0] == URL_FEATURE_NAMES + OSINT_FEATURE_NAMES + ["label"]
    assert len(rows[0]) == 29 + 1  # 17 URL + 12 OSINT + label
    assert summary["rowsWritten"] == 1


def test_labelMapping_perVerdict(tmp_path):
    store, ids = _populated_store()
    logPath = _write_feedback(
        tmp_path,
        [
            _record(ids["phish"], "false_negative"),  # -> 1
            _record(ids["safe"], "false_positive"),   # -> 0
            _record(ids["safe"], "correct"),          # -> 0 (original safe)
        ],
    )
    outCsv = tmp_path / "out.csv"

    convert_feedback(logPath, outCsv, tmp_path / "summary.json", store)

    rows = _read_csv(outCsv)
    labels = [r[-1] for r in rows[1:]]
    assert labels == ["1", "0", "0"]


def test_correctVerdictOnPhishingEntryKeepsPhishingLabel(tmp_path):
    store = HistoryStore()
    entry = store.add(
        content="https://phishy.example/login",
        contentType="url",
        response=_response(isPhishing=True),
    )
    logPath = _write_feedback(tmp_path, [_record(entry.id, "correct")])
    outCsv = tmp_path / "out.csv"

    convert_feedback(logPath, outCsv, tmp_path / "summary.json", store)

    rows = _read_csv(outCsv)
    assert rows[1][-1] == "1"


def test_osintColumnsAreNaN(tmp_path):
    store, ids = _populated_store()
    logPath = _write_feedback(tmp_path, [_record(ids["safe"], "correct")])
    outCsv = tmp_path / "out.csv"

    convert_feedback(logPath, outCsv, tmp_path / "summary.json", store)

    rows = _read_csv(outCsv)
    dataRow = rows[1]
    urlCount = len(URL_FEATURE_NAMES)
    osintValues = dataRow[urlCount:-1]  # before the label column
    assert len(osintValues) == len(OSINT_FEATURE_NAMES)
    assert all(v.lower() == "nan" for v in osintValues)


def test_urlFeaturesArePopulated(tmp_path):
    store, ids = _populated_store()
    logPath = _write_feedback(tmp_path, [_record(ids["safe"], "correct")])
    outCsv = tmp_path / "out.csv"

    convert_feedback(logPath, outCsv, tmp_path / "summary.json", store)

    rows = _read_csv(outCsv)
    urlValues = rows[1][: len(URL_FEATURE_NAMES)]
    # A bare https://example.com URL has a measurable urlLength > 0 and
    # no IP address, and every column is numeric (float-coerced, like
    # the original features_raw.csv).
    assert float(urlValues[0]) > 0  # urlLength
    assert urlValues[4] == "0.0"  # hasIpAddress (bool -> float)
    assert all(_is_numeric(v) for v in urlValues)


# ---------------------------------------------------------------------------
# Skip paths
# ---------------------------------------------------------------------------

def test_skipsMissingHistoryEntry(tmp_path):
    store, _ = _populated_store()
    logPath = _write_feedback(
        tmp_path, [_record("no-such-history-id", "false_negative")]
    )
    outCsv = tmp_path / "out.csv"

    summary = convert_feedback(logPath, outCsv, tmp_path / "summary.json", store)

    assert summary["recordsRead"] == 1
    assert summary["skippedNoHistory"] == 1
    assert summary["rowsWritten"] == 0


def test_skipsNonUrlContent(tmp_path):
    store = HistoryStore()
    entry = store.add(
        content="Dear customer, verify your account now",
        contentType="text",
        response=_response(isPhishing=False),
    )
    logPath = _write_feedback(tmp_path, [_record(entry.id, "false_positive")])
    outCsv = tmp_path / "out.csv"

    summary = convert_feedback(logPath, outCsv, tmp_path / "summary.json", store)

    assert summary["skippedNonUrl"] == 1
    assert summary["rowsWritten"] == 0


def test_skipsUnknownVerdict(tmp_path):
    store, ids = _populated_store()
    logPath = _write_feedback(
        tmp_path,
        [json.dumps({"historyId": ids["safe"], "verdict": "maybe"})],
    )
    outCsv = tmp_path / "out.csv"

    summary = convert_feedback(logPath, outCsv, tmp_path / "summary.json", store)

    assert summary["skippedUnknownVerdict"] == 1
    assert summary["rowsWritten"] == 0


def test_skipsMalformedLine(tmp_path):
    store, ids = _populated_store()
    logPath = _write_feedback(
        tmp_path,
        ["{not valid json", _record(ids["safe"], "correct")],
    )
    outCsv = tmp_path / "out.csv"

    summary = convert_feedback(logPath, outCsv, tmp_path / "summary.json", store)

    assert summary["malformedLines"] == 1
    assert summary["rowsWritten"] == 1  # the good line still lands


def test_missingLogFileWritesHeaderOnly(tmp_path):
    outCsv = tmp_path / "out.csv"
    summaryJson = tmp_path / "summary.json"

    summary = convert_feedback(
        tmp_path / "does-not-exist.jsonl", outCsv, summaryJson, HistoryStore()
    )

    assert summary["rowsWritten"] == 0
    rows = _read_csv(outCsv)
    assert len(rows) == 1  # header only
    assert rows[0][-1] == "label"


def test_summaryPersistedWithOutputPaths(tmp_path):
    store, ids = _populated_store()
    logPath = _write_feedback(tmp_path, [_record(ids["safe"], "correct")])
    outCsv = tmp_path / "out.csv"
    summaryJson = tmp_path / "summary.json"

    summary = convert_feedback(logPath, outCsv, summaryJson, store)

    with open(summaryJson, encoding="utf-8") as f:
        persisted = json.load(f)
    assert persisted == summary
    assert persisted["outputCsv"] == str(outCsv)
    assert persisted["labelSplit"] == {"0": 1, "1": 0}


def test_defaultFeedbackLogConstantPointsAtDataDir():
    """The bridge and the API must agree on where feedback lives."""
    assert DEFAULT_FEEDBACK_LOG.name == "feedback.jsonl"
    assert "data" in DEFAULT_FEEDBACK_LOG.parts
