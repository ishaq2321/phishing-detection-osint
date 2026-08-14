"""
Unit tests for ``backend/api/historyExport.py`` (Tier 4 B).

Covers the serialization contract:

* CSV header row is the pinned column order
* CSV rows flatten verdict / osint fields correctly
* CSV escaping: commas, quotes, and newlines inside content
* reasons are joined with ``; ``
* JSON export is a lossless array dump with ISO-8601 timestamps
* empty store -> header-only CSV / empty JSON array
* ordering is newest-first (matches GET /api/history)
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from backend.api.historyExport import (
    CSV_COLUMNS,
    entriesToCsv,
    entriesToJson,
)
from backend.api.historyStore import HistoryEntry
from backend.api.schemas import (
    AnalysisResponse,
    FeatureSummary,
    OsintSummary,
    VerdictResult,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def makeEntry(
    *,
    content: str = "https://examp1e-login.tk/verify",
    contentType: str = "url",
    isPhishing: bool = True,
    threatLevel: str = "dangerous",
    confidenceScore: float = 0.87,
    reasons: list[str] | None = None,
    osintDomain: str = "examp1e-login.tk",
    osintScore: float = 0.15,
    createdAt: datetime | None = None,
) -> HistoryEntry:
    return HistoryEntry(
        content=content,
        contentType=contentType,
        response=AnalysisResponse(
            success=True,
            verdict=VerdictResult(
                isPhishing=isPhishing,
                confidenceScore=confidenceScore,
                threatLevel=threatLevel,
                reasons=reasons or ["Suspicious URL structure", "Recent domain"],
                recommendation="Do not interact.",
            ),
            osint=(
                OsintSummary(
                    domain=osintDomain,
                    reputationScore=osintScore,
                    domainAgeDays=12,
                    isPrivate=True,
                )
                if osintDomain
                else None
            ),
            features=FeatureSummary(totalRiskIndicators=5),
            analysisTime=1234.5,
        ),
        createdAt=createdAt or datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
    )


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def test_csv_header_row_is_pinned_column_order():
    out = entriesToCsv([])
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0] == CSV_COLUMNS
    assert len(rows) == 1  # header only


def test_csv_row_flattens_entry_fields():
    entry = makeEntry()
    rows = list(csv.DictReader(io.StringIO(entriesToCsv([entry]))))
    assert len(rows) == 1
    row = rows[0]
    assert row["id"] == entry.id
    assert row["contentType"] == "url"
    assert row["content"] == "https://examp1e-login.tk/verify"
    assert row["isPhishing"] == "true"
    assert row["threatLevel"] == "dangerous"
    assert row["confidenceScore"] == "0.87"
    assert row["reasons"] == "Suspicious URL structure; Recent domain"
    assert row["osintDomain"] == "examp1e-login.tk"
    assert row["osintReputationScore"] == "0.15"
    assert row["analysisTimeMs"] == "1234.5"


def test_csv_escapes_commas_quotes_and_newlines():
    entry = makeEntry(
        content='email, body "with quotes"\nand a second line',
    )
    out = entriesToCsv([entry])
    # Round-trip through the csv module: the escaping must be valid.
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[1][3] == 'email, body "with quotes"\nand a second line'


def test_csv_missing_osint_renders_empty_cells():
    entry = makeEntry(osintDomain="")
    rows = list(csv.DictReader(io.StringIO(entriesToCsv([entry]))))
    assert rows[0]["osintDomain"] == ""
    assert rows[0]["osintReputationScore"] == ""


def test_csv_safe_entry_false_flag():
    entry = makeEntry(isPhishing=False, threatLevel="safe", confidenceScore=0.12)
    rows = list(csv.DictReader(io.StringIO(entriesToCsv([entry]))))
    assert rows[0]["isPhishing"] == "false"


def test_csv_rows_newest_first():
    older = makeEntry(content="https://older.example", createdAt=datetime(2026, 1, 1, tzinfo=timezone.utc))
    newer = makeEntry(content="https://newer.example", createdAt=datetime(2026, 1, 2, tzinfo=timezone.utc))
    rows = list(csv.DictReader(io.StringIO(entriesToCsv([newer, older]))))
    assert [r["content"] for r in rows] == ["https://newer.example", "https://older.example"]


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def test_json_export_is_lossless_array():
    entry = makeEntry()
    payload = json.loads(entriesToJson([entry]))
    assert isinstance(payload, list)
    assert len(payload) == 1
    obj = payload[0]
    assert obj["id"] == entry.id
    assert obj["content"] == entry.content
    assert obj["contentType"] == "url"
    # ISO-8601 with UTC — pydantic emits a ``Z`` suffix for UTC.
    parsed = datetime.fromisoformat(obj["createdAt"].replace("Z", "+00:00"))
    assert parsed == datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    # Full nested response survives (lossless).
    assert obj["response"]["verdict"]["threatLevel"] == "dangerous"
    assert obj["response"]["osint"]["domain"] == "examp1e-login.tk"


def test_json_export_empty_store():
    assert entriesToJson([]) == "[]"


def test_json_export_no_datetime_leaks():
    payload = entriesToJson([makeEntry()])
    # Plain JSON: no Python repr artifacts.
    assert "datetime" not in payload
    json.loads(payload)  # must parse cleanly


# ---------------------------------------------------------------------------
# Ordering / determinism
# ---------------------------------------------------------------------------

def test_csv_and_json_agree_on_order():
    older = makeEntry(content="https://older.example", createdAt=datetime(2026, 1, 1, tzinfo=timezone.utc))
    newer = makeEntry(content="https://newer.example", createdAt=datetime(2026, 1, 2, tzinfo=timezone.utc))
    csvRows = list(csv.DictReader(io.StringIO(entriesToCsv([newer, older]))))
    jsonRows = json.loads(entriesToJson([newer, older]))
    assert [r["content"] for r in csvRows] == [o["content"] for o in jsonRows]
