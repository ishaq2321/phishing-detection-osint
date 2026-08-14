"""
History Export Module (Tier 4 B)
================================

Pure serialization helpers for exporting the history store to CSV and
JSON.  Kept dependency-free of FastAPI so the format contract can be
unit-tested in isolation; the routes in ``router.py`` just call these
and wrap the result in a ``Response``.

CSV contract
------------

Columns (in order)::

    id,createdAt,contentType,content,isPhishing,threatLevel,
    confidenceScore,reasons,recommendation,osintDomain,
    osintReputationScore,analysisTimeMs

* ``reasons`` is a ``; ``-joined string (reasons are already
  human-readable prose, so the CSV stays greppable in Excel).
* ``content`` is the FULL original analysed payload -- a history
  export is meant for offline triage, so truncating it would defeat
  the purpose.  The ``csv`` module handles quoting/escaping.
* Rows are exported newest-first, matching the order of
  ``GET /api/history`` so the UI and the export tell the same story.

JSON contract
-------------

A JSON array of full history entries (``id``, ``content``,
``contentType``, ``response``, ``createdAt``), timestamps as ISO-8601
strings.  This is a lossless dump suitable for re-import or archive.

Both exporters are bounded by the history store's FIFO cap, so the
payload can never grow without limit.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Iterable

from .historyStore import HistoryEntry

# Column order is part of the public contract -- tests pin it.
CSV_COLUMNS: list[str] = [
    "id",
    "createdAt",
    "contentType",
    "content",
    "isPhishing",
    "threatLevel",
    "confidenceScore",
    "reasons",
    "recommendation",
    "osintDomain",
    "osintReputationScore",
    "analysisTimeMs",
]


def _rowFor(entry: HistoryEntry) -> list[str]:
    """Flatten one history entry into a CSV row (all strings)."""
    response = entry.response
    verdict = response.verdict
    osint = response.osint
    return [
        entry.id,
        entry.createdAt.isoformat(),
        entry.contentType,
        entry.content,
        "true" if verdict.isPhishing else "false",
        verdict.threatLevel,
        str(verdict.confidenceScore),
        "; ".join(verdict.reasons),
        verdict.recommendation,
        osint.domain if osint else "",
        str(osint.reputationScore) if osint else "",
        str(response.analysisTime),
    ]


def entriesToCsv(entries: Iterable[HistoryEntry]) -> str:
    """Serialize history entries to a CSV string (with header row)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for entry in entries:
        writer.writerow(_rowFor(entry))
    return buffer.getvalue()


def entriesToJson(entries: Iterable[HistoryEntry]) -> str:
    """Serialize history entries to a JSON array string (lossless).

    Timestamps are emitted as ISO-8601 strings so the payload is plain
    JSON (no Python ``datetime`` objects leak into the wire format).
    """
    payload = [
        entry.model_dump(mode="json")  # datetime -> ISO-8601 str
        for entry in entries
    ]
    return json.dumps(payload, ensure_ascii=False, indent=2)
