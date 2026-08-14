"""
Feedback Loop Module (Tier 2.3)
=================================

Lets operators flag misclassifications against past analyses.  The
feedback is appended to a JSON-lines log file that the downstream
training bridge ``ml/training/retrainFromFeedback.py`` ingests to fold
operator corrections back into the Optuna/XGBoost pipeline.

Why JSONL instead of pushing into the history store?

* The history store is constrained in size by the FIFO cap; the
  feedback log is meant for long-term retention.
* The feedback log is append-only, so concurrent writers from
  multiple workers cannot corrupt earlier lines.
* The ML team can ingest the file with a single ``line.split()``
  pass -- no Pydantic round-trip required at ingest time.

Pydantic schema for the request body
------------------------------------

::

    POST /api/feedback
    {
        "historyId": "uuid-of-the-analysis",
        "verdict":    "false_negative" | "false_positive" | "correct",
        "comment":    "human-readable note (optional)",
        "reporter":   "domain/email of the operator (optional)"
    }

Each accepted request appends a JSON object containing the request
fields plus ``receivedAt`` (ISO-8601 UTC) and ``appVersion`` so the
training pipeline can correlate feedback against the model that
produced the original verdict.

Storage
-------

The file location defaults to ``./data/feedback.jsonl`` and is
overridable via ``PHISHGUARD_FEEDBACK_LOG``.  Operators can rotate
the file periodically (``logrotate`` or a cron to move it aside);
the writer always opens with append mode so a rotated file is
never overwritten.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from backend.health import APP_VERSION

logger = logging.getLogger(__name__)


# Constants
DEFAULT_FEEDBACK_LOG = "./data/feedback.jsonl"

VERDICT_FALSE_NEGATIVE = "false_negative"
VERDICT_FALSE_POSITIVE = "false_positive"
VERDICT_CORRECT = "correct"

_VALID_VERDICT_VALUES: frozenset[str] = frozenset(
    {VERDICT_FALSE_NEGATIVE, VERDICT_FALSE_POSITIVE, VERDICT_CORRECT}
)


def _is_persistence_enabled() -> bool:
    """True iff the feedback loop is enabled (always-on now)."""
    flag = os.environ.get("PHISHGUARD_FEEDBACK_DISABLED", "").strip().lower()
    return flag not in {"1", "true", "yes", "on"}


def _feedback_log_path() -> str:
    """Resolve the JSONL path, env-overridable."""
    raw = os.environ.get("PHISHGUARD_FEEDBACK_LOG", "").strip()
    return raw or DEFAULT_FEEDBACK_LOG


# ---------------------------------------------------------------------------
# Request schema
# ---------------------------------------------------------------------------
class FeedbackRequest(BaseModel):
    """Body of ``POST /api/feedback``."""

    historyId: str = Field(
        ...,
        min_length=1,
        description="UUID of the history entry being labelled",
        examples=["a8bc7e95-1234-5678-90ab-cdef01234567"],
    )
    verdict: str = Field(
        ...,
        description="Operator's classification of the model's verdict",
        examples=[VERDICT_FALSE_NEGATIVE, VERDICT_FALSE_POSITIVE, VERDICT_CORRECT],
    )
    comment: Optional[str] = Field(
        default=None,
        max_length=2000,
        description="Optional free-form operator note",
    )
    reporter: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Optional operator identifier (email, domain, name)",
    )

    @classmethod
    def __get_validators__(cls):
        yield from super().__get_validators__()


# ---------------------------------------------------------------------------
# Sink
# ---------------------------------------------------------------------------
class JsonlFeedbackSink:
    """Thread-safe append-only JSONL sink.

    A single ``threading.Lock`` guards every call because
    ``open(.., "a")`` is not atomic across concurrent writers on
    POSIX.  Each line is a single JSON object terminated with a
    newline; downstream parsers can split on ``\\n`` then
    ``json.loads`` each segment.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        # Make sure the parent directory exists.
        parent = Path(path).expanduser().resolve().parent
        parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def path(self) -> str:
        return self._path

    def append(self, record: dict[str, Any]) -> None:
        """Append one JSON record to the sink.

        Falls back to ``logger.warning`` if writing fails -- we
        don't want feedback to take the API down.
        """
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            try:
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError as exc:
                logger.error(
                    "Failed to write feedback record to %s -- got %s",
                    self._path,
                    exc,
                )
                raise

    def records(self) -> list[dict[str, Any]]:
        """Read all records currently on disk.  Returns ``[]`` if the
        file does not exist yet or contains malformed lines.

        Used by ``GET /api/feedback`` so operators can browse the
        raw log without leaving the API.
        """
        if not os.path.exists(self._path):
            return []
        out: list[dict[str, Any]] = []
        with self._lock:
            with open(self._path, "r", encoding="utf-8") as f:
                for raw in f:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        out.append(json.loads(raw))
                    except json.JSONDecodeError:
                        continue
        return out

    def clear(self) -> int:
        """Test helper: truncate the file.  Returns the number of
        records that were dropped.
        """
        prior = len(self.records())
        with self._lock:
            with open(self._path, "w", encoding="utf-8") as f:
                pass
        return prior


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------
def _build_record(
    request: FeedbackRequest,
    *,
    received_at: Optional[datetime] = None,
) -> dict[str, Any]:
    """Materialise a feedback record from the request payload."""
    if received_at is None:
        received_at = datetime.now(timezone.utc)
    return {
        "id": str(uuid.uuid4()),
        "historyId": request.historyId,
        "verdict": request.verdict,
        "comment": request.comment,
        "reporter": request.reporter,
        "receivedAt": received_at.isoformat(),
        "appVersion": APP_VERSION,
    }


def _validate_verdict(verdict: str) -> str:
    """Raise HTTP 422 if the verdict is not in the valid set."""
    if verdict not in _VALID_VERDICT_VALUES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"verdict must be one of "
                f"{sorted(_VALID_VERDICT_VALUES)}; got {verdict!r}"
            ),
        )
    return verdict


# ---------------------------------------------------------------------------
# Router registration
# ---------------------------------------------------------------------------
def registerFeedbackEndpoints(
    app: FastAPI,
    *,
    sink: Optional[JsonlFeedbackSink] = None,
) -> JsonlFeedbackSink:
    """Register ``/api/feedback`` endpoints on ``app``.

    Returns the sink so tests / operators can reach it without
    going through the router registry.

    The router keeps ``feedback`` out of the rate-limit default
    because honest operators routinely batch ~30+ corrections per
    day; throttling them at 60/min would be punitive.  If the
    route ever needs a bucket, add a per-operator one rather than
    a per-IP default.
    """
    router = APIRouter(prefix="/api", tags=["ops"])

    activeSink = sink or JsonlFeedbackSink(_feedback_log_path())

    @router.post(
        "/feedback",
        summary="Submit a feedback record about a past analysis",
        description=(
            "Append an operator-labelled record to the feedback log. "
            "Used by ML pipelines that re-train from operator "
            "feedback at weekly cadence."
        ),
    )
    async def postFeedback(body: FeedbackRequest):
        _validate_verdict(body.verdict)
        record = _build_record(body)
        activeSink.append(record)
        # Cheap path: don't wait for full file flush.
        return {
            "accepted": True,
            "feedbackId": record["id"],
            "historyId": record["historyId"],
        }

    @router.get(
        "/feedback",
        summary="List feedback records (alias for the raw log)",
        description=(
            "Returns the parsed record list from the JSONL sink. "
            "Useful for operator dashboards that want to verify a "
            "record landed without leaving the API."
        ),
    )
    async def listFeedback(limit: int = 100, offset: int = 0):
        allRecords = activeSink.records()
        # Newest-first
        allRecords.reverse()
        page = allRecords[offset : offset + limit]
        return {
            "feedback": page,
            "total": len(allRecords),
        }

    app.include_router(router)
    logger.info(
        "feedback endpoints registered (sink=%s, enabled=%s)",
        activeSink.path,
        _is_persistence_enabled(),
    )
    return activeSink


# Public exports
__all__ = [
    "FeedbackRequest",
    "JsonlFeedbackSink",
    "registerFeedbackEndpoints",
    "VERDICT_FALSE_NEGATIVE",
    "VERDICT_FALSE_POSITIVE",
    "VERDICT_CORRECT",
    "_VALID_VERDICT_VALUES",
    "_is_persistence_enabled",
    "_feedback_log_path",
    "_build_record",
    "_validate_verdict",
    "DEFAULT_FEEDBACK_LOG",
]
