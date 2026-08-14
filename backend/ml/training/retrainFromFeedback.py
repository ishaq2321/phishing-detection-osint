"""
Retrain-From-Feedback Bridge (Tier 4 J)
=======================================

Reads the operator feedback log (JSONL, written by ``backend.api.feedback``)
and materialises a labelled feature matrix that the existing Optuna / XGBoost
pipeline can ingest.

Why this exists
---------------
Tier 2.3 added the feedback loop (``POST /api/feedback``) so operators can
flag misclassifications with three verdicts -- ``false_negative``,
``false_positive``, or ``correct``.  That loop is only half-closed until the
feedback can re-enter the training pipeline; this module is the other half.

Input
-----
The JSONL log at ``./data/feedback.jsonl`` (``PHISHGUARD_FEEDBACK_LOG``
overrides, matching ``backend/api/feedback.py``).  Each line is one record
as written by ``_build_record``::

    {"id": "...", "historyId": "...", "verdict": "false_negative",
     "comment": "...", "reporter": "...", "receivedAt": "...", ...}

Output
------
``data/processed/feedback_features.csv`` -- rows in exactly the same schema
as ``data/processed/features_raw.csv`` (``FEATURE_NAMES`` + ``label``), so
an operator can concatenate the two files and re-run ``prepareDataset`` +
``trainModel`` to fine-tune on human-verified misclassifications.

Label derivation
----------------
* ``false_negative`` -> 1  (operator: the model said safe, it was phishing)
* ``false_positive`` -> 0  (operator: the model said phishing, it was safe)
* ``correct``        -> the original verdict (operator confirms the model)

Feature extraction
------------------
The 17 URL structural features are re-extracted offline with
``extractUrlFeatures`` -- instant, deterministic, no network.  The 12 OSINT
features are emitted as NaN ("unknown"): live WHOIS / DNS / reputation is
*not* re-queried because (a) it is slow and rate-limited, and (b)
infrastructure data may have changed since the original analysis.  This is
the same convention ``backend/ml/training/extractFeatures.py`` already uses
("unavailable OSINT features are stored as NaN") and XGBoost handles NaN
natively.  The downstream ``prepareDataset`` drops zero-variance columns
exactly as it did for the original corpus, so the effective model input
schema (the 21 features in ``modelMetadata.json``) is preserved.

Entries that cannot contribute are skipped and counted in the summary:

* ``historyId`` not found in the history store (FIFO eviction / no
  persistence),
* content that is not URL-shaped (email/text verdicts come from the NLP
  pipeline, not the URL classifier),
* an unknown ``verdict`` value,
* malformed JSONL lines.

Usage::

    python -m backend.ml.training.retrainFromFeedback

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from __future__ import annotations

import csv
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

from backend.api.historyStore import HistoryStore, open_history_store
from backend.ml import OSINT_FEATURE_NAMES, URL_FEATURE_NAMES, extractUrlFeatures

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

PROJECT_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_FEEDBACK_LOG = PROJECT_ROOT / "data" / "feedback.jsonl"
DEFAULT_OUTPUT_CSV = PROJECT_ROOT / "data" / "processed" / "feedback_features.csv"
DEFAULT_SUMMARY_JSON = (
    PROJECT_ROOT / "data" / "processed" / "feedback_ingest_summary.json"
)

VERDICT_FALSE_NEGATIVE = "false_negative"
VERDICT_FALSE_POSITIVE = "false_positive"
VERDICT_CORRECT = "correct"

_VALID_VERDICTS = frozenset(
    {VERDICT_FALSE_NEGATIVE, VERDICT_FALSE_POSITIVE, VERDICT_CORRECT}
)

# Matches the orchestrator's bare-domain heuristic (no spaCy needed).
_BARE_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}(/.*)?$",
    re.IGNORECASE,
)


def _resolve_feedback_path() -> Path:
    """Resolve the feedback log path, honouring ``PHISHGUARD_FEEDBACK_LOG``
    so the bridge always reads the same file the API writes to."""
    raw = os.environ.get("PHISHGUARD_FEEDBACK_LOG", "").strip()
    return Path(raw) if raw else DEFAULT_FEEDBACK_LOG


# ============================================================================
# Helpers
# ============================================================================

def _looks_like_url(content: str) -> bool:
    """True when ``content`` is URL-shaped (protocol, www, or bare domain).

    Deliberately mirrors ``AnalysisOrchestrator._detectContentType`` without
    loading the NLP pipeline -- the URL classifier only retrains on URLs.
    """
    stripped = content.strip().lower()
    if stripped.startswith(("http://", "https://", "www.")):
        return True
    return bool(_BARE_DOMAIN_RE.match(stripped))


def _label_for_verdict(verdict: str, originalIsPhishing: bool) -> Optional[int]:
    """Map an operator verdict to a training label.

    ``false_negative`` corrects a miss -> phishing (1); ``false_positive``
    corrects a false alarm -> safe (0); ``correct`` confirms the model's own
    verdict.  Returns ``None`` for anything else (unknown verdict).
    """
    if verdict == VERDICT_FALSE_NEGATIVE:
        return 1
    if verdict == VERDICT_FALSE_POSITIVE:
        return 0
    if verdict == VERDICT_CORRECT:
        return 1 if originalIsPhishing else 0
    return None


def _build_feature_row(content: str) -> list[Any]:
    """Build one feature row for ``content``.

    The 17 URL features are re-extracted offline; the 12 OSINT features are
    NaN ("unknown") because live lookups are not re-run (see module
    docstring).  Raises if the URL cannot be parsed structurally.
    """
    urlFeatures = extractUrlFeatures(content)
    # Coerce to float, matching the numeric schema of features_raw.csv
    # (bools -> 0.0/1.0); pandas would otherwise read "True"/"False"
    # as object dtype and break the numeric cleaning steps.
    urlValues = [float(getattr(urlFeatures, name)) for name in URL_FEATURE_NAMES]
    osintUnknown = [float("nan")] * len(OSINT_FEATURE_NAMES)
    return urlValues + osintUnknown


# ============================================================================
# Core conversion
# ============================================================================

def convert_feedback(
    feedbackPath: Optional[Path] = None,
    outputCsv: Optional[Path] = None,
    summaryJson: Optional[Path] = None,
    store: Optional[HistoryStore] = None,
) -> dict[str, Any]:
    """Convert the feedback JSONL log into a labelled feature CSV.

    Args:
        feedbackPath: JSONL feedback log (default ``data/feedback.jsonl``).
        outputCsv: Destination CSV (default
            ``data/processed/feedback_features.csv``).
        summaryJson: Destination for the ingest summary
            (default ``data/processed/feedback_ingest_summary.json``).
        store: History store to resolve ``historyId`` -> content.  Defaults
            to ``open_history_store()`` (respects ``PHISHGUARD_PERSIST_HISTORY``).

    Returns:
        A summary dict with per-skip counters and the label split, which is
        also persisted as ``summaryJson``.  The CSV always carries the full
        ``FEATURE_NAMES + label`` header (possibly with zero data rows).
    """
    srcPath = Path(feedbackPath) if feedbackPath is not None else _resolve_feedback_path()
    csvPath = Path(outputCsv) if outputCsv is not None else DEFAULT_OUTPUT_CSV
    summaryPath = Path(summaryJson) if summaryJson is not None else DEFAULT_SUMMARY_JSON
    history = store if store is not None else open_history_store()

    summary: dict[str, Any] = {
        "feedbackPath": str(srcPath),
        "outputCsv": str(csvPath),
        "summaryJson": str(summaryPath),
        "recordsRead": 0,
        "malformedLines": 0,
        "rowsWritten": 0,
        "skippedNoHistory": 0,
        "skippedNonUrl": 0,
        "skippedUnknownVerdict": 0,
        "skippedFeatureExtraction": 0,
        "labelSplit": {"0": 0, "1": 0},
    }

    rows: list[list[Any]] = []

    if srcPath.exists():
        with open(srcPath, "r", encoding="utf-8") as logFile:
            for line in logFile:
                line = line.strip()
                if not line:
                    continue
                summary["recordsRead"] += 1

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    summary["malformedLines"] += 1
                    continue

                historyId = record.get("historyId")
                if not historyId:
                    summary["skippedNoHistory"] += 1
                    continue

                entry = history.get(historyId)
                if entry is None:
                    summary["skippedNoHistory"] += 1
                    continue

                label = _label_for_verdict(
                    record.get("verdict"),
                    entry.response.verdict.isPhishing,
                )
                if label is None:
                    summary["skippedUnknownVerdict"] += 1
                    continue

                if not _looks_like_url(entry.content):
                    summary["skippedNonUrl"] += 1
                    continue

                try:
                    featureRow = _build_feature_row(entry.content)
                except Exception:  # noqa: BLE001 -- one bad URL must not kill the run
                    summary["skippedFeatureExtraction"] += 1
                    continue

                rows.append(featureRow + [label])
                summary["labelSplit"][str(label)] += 1
    else:
        logger.warning("Feedback log not found: %s (writing header-only CSV)", srcPath)

    summary["rowsWritten"] = len(rows)

    fieldnames = URL_FEATURE_NAMES + OSINT_FEATURE_NAMES + ["label"]
    csvPath.parent.mkdir(parents=True, exist_ok=True)
    with open(csvPath, "w", newline="", encoding="utf-8") as csvFile:
        writer = csv.writer(csvFile)
        writer.writerow(fieldnames)
        writer.writerows(rows)

    summaryPath.parent.mkdir(parents=True, exist_ok=True)
    with open(summaryPath, "w", encoding="utf-8") as jsonFile:
        json.dump(summary, jsonFile, indent=2)

    return summary


# ============================================================================
# CLI
# ============================================================================

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s %(message)s",
        datefmt="%H:%M:%S",
    )

    summary = convert_feedback()

    logger.info("Feedback -> features: %d rows written -> %s",
                summary["rowsWritten"], summary["outputCsv"])
    for key in (
        "recordsRead",
        "skippedNoHistory",
        "skippedNonUrl",
        "skippedUnknownVerdict",
        "skippedFeatureExtraction",
        "malformedLines",
    ):
        logger.info("  %s: %d", key, summary[key])
    logger.info("  label split: %s", summary["labelSplit"])
    logger.info("  summary -> %s", summary["summaryJson"])


if __name__ == "__main__":
    main()
