"""Model Drift Monitor — PSI-based feature drift detection.

Detects when the live feature distribution seen by the API diverges from
the distribution the XGBoost classifier was calibrated on.  Uses the
Population Stability Index (PSI), the standard banking/credit-risk drift
statistic, computed per feature over a rolling window of logged feature
vectors.

Zero-dependency and zero-cost by design: it reads only data produced by
PhishGuard itself (a JSONL feature log) — no external services, no keys.

Cold-start semantics
--------------------
There is no committed training-time baseline (the training dataset is not
distributed with the repository).  Instead the monitor bootstraps its own
reference window: once ``minSamples`` vectors have been recorded, the
oldest ``baselineSize`` rows are snapshotted to
``<dataDir>/driftBaseline.json`` and used as the expected distribution for
all subsequent evaluations.  Until then the monitor reports
``status="cold_start"``.

Usage
-----
>>> from backend.ml.drift import DriftMonitor, vectorFromFeatureSet
>>> monitor = DriftMonitor()
>>> monitor.record(vectorFromFeatureSet(featureSet))
>>> report = monitor.evaluate()
>>> report["overallStatus"]
'stable'
"""

from __future__ import annotations

import json
import math
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "FEATURE_NAMES",
    "PSI_THRESHOLDS",
    "DriftMonitor",
    "psi",
    "vectorFromFeatureSet",
]

# The exact 21-feature vector consumed by the XGBoost model.  Order matches
# backend/ml/models/modelMetadata.json.
FEATURE_NAMES: tuple[str, ...] = (
    "urlLength",
    "domainLength",
    "subdomainCount",
    "pathDepth",
    "hasIpAddress",
    "hasAtSymbol",
    "hasDoubleSlash",
    "hasDashInDomain",
    "hasUnderscoreInDomain",
    "isHttps",
    "hasPortNumber",
    "hasSuspiciousTld",
    "hasEncodedChars",
    "hasSuspiciousKeywords",
    "digitRatio",
    "specialCharCount",
    "queryParamCount",
    "hasValidMx",
    "usesCdn",
    "dnsRecordCount",
    "hasValidDns",
)

# Standard PSI interpretation bands.
PSI_THRESHOLDS = {"stable": 0.10, "moderate": 0.25}  # >= 0.25 -> significant


def _defaultDataDir() -> Path:
    """Resolve the runtime data directory (same home as the history DB)."""
    envDir = os.environ.get("PHISHGUARD_DATA_DIR")
    if envDir:
        return Path(envDir)
    return Path(__file__).resolve().parent.parent / "data"


def psi(expected: list[float], actual: list[float], bins: int = 10) -> float:
    """Population Stability Index between two samples of one feature.

    Bin edges are taken from quantiles of the *expected* sample so both
    distributions are measured against the same yardstick.  Zero counts are
    smoothed with an epsilon floor (standard practice) to keep the log term
    finite.
    """
    if not expected or not actual:
        return 0.0

    sortedExpected = sorted(expected)
    edges: list[float] = []
    for i in range(1, bins):
        idx = i * len(sortedExpected) // bins
        value = float(sortedExpected[min(idx, len(sortedExpected) - 1)])
        # Collapse duplicate quantile values (low-cardinality features such
        # as booleans produce many identical edges).
        if not edges or value > edges[-1]:
            edges.append(value)

    def _counts(sample: list[float]) -> list[int]:
        counts = [0] * (len(edges) + 1)
        for v in sample:
            placed = False
            for i, edge in enumerate(edges):
                if float(v) <= edge:
                    counts[i] += 1
                    placed = True
                    break
            if not placed:
                counts[-1] += 1
        return counts

    epsilon = 1e-6
    expCounts = _counts(expected)
    actCounts = _counts(actual)
    total = len(edges) + 1

    score = 0.0
    for i in range(total):
        e = max(expCounts[i] / len(expected), epsilon)
        a = max(actCounts[i] / len(actual), epsilon)
        score += (a - e) * math.log(a / e)
    return round(score, 6)


def buildBaseline(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a baseline document (per-feature samples) from raw vectors."""
    perFeature: dict[str, dict[str, list[float]]] = {}
    for name in FEATURE_NAMES:
        values = [
            float(r[name])
            for r in rows
            if isinstance(r.get(name), (int, float))
            and not (isinstance(r.get(name), float) and math.isnan(r[name]))
        ]
        perFeature[name] = {"values": values}
    return {
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "sampleCount": len(rows),
        "features": perFeature,
    }


class DriftMonitor:
    """Append-only feature log + PSI evaluation against a snapshotted baseline."""

    def __init__(
        self,
        dataDir: Optional[Path] = None,
        minSamples: int = 200,
        evaluationWindow: int = 100,
    ) -> None:
        dirPath = Path(dataDir) if dataDir else _defaultDataDir()
        self._logPath = dirPath / "featureLog.jsonl"
        self._baselinePath = dirPath / "driftBaseline.json"
        self._minSamples = minSamples
        self._evaluationWindow = evaluationWindow
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(self, vector: dict[str, Any]) -> None:
        """Append one feature vector to the JSONL log (best-effort)."""
        try:
            payload = {
                "features": {n: vector.get(n) for n in FEATURE_NAMES},
                "recordedAt": datetime.now(timezone.utc).isoformat(),
            }
            with self._lock:
                self._logPath.parent.mkdir(parents=True, exist_ok=True)
                with open(self._logPath, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(payload) + "\n")
        except OSError:
            # Monitoring must never break analysis; drop the sample silently.
            pass

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def _readLog(self) -> list[dict[str, Any]]:
        if not self._logPath.exists():
            return []
        rows: list[dict[str, Any]] = []
        try:
            with open(self._logPath, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue  # tolerate torn trailing writes
                        features = entry.get("features")
                        if isinstance(features, dict):
                            rows.append(features)
        except OSError:
            return []
        return rows

    def evaluate(self) -> dict[str, Any]:
        """Compute the current drift report.

        Returns a dict with:
          status      -- cold_start | ok | error
          overall     -- stable | moderate | significant (once ready)
          sampleCount -- rows available in the log
          baselineAt  -- ISO timestamp of the reference snapshot (if any)
          features    -- [{name, psi, status}] sorted by PSI descending
        """
        with self._lock:
            rows = self._readLog()

        report: dict[str, Any] = {
            "status": "ok",
            "overall": "stable",
            "sampleCount": len(rows),
            "baselineAt": None,
            "features": [],
        }

        if len(rows) < self._minSamples:
            report["status"] = "cold_start"
            return report

        baselineDoc: Optional[dict[str, Any]]
        try:
            baselineDoc = json.loads(self._baselinePath.read_text(encoding="utf-8"))
            if baselineDoc is not None and "features" in baselineDoc \
                    and "values" not in next(iter(baselineDoc["features"].values())):
                baselineDoc = None  # unexpected shape — rebuild below
        except (OSError, json.JSONDecodeError, StopIteration):
            baselineDoc = None

        if baselineDoc is None:
            # Bootstrap: freeze the oldest minSamples rows as the reference.
            snapshot = buildBaseline(rows[: self._minSamples])
            compact = {
                "createdAt": snapshot["createdAt"],
                "sampleCount": snapshot["sampleCount"],
                "features": {
                    name: {
                        "edges": [],  # edges derived at eval time from values
                        "values": bucket["values"],
                    }
                    for name, bucket in snapshot["features"].items()
                },
            }
            try:
                with self._lock:
                    self._baselinePath.write_text(
                        json.dumps(compact), encoding="utf-8"
                    )
            except OSError:
                pass  # still usable in-memory this run
            baselineDoc = compact

        recent = rows[-self._evaluationWindow :]
        results: list[dict[str, Any]] = []
        for name in FEATURE_NAMES:
            baseVals = baselineDoc["features"].get(name, {}).get("values", [])
            actualVals = [
                float(r[name])
                for r in recent
                if isinstance(r.get(name), (int, float))
                and not (
                    isinstance(r.get(name), float) and math.isnan(r[name])
                )
            ]
            score = psi(baseVals, actualVals) if baseVals else 0.0
            if score >= PSI_THRESHOLDS["moderate"]:
                level = "significant"
            elif score >= PSI_THRESHOLDS["stable"]:
                level = "moderate"
            else:
                level = "stable"
            results.append({"name": name, "psi": score, "status": level})

        results.sort(key=lambda item: item["psi"], reverse=True)
        worst = results[0]["status"] if results else "stable"
        report["features"] = results
        report["overall"] = worst
        report["baselineAt"] = baselineDoc.get("createdAt")

        return report


def vectorFromFeatureSet(featureSet: Any) -> dict[str, Any]:
    """Flatten a FeatureSet into the raw 21-key model input vector."""
    urlF = featureSet.urlFeatures
    osintF = featureSet.osintFeatures
    return {
        "urlLength": urlF.urlLength,
        "domainLength": urlF.domainLength,
        "subdomainCount": urlF.subdomainCount,
        "pathDepth": urlF.pathDepth,
        "hasIpAddress": int(bool(urlF.hasIpAddress)),
        "hasAtSymbol": int(bool(urlF.hasAtSymbol)),
        "hasDoubleSlash": int(bool(urlF.hasDoubleSlash)),
        "hasDashInDomain": int(bool(urlF.hasDashInDomain)),
        "hasUnderscoreInDomain": int(bool(urlF.hasUnderscoreInDomain)),
        "isHttps": int(bool(urlF.isHttps)),
        "hasPortNumber": int(bool(urlF.hasPortNumber)),
        "hasSuspiciousTld": int(bool(urlF.hasSuspiciousTld)),
        "hasEncodedChars": int(bool(urlF.hasEncodedChars)),
        "hasSuspiciousKeywords": int(bool(urlF.hasSuspiciousKeywords)),
        "digitRatio": urlF.digitRatio,
        "specialCharCount": urlF.specialCharCount,
        "queryParamCount": urlF.queryParamCount,
        "hasValidMx": int(bool(osintF.hasValidMx)),
        "usesCdn": int(bool(osintF.usesCdn)),
        "dnsRecordCount": osintF.dnsRecordCount,
        "hasValidDns": int(bool(osintF.hasValidDns)),
    }


# ---------------------------------------------------------------------------
# Process-wide singleton (lazy; swappable in tests)
# ---------------------------------------------------------------------------

_monitor: Optional[DriftMonitor] = None
_monitorLock = threading.Lock()


def getMonitor() -> DriftMonitor:
    """Return the process-wide DriftMonitor, creating it on first use."""
    global _monitor
    with _monitorLock:
        if _monitor is None:
            _monitor = DriftMonitor()
        return _monitor


def setMonitor(monitor: Optional[DriftMonitor]) -> None:
    """Replace the process-wide monitor (used by tests and reset paths)."""
    global _monitor
    with _monitorLock:
        _monitor = monitor
