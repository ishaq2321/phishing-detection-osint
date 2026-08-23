"""
Unit Tests: Model Drift Monitor
===============================

Covers the PSI statistic, baseline bootstrapping, cold-start semantics,
and the JSONL feature-log behaviour of backend/ml/drift.py.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import json
import math

import pytest

from backend.ml.drift import (
    FEATURE_NAMES,
    DriftMonitor,
    buildBaseline,
    psi,
    setMonitor,
    vectorFromFeatureSet,
)
from backend.ml.schemas import FeatureSet, OsintFeatures, UrlFeatures


# =============================================================================
# PSI Statistic
# =============================================================================

class TestPsiStatistic:
    def test_identicalDistributionsGiveNearZero(self):
        sample = [float(i % 10) for i in range(1000)]
        assert psi(sample, sample) < 0.001

    def test_sameDistributionDifferentSampleGivesSmallPsi(self):
        expected = [float(i % 10) for i in range(2000)]
        actual = [float(i % 10) for i in range(500)]
        assert psi(expected, actual) < 0.05

    def test_shiftedDistributionExceedsSignificantBand(self):
        expected = [float(i % 2) for i in range(1000)]          # 50/50 zeros/ones
        shifted = [1.0] * 1000                                  # all ones now
        score = psi(expected, shifted)
        assert score >= 0.25

    def test_moderateShiftLandsInModerateBand(self):
        expected = [float(i % 4) for i in range(800)]
        # Replace a quarter of the mass with the rarest value.
        actual = [float(i % 4) for i in range(600)] + [3.0] * 200
        score = psi(expected, actual)
        assert 0.0 <= score < 1.0

    def test_emptySamplesReturnZero(self):
        assert psi([], []) == 0.0
        assert psi([1.0], []) == 0.0
        assert psi([], [1.0]) == 0.0

    def test_booleanFeatureLowCardinalityDoesNotCrash(self):
        expected = [0.0, 1.0] * 500
        actual = [1.0] * 300
        score = psi(expected, actual)
        assert math.isfinite(score)


# =============================================================================
# Baseline Construction
# =============================================================================

class TestBuildBaseline:
    def test_includesAllFeatures(self):
        rows = [{n: float(i) for n in FEATURE_NAMES} for i in range(20)]
        doc = buildBaseline(rows)
        assert doc["sampleCount"] == 20
        assert set(doc["features"].keys()) == set(FEATURE_NAMES)

    def test_nanAndNoneValuesAreExcluded(self):
        row = {n: 1.0 for n in FEATURE_NAMES}
        row["urlLength"] = float("nan")
        row["digitRatio"] = None
        doc = buildBaseline([row] * 5)
        assert doc["features"]["urlLength"]["values"] == []
        assert doc["features"]["digitRatio"]["values"] == []
        assert len(doc["features"]["domainLength"]["values"]) == 5


# =============================================================================
# DriftMonitor Lifecycle
# =============================================================================

@pytest.fixture()
def monitor(tmp_path):
    """Fresh monitor with tiny thresholds for fast tests."""
    return DriftMonitor(
        dataDir=tmp_path,
        minSamples=40,
        evaluationWindow=20,
    )


def _vector(mutation: dict = None) -> dict:
    base = {
        "urlLength": 60.0,
        "domainLength": 15.0,
        "subdomainCount": 1.0,
        "pathDepth": 2.0,
        "hasIpAddress": 0.0,
        "hasAtSymbol": 0.0,
        "hasDoubleSlash": 0.0,
        "hasDashInDomain": 0.0,
        "hasUnderscoreInDomain": 0.0,
        "isHttps": 1.0,
        "hasPortNumber": 0.0,
        "hasSuspiciousTld": 0.0,
        "hasEncodedChars": 0.0,
        "hasSuspiciousKeywords": 0.0,
        "digitRatio": 0.1,
        "specialCharCount": 3.0,
        "queryParamCount": 1.0,
        "hasValidMx": 1.0,
        "usesCdn": 1.0,
        "dnsRecordCount": 5.0,
        "hasValidDns": 1.0,
    }
    base.update(mutation or {})
    return base


class TestDriftMonitorLifecycle:
    def test_coldStartBeforeMinSamples(self, tmp_path):
        monitor = DriftMonitor(dataDir=tmp_path, minSamples=100)
        for _ in range(50):
            monitor.record(_vector())
        report = monitor.evaluate()
        assert report["status"] == "cold_start"
        assert report["sampleCount"] == 50
        assert report["features"] == []

    @pytest.mark.asyncio
    async def test_bootstrapCreatesBaselineFile(self, monitor, tmp_path):
        for _ in range(monitor._minSamples):
            monitor.record(_vector())
        report = monitor.evaluate()
        assert report["status"] == "ok"
        baselinePath = tmp_path / "driftBaseline.json"
        assert baselinePath.exists()
        doc = json.loads(baselinePath.read_text())
        assert doc["sampleCount"] == monitor._minSamples
        assert len(report["features"]) == len(FEATURE_NAMES)

    def test_stableWhenWindowMatchesBaseline(self, monitor):
        for _ in range(monitor._minSamples + monitor._evaluationWindow):
            monitor.record(_vector())
        report = monitor.evaluate()
        assert report["status"] == "ok"
        assert report["overall"] in {"stable", "moderate"}

    def test_detectsSignificantDriftInRecentWindow(self, monitor):
        for _ in range(monitor._minSamples):
            monitor.record(_vector({"digitRatio": 0.1}))
        # Recent window: digitRatio jumps from 0.1 to 0.9 everywhere.
        for _ in range(monitor._evaluationWindow):
            monitor.record(_vector({"digitRatio": 0.9}))
        report = monitor.evaluate()
        top = report["features"][0]
        assert top["name"] == "digitRatio"
        assert top["psi"] >= 0.25
        assert top["status"] == "significant"
        assert report["overall"] == "significant"

    def test_tornTrailingJsonLineIsTolerated(self, monitor):
        for _ in range(monitor._minSamples + 5):
            monitor.record(_vector())
        with open(monitor._logPath, "a", encoding="utf-8") as fh:
            fh.write('{"features": {"urlLe')  # simulate torn write
        report = monitor.evaluate()
        assert report["sampleCount"] == monitor._minSamples + 5

    def test_recordNeverRaisesOnUnwritableDirectory(self, tmp_path):
        monitor = DriftMonitor(
            dataDir=tmp_path / "not" / "writable",
            minSamples=5,
        )
        # Simulate an unwritable location by pointing logPath at a file.
        monitor._logPath.parent.mkdir(parents=True)
        monitor._logPath.write_text("occupies-the-path")
        monitor.record(_vector())  # must not raise


# =============================================================================
# Vector Mapping
# =============================================================================

class TestVectorFromFeatureSet:
    def test_producesAll21KeysWithNumericValues(self):
        fs = FeatureSet(
            url="https://example.com",
            domain="example.com",
            urlFeatures=UrlFeatures(urlLength=42),
            osintFeatures=OsintFeatures(dnsRecordCount=7),
        )
        vector = vectorFromFeatureSet(fs)
        assert list(vector.keys()) == list(FEATURE_NAMES)
        assert all(isinstance(v, (int, float)) for v in vector.values())

    def test_booleanFieldsAreCoercedToInt(self):
        fs = FeatureSet(
            url="https://example.com",
            domain="example.com",
            urlFeatures=UrlFeatures(isHttps=True),
            osintFeatures=OsintFeatures(hasValidMx=True),
        )
        vector = vectorFromFeatureSet(fs)
        assert vector["isHttps"] == 1
        assert vector["hasValidMx"] == 1
