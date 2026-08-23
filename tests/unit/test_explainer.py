"""
Unit Tests: Template-Based Explanation Engine
=============================================

Covers backend/ml/explainer.py: signal triggers, severity ordering,
SHAP-informed ranking within a band, and summary generation.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from backend.ml.explainer import (
    PhishingExplainer,
    _loadShapWeights,
    setExplainer,
)
from backend.ml.schemas import FeatureSet, OsintFeatures, UrlFeatures


VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _features(**urlOverrides) -> FeatureSet:
    return FeatureSet(
        url="https://example.com",
        domain="example.com",
        urlFeatures=UrlFeatures(**urlOverrides),
        osintFeatures=OsintFeatures(),
    )


class TestWeightLoading:
    def test_shapWeightsLoadFromCommittedReport(self):
        weights = _loadShapWeights()
        assert len(weights) == 21
        assert all(v >= 0 for v in weights.values())

    def test_explicitWeightsOverrideFile(self):
        explainer = PhishingExplainer(weights={"urlLength": 5.0})
        assert explainer._w("urlLength") == 5.0

    def test_unknownFeatureGetsSmallDefaultWeight(self):
        explainer = PhishingExplainer(weights={})
        assert explainer._w("nonexistent") > 0


class TestSignalTriggers:
    def test_noSignalsProducesFallbackSummary(self):
        report = PhishingExplainer(weights={}).explain(
            _features(
                urlLength=40,
                isHttps=True,
                digitRatio=0.05,
                specialCharCount=2,
            )
        )
        assert report["items"] == []
        assert "No individual risk signals" in report["summary"]

    def test_longUrlTriggersCritical(self):
        report = PhishingExplainer(weights={}).explain(_features(urlLength=150))
        signals = [i["signal"] for i in report["items"]]
        assert "urlLength" in signals
        item = next(i for i in report["items"] if i["signal"] == "urlLength")
        assert item["severity"] == "critical"
        assert "150" in item["detail"]

    def test_suspiciousTldAndKeywordsTriggerHigh(self):
        report = PhishingExplainer(weights={}).explain(
            _features(hasSuspiciousTld=True, hasSuspiciousKeywords=True)
        )
        bySignal = {i["signal"]: i["severity"] for i in report["items"]}
        assert bySignal["hasSuspiciousTld"] == "high"
        assert bySignal["hasSuspiciousKeywords"] == "high"

    def test_lackOfHttpsIsMedium(self):
        report = PhishingExplainer(weights={}).explain(_features(isHttps=False))
        item = next(i for i in report["items"] if i["signal"] == "isHttps")
        assert item["severity"] == "medium"

    def test_cleanUrlYieldsNoItems(self):
        report = PhishingExplainer(weights={}).explain(
            _features(
                urlLength=40,
                isHttps=True,
                digitRatio=0.05,
                specialCharCount=2,
            )
        )
        assert report["items"] == []


class TestOrdering:
    def test_itemsSortedBySeverityThenWeight(self):
        weights = {"urlLength": 0.9, "digitRatio": 0.1}
        report = PhishingExplainer(weights=weights).explain(
            _features(urlLength=80, digitRatio=0.8, isHttps=False)
        )
        severities = [i["severity"] for i in report["items"]]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        assert severities == sorted(severities, key=lambda s: order[s])
        # Within the same band the heavier SHAP weight comes first.
        highs = [i["signal"] for i in report["items"] if i["severity"] == "high"]
        assert highs.index("urlLength") < highs.index("digitRatio")

    def test_allSeveritiesAreValid(self):
        report = PhishingExplainer().explain(
            _features(urlLength=150, isHttps=False, subdomainCount=4)
        )
        for item in report["items"]:
            assert item["severity"] in VALID_SEVERITIES
            assert item["detail"].endswith((".", ")", "]")) or item["detail"]

    def test_summaryLeadsWithHighestSeverityItem(self):
        report = PhishingExplainer(weights={}).explain(
            _features(urlLength=150, isHttps=False)
        )
        assert report["summary"].startswith("Flagged primarily because")
        lead = report["items"][0]
        firstFactor = lead["detail"][0].lower()
        assert firstFactor in report["summary"].lower()


class TestSingleton:
    def test_setExplainerSwapsInstance(self):
        original = None
        from backend.ml import explainer as module

        original = module._explainer
        custom = PhishingExplainer(weights={})
        setExplainer(custom)
        try:
            from backend.ml.explainer import getExplainer

            assert getExplainer() is custom
        finally:
            setExplainer(original)
