"""
Integration Tests: Drift Monitoring Endpoint and Orchestrator Hook
==================================================================

Verifies the full drift pipeline through the real FastAPI app:
- URL analyses append vectors to the JSONL feature log (orchestrator hook)
- GET /api/model/drift reports cold_start before enough samples exist
- GET /api/model/drift returns a full PSI report once bootstrapped
- /metrics exposes the phishguard_drift_* gauges after evaluation

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.ml.drift import DriftMonitor, FEATURE_NAMES, setMonitor
from osint import OsintData, WhoisResult, DnsResult, ReputationResult, LookupStatus


@pytest.fixture
def isolatedMonitor(tmp_path):
    """Point the process-wide monitor at an empty temp directory."""
    from backend.ml import drift as driftModule

    previous = driftModule._monitor
    monitor = DriftMonitor(dataDir=tmp_path, minSamples=30, evaluationWindow=10)
    setMonitor(monitor)
    yield monitor
    setMonitor(previous)


@pytest.fixture
def client():
    return TestClient(app)


def _mockCollect(domain, url=""):
    target = url or f"https://{domain}"
    host = target.split("//")[-1].split("/")[0]
    return OsintData(
        url=target,
        domain=host,
        whois=WhoisResult(
            domain=host,
            status=LookupStatus.SUCCESS,
            registrar="TestRegistrar",
            creationDate=datetime.now() - timedelta(days=400),
        ),
        dns=DnsResult(domain=host, status=LookupStatus.SUCCESS),
        reputation=ReputationResult(
            domain=host,
            status=LookupStatus.SUCCESS,
            checks=[],
            aggregateScore=0.1,
        ),
    )


class TestOrchestratorHook:
    def test_urlAnalysisAppendsToFeatureLog(self, client, isolatedMonitor):
        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=_mockCollect,
        ):
            before = isolatedMonitor.evaluate()["sampleCount"]
            response = client.post(
                "/api/analyze",
                json={"content": "https://example.com/login", "contentType": "url"},
            )
            assert response.status_code == 200
            assert response.json()["success"] is True

            after = isolatedMonitor.evaluate()["sampleCount"]
            assert after == before + 1

    def test_nonUrlContentIsNotLogged(self, client, isolatedMonitor):
        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=_mockCollect,
        ):
            before = isolatedMonitor.evaluate()["sampleCount"]
            response = client.post(
                "/api/analyze",
                json={
                    "content": "Your account will be suspended, click here!",
                    "contentType": "text",
                },
            )
            assert response.status_code == 200
            after = isolatedMonitor.evaluate()["sampleCount"]
            assert after == before


class TestDriftEndpoint:
    def test_coldStartBeforeEnoughSamples(self, client, isolatedMonitor):
        response = client.get("/api/model/drift")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "cold_start"
        assert body["features"] == []
        assert body["overall"] == "stable"

    def test_fullReportAfterBootstrap(self, client, isolatedMonitor):
        for i in range(isolatedMonitor._minSamples):
            isolatedMonitor.record({name: float(i % 5) for name in FEATURE_NAMES})

        report = client.get("/api/model/drift").json()
        assert report["status"] == "ok"
        assert len(report["features"]) == len(FEATURE_NAMES)
        top = report["features"][0]
        assert {"name", "psi", "status"} <= set(top.keys())
        assert report["baselineAt"] is not None

    def test_metricsExposeDriftGauges(self, client, isolatedMonitor):
        for i in range(isolatedMonitor._minSamples):
            isolatedMonitor.record({name: float(i % 5) for name in FEATURE_NAMES})
        client.get("/api/model/drift")

        metricsText = client.get("/metrics").text
        assert "phishguard_drift_psi" in metricsText
        assert "phishguard_drift_max_psi" in metricsText
