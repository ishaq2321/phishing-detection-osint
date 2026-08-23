"""
Integration Tests: Explanation Field in Analysis Responses
==========================================================

Verifies through the real FastAPI app that:
- URL analyses carry a structured, severity-ordered explanation
- Non-URL analyses leave the explanation field as None (backward compatible)

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from osint import OsintData, WhoisResult, DnsResult, ReputationResult, LookupStatus


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
            creationDate=datetime.now() - timedelta(days=6),
            domainAgeDays=6,
        ),
        dns=DnsResult(domain=host, status=LookupStatus.SUCCESS),
        reputation=ReputationResult(
            domain=host,
            status=LookupStatus.SUCCESS,
            checks=[],
            aggregateScore=0.1,
        ),
    )


class TestExplanationInResponses:
    def test_urlAnalysisIncludesExplanation(self, client):
        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=_mockCollect,
        ):
            response = client.post(
                "/api/analyze",
                json={"content": "http://paypal-verify.tk/login", "contentType": "url"},
            )
            assert response.status_code == 200
            body = response.json()

            explanation = body["explanation"]
            assert explanation is not None
            assert explanation["summary"]
            assert isinstance(explanation["items"], list)
            for item in explanation["items"]:
                assert item["severity"] in {"critical", "high", "medium", "low"}
                assert item["signal"]
                assert item["detail"]

            # The fresh domain (6 days) must be surfaced as critical and
            # lead both the item list and the summary.
            top = explanation["items"][0]
            assert top["signal"] == "newlyRegisteredDomain"
            assert top["severity"] == "critical"
            assert explanation["summary"].startswith("Flagged primarily because")

    def test_textAnalysisHasNoExplanation(self, client):
        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=_mockCollect,
        ):
            response = client.post(
                "/api/analyze",
                json={
                    "content": "Urgent: verify your account now or it will be closed!",
                    "contentType": "text",
                },
            )
            assert response.status_code == 200
            body = response.json()
            assert body["success"] is True
            assert body["explanation"] is None

    def test_batchItemsCarryNoExplanationRegression(self, client):
        """The batch endpoint reuses single-item internals; ensure the
        added field does not break its schema."""
        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=_mockCollect,
        ):
            response = client.post(
                "/api/analyze/batch",
                json={"items": [{"type": "url", "url": "https://example.com"}]},
            )
            assert response.status_code == 200
