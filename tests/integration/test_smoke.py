"""
End-to-End Smoke Tests
======================

Smoke tests to verify the complete system runs without errors.
These tests validate that the full pipeline works end-to-end
using the FastAPI test client with mocked OSINT dependencies.

Coverage:
- System health check
- Batch URL analysis (10 URLs)
- Batch email analysis (5 emails)
- Response format consistency
- Performance validation (< 5s per analysis)

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import time

import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

from backend.main import app
from osint import OsintData, WhoisResult, DnsResult, ReputationResult, LookupStatus


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def suspiciousMockOsint():
    """Mock OSINT data for a suspicious domain."""
    return OsintData(
        url="http://paypal-login-verify.tk/secure",
        domain="paypal-login-verify.tk",
        whois=WhoisResult(
            domain="paypal-login-verify.tk",
            status=LookupStatus.SUCCESS,
            registrar="Freenom",
            creationDate=datetime.now() - timedelta(days=3),
            registrantName="REDACTED FOR PRIVACY",
        ),
        dns=DnsResult(
            domain="paypal-login-verify.tk",
            status=LookupStatus.SUCCESS,
            records=[],
        ),
        reputation=ReputationResult(
            domain="paypal-login-verify.tk",
            status=LookupStatus.SUCCESS,
            checks=[],
            aggregateScore=0.75,
        ),
    )


# =============================================================================
# Sample Data
# =============================================================================

SAMPLE_URLS = [
    "https://www.google.com",
    "https://github.com/login",
    "https://www.amazon.com/gp/orders",
    "https://login.microsoftonline.com",
    "https://www.python.org/downloads",
    "http://paypal-secure-verify.tk/login",
    "http://microsoft-support-help.ml/account",
    "https://apple-id-verification.ga/signin",
    "http://bank-secure-update.xyz/login.php",
    "https://www.wikipedia.org/wiki/Phishing",
]

SAMPLE_EMAILS = [
    {
        "content": "Dear user, your account has been suspended. "
                   "Click here immediately to verify: http://verify-now.tk/login",
        "subject": "URGENT: Account Suspended",
        "sender": "security@paypa1.com",
    },
    {
        "content": "Hello, thank you for your recent purchase. "
                   "Your order #12345 has been shipped and will arrive by Friday.",
        "subject": "Order Confirmation",
        "sender": "orders@amazon.com",
    },
    {
        "content": "Your password will expire in 24 hours. "
                   "Update it immediately at http://microsoft-login.ml/reset "
                   "or you will lose access to all files.",
        "subject": "Password Expiration Notice",
        "sender": "admin@m1crosoft.com",
    },
    {
        "content": "Hi team, please review the quarterly report attached. "
                   "Let me know if you have any questions before the meeting.",
        "subject": "Q4 Report Review",
        "sender": "manager@company.com",
    },
    {
        "content": "Congratulations! You have won a $1,000,000 prize. "
                   "Claim now by sending your bank details to this address.",
        "subject": "You Won!!!",
        "sender": "winner@lotteryprize.xyz",
    },
]


# =============================================================================
# System Startup Smoke Tests
# =============================================================================

class TestSystemStartup:
    """Verify the system starts and basic endpoints respond."""

    def test_healthCheckReturnsHealthy(self, client):
        """Health endpoint returns healthy status with all services."""
        response = client.get("/api/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"
        assert data["services"]["osint"] is True
        assert data["services"]["ml"] is True
        assert data["services"]["analyzer"] is True

    def test_rootEndpointResponds(self, client):
        """Root endpoint returns API metadata."""
        response = client.get("/")

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Phishing Detection API"

    def test_apiRootEndpointResponds(self, client):
        """API root returns available endpoints."""
        response = client.get("/api/")

        assert response.status_code == 200
        data = response.json()
        assert "endpoints" in data

    def test_openApiSchemaAccessible(self, client):
        """OpenAPI JSON schema is generated and accessible."""
        response = client.get("/openapi.json")

        assert response.status_code == 200
        schema = response.json()
        assert "paths" in schema
        assert "/api/analyze" in schema["paths"]
        assert "/api/health" in schema["paths"]


# =============================================================================
# Batch URL Analysis Smoke Tests
# =============================================================================

class TestBatchUrlAnalysis:
    """Analyze 10 sample URLs — all must return valid JSON without crashing."""

    def _mockOsintForUrl(self, url):
        """Create a mock OSINT result tailored to the given URL."""
        from urllib.parse import urlparse
        parsed = urlparse(url if "://" in url else f"http://{url}")
        domain = parsed.netloc.lower().replace("www.", "")
        return OsintData(
            url=url,
            domain=domain,
            whois=WhoisResult(
                domain=domain,
                status=LookupStatus.SUCCESS,
                registrar="Test Registrar",
                creationDate=datetime.now() - timedelta(days=365),
            ),
            dns=DnsResult(
                domain=domain,
                status=LookupStatus.SUCCESS,
                records=[],
            ),
            reputation=ReputationResult(
                domain=domain,
                status=LookupStatus.SUCCESS,
                checks=[],
                aggregateScore=0.1,
            ),
        )

    def test_analyzeTenUrlsSuccessfully(self, client):
        """All 10 sample URLs produce valid analysis results."""
        async def mockCollect(domain, url=""):
            return self._mockOsintForUrl(url or f"https://{domain}")

        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=mockCollect,
        ):
            for url in SAMPLE_URLS:
                response = client.post(
                    "/api/analyze",
                    json={"content": url, "contentType": "url"},
                )

                assert response.status_code == 200, (
                    f"Failed for URL: {url}"
                )
                data = response.json()
                assert data["success"] is True, (
                    f"Analysis unsuccessful for: {url}"
                )

    @pytest.mark.parametrize("url", SAMPLE_URLS, ids=lambda u: u.split("//")[-1][:30])
    def test_eachUrlReturnsValidVerdict(self, client, url):
        """Each URL individually returns a structurally valid verdict."""
        async def mockCollect(domain, url=""):
            return self._mockOsintForUrl(url or f"https://{domain}")

        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=mockCollect,
        ):
            response = client.post(
                "/api/analyze",
                json={"content": url, "contentType": "url"},
            )

            data = response.json()
            verdict = data["verdict"]

            assert isinstance(verdict["isPhishing"], bool)
            assert 0.0 <= verdict["confidenceScore"] <= 1.0
            assert verdict["threatLevel"] in [
                "safe", "suspicious", "dangerous", "critical"
            ]
            assert isinstance(verdict["reasons"], list)
            assert isinstance(verdict["recommendation"], str)

    def test_urlAnalysisViaSpecificEndpoint(self, client):
        """POST /api/analyze/url endpoint works for all sample URLs."""
        async def mockCollect(domain, url=""):
            return self._mockOsintForUrl(url or f"https://{domain}")

        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=mockCollect,
        ):
            for url in SAMPLE_URLS:
                response = client.post(
                    "/api/analyze/url",
                    json={"url": url},
                )

                assert response.status_code == 200, (
                    f"/api/analyze/url failed for: {url}"
                )


# =============================================================================
# Batch Email Analysis Smoke Tests
# =============================================================================

class TestBatchEmailAnalysis:
    """Analyze 5 sample emails — all must return valid JSON without crashing."""

    @staticmethod
    def _mockOsintForDomain(domain):
        """Create mock OSINT for a given domain."""
        return OsintData(
            url=f"https://{domain}",
            domain=domain,
            whois=WhoisResult(
                domain=domain,
                status=LookupStatus.SUCCESS,
                registrar="Test Registrar",
                creationDate=datetime.now() - timedelta(days=365),
            ),
            dns=DnsResult(
                domain=domain,
                status=LookupStatus.SUCCESS,
                records=[],
            ),
            reputation=ReputationResult(
                domain=domain,
                status=LookupStatus.SUCCESS,
                checks=[],
                aggregateScore=0.1,
            ),
        )

    def test_analyzeFiveEmailsSuccessfully(self, client):
        """All 5 sample emails produce valid analysis results."""
        async def mockCollect(domain, url=""):
            return self._mockOsintForDomain(domain)

        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=mockCollect,
        ):
            for email in SAMPLE_EMAILS:
                response = client.post(
                    "/api/analyze/email",
                    json=email,
                )

                assert response.status_code == 200, (
                    f"Failed for email subject: {email['subject']}"
                )
                data = response.json()
                assert data["success"] is True, (
                    f"Analysis unsuccessful for: {email['subject']}"
                )

    @pytest.mark.parametrize(
        "email",
        SAMPLE_EMAILS,
        ids=lambda e: e["subject"][:25],
    )
    def test_eachEmailReturnsValidVerdict(self, client, email):
        """Each email individually returns a structurally valid verdict."""
        async def mockCollect(domain, url=""):
            return self._mockOsintForDomain(domain)

        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=mockCollect,
        ):
            response = client.post("/api/analyze/email", json=email)

        data = response.json()
        verdict = data["verdict"]

        assert isinstance(verdict["isPhishing"], bool)
        assert 0.0 <= verdict["confidenceScore"] <= 1.0
        assert verdict["threatLevel"] in [
            "safe", "suspicious", "dangerous", "critical"
        ]
        assert isinstance(verdict["reasons"], list)

    def test_emailAutoDetectionWorks(self, client):
        """Email content sent to /api/analyze with auto-detection works."""
        async def mockCollect(domain, url=""):
            return self._mockOsintForDomain(domain)

        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=mockCollect,
        ):
            for email in SAMPLE_EMAILS:
                content = f"From: {email['sender']}\nSubject: {email['subject']}\n\n{email['content']}"
                response = client.post(
                    "/api/analyze",
                    json={"content": content},
                )

                assert response.status_code == 200
                assert response.json()["success"] is True


# =============================================================================
# Response Format Consistency
# =============================================================================

class TestResponseFormatConsistency:
    """Verify all responses share the same JSON structure."""

    REQUIRED_TOP_KEYS = {"success", "verdict", "features", "analysisTime"}
    REQUIRED_VERDICT_KEYS = {
        "isPhishing", "confidenceScore", "threatLevel", "reasons", "recommendation"
    }
    REQUIRED_FEATURE_KEYS = {
        "urlFeatures", "textFeatures", "osintFeatures",
        "totalRiskIndicators", "detectedTactics"
    }

    def test_urlResponseFormatConsistency(self, client):
        """URL analysis responses have all required keys."""
        async def mockCollect(domain, url=""):
            from urllib.parse import urlparse
            parsed = urlparse(url if "://" in url else f"http://{url}")
            d = parsed.netloc.lower().replace("www.", "") or domain
            return OsintData(
                url=url or f"https://{domain}",
                domain=d,
                whois=WhoisResult(domain=d, status=LookupStatus.SUCCESS, registrar="Test",
                                  creationDate=datetime.now() - timedelta(days=365)),
                dns=DnsResult(domain=d, status=LookupStatus.SUCCESS, records=[]),
                reputation=ReputationResult(domain=d, status=LookupStatus.SUCCESS, checks=[], aggregateScore=0.1),
            )

        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=mockCollect,
        ):
            for url in SAMPLE_URLS[:3]:
                data = client.post(
                    "/api/analyze",
                    json={"content": url, "contentType": "url"},
                ).json()

                assert self.REQUIRED_TOP_KEYS.issubset(data.keys()), (
                    f"Missing top-level keys in response for {url}"
                )
                assert self.REQUIRED_VERDICT_KEYS.issubset(
                    data["verdict"].keys()
                ), f"Missing verdict keys for {url}"
                assert self.REQUIRED_FEATURE_KEYS.issubset(
                    data["features"].keys()
                ), f"Missing feature keys for {url}"

    def test_emailResponseFormatConsistency(self, client):
        """Email analysis responses have all required keys."""
        async def mockCollect(domain, url=""):
            return OsintData(
                url=url or f"https://{domain}", domain=domain,
                whois=WhoisResult(domain=domain, status=LookupStatus.SUCCESS, registrar="Test",
                                  creationDate=datetime.now() - timedelta(days=365)),
                dns=DnsResult(domain=domain, status=LookupStatus.SUCCESS, records=[]),
                reputation=ReputationResult(domain=domain, status=LookupStatus.SUCCESS, checks=[], aggregateScore=0.1),
            )

        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=mockCollect,
        ):
            for email in SAMPLE_EMAILS[:3]:
                data = client.post("/api/analyze/email", json=email).json()

            assert self.REQUIRED_TOP_KEYS.issubset(data.keys()), (
                f"Missing top-level keys for email: {email['subject']}"
            )
            assert self.REQUIRED_VERDICT_KEYS.issubset(
                data["verdict"].keys()
            ), f"Missing verdict keys for: {email['subject']}"
            assert self.REQUIRED_FEATURE_KEYS.issubset(
                data["features"].keys()
            ), f"Missing feature keys for: {email['subject']}"

    def test_analysisTimeIsPositive(self, client):
        """analysisTime is a positive number across all endpoints."""
        async def mockCollect(domain, url=""):
            return OsintData(
                url=url or f"https://{domain}", domain=domain,
                whois=WhoisResult(domain=domain, status=LookupStatus.SUCCESS, registrar="Test",
                                  creationDate=datetime.now() - timedelta(days=365)),
                dns=DnsResult(domain=domain, status=LookupStatus.SUCCESS, records=[]),
                reputation=ReputationResult(domain=domain, status=LookupStatus.SUCCESS, checks=[], aggregateScore=0.1),
            )

        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=mockCollect,
        ):
            # URL endpoint
            data = client.post(
                "/api/analyze", json={"content": "https://example.com"}
            ).json()
            assert data["analysisTime"] > 0

            # Email endpoint
            data = client.post(
                "/api/analyze/email",
                json={"content": "Test email body"},
            ).json()
            assert data["analysisTime"] > 0


# =============================================================================
# Performance Smoke Tests
# =============================================================================

class TestPerformance:
    """Each analysis completes within the 5-second budget."""

    MAX_SECONDS_PER_ANALYSIS = 5.0

    def test_urlAnalysisUnderFiveSeconds(self, client):
        """Every URL analysis finishes within 5 seconds."""
        async def mockCollect(domain, url=""):
            from urllib.parse import urlparse
            d = domain
            return OsintData(
                url=url or f"https://{d}", domain=d,
                whois=WhoisResult(domain=d, status=LookupStatus.SUCCESS, registrar="Test",
                                  creationDate=datetime.now() - timedelta(days=365)),
                dns=DnsResult(domain=d, status=LookupStatus.SUCCESS, records=[]),
                reputation=ReputationResult(domain=d, status=LookupStatus.SUCCESS, checks=[], aggregateScore=0.1),
            )

        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=mockCollect,
        ):
            for url in SAMPLE_URLS:
                start = time.time()
                response = client.post(
                    "/api/analyze",
                    json={"content": url, "contentType": "url"},
                )
                elapsed = time.time() - start

                assert response.status_code == 200
                assert elapsed < self.MAX_SECONDS_PER_ANALYSIS, (
                    f"URL analysis took {elapsed:.2f}s for {url} "
                    f"(limit: {self.MAX_SECONDS_PER_ANALYSIS}s)"
                )

    def test_emailAnalysisUnderFiveSeconds(self, client):
        """Every email analysis finishes within 5 seconds."""
        async def mockCollect(domain, url=""):
            return OsintData(
                url=url or f"https://{domain}", domain=domain,
                whois=WhoisResult(domain=domain, status=LookupStatus.SUCCESS, registrar="Test",
                                  creationDate=datetime.now() - timedelta(days=365)),
                dns=DnsResult(domain=domain, status=LookupStatus.SUCCESS, records=[]),
                reputation=ReputationResult(domain=domain, status=LookupStatus.SUCCESS, checks=[], aggregateScore=0.1),
            )

        with patch(
            "backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
            new_callable=AsyncMock,
            side_effect=mockCollect,
        ):
            for email in SAMPLE_EMAILS:
                start = time.time()
                response = client.post("/api/analyze/email", json=email)
                elapsed = time.time() - start

                assert response.status_code == 200
                assert elapsed < self.MAX_SECONDS_PER_ANALYSIS, (
                    f"Email analysis took {elapsed:.2f}s for '{email['subject']}' "
                    f"(limit: {self.MAX_SECONDS_PER_ANALYSIS}s)"
                )

    def test_healthCheckUnderOneSecond(self, client):
        """Health check responds in under 1 second."""
        start = time.time()
        response = client.get("/api/health")
        elapsed = time.time() - start

        assert response.status_code == 200
        assert elapsed < 1.0, f"Health check took {elapsed:.2f}s"
