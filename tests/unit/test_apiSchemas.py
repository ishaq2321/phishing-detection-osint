"""
Unit Tests for API Schemas
==========================

Tests for Pydantic models in api.schemas module.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import pytest
from pydantic import ValidationError

from backend.api.schemas import (
    AnalysisResponse,
    AnalyzeRequest,
    EmailRequest,
    FeatureSummary,
    HealthResponse,
    OsintSummary,
    UrlRequest,
    VerdictResult,
)


class TestAnalyzeRequest:
    """Test AnalyzeRequest model validation."""

    def test_validRequest(self):
        """Valid request should pass validation."""
        req = AnalyzeRequest(content="https://example.com", contentType="url")
        assert req.content == "https://example.com"
        assert req.contentType == "url"

    def test_defaultContentTypeIsAuto(self):
        """Default content type should be 'auto'."""
        req = AnalyzeRequest(content="https://example.com")
        assert req.contentType == "auto"

    def test_emptyContentRaisesError(self):
        """Empty content should raise validation error."""
        with pytest.raises(ValidationError):
            AnalyzeRequest(content="")


class TestUrlRequest:
    """Test UrlRequest model validation."""

    def test_validUrlRequest(self):
        """Valid URL request should pass validation."""
        req = UrlRequest(url="https://example.com")
        assert req.url == "https://example.com"

    def test_emptyUrlRaisesError(self):
        """Empty URL should raise validation error."""
        with pytest.raises(ValidationError):
            UrlRequest(url="")


class TestEmailRequest:
    """Test EmailRequest model validation."""

    def test_validEmailRequest(self):
        """Valid email request should pass validation."""
        req = EmailRequest(
            content="Urgent: verify your account",
            subject="Account Verification",
            sender="noreply@example.com"
        )
        assert req.content == "Urgent: verify your account"
        assert req.subject == "Account Verification"
        assert req.sender == "noreply@example.com"

    def test_emptyContentRaisesError(self):
        """Empty email content should raise validation error."""
        with pytest.raises(ValidationError):
            EmailRequest(content="")


class TestVerdictResult:
    """Test VerdictResult model."""

    def test_validVerdict(self):
        """Valid verdict should pass validation."""
        verdict = VerdictResult(
            isPhishing=True,
            confidenceScore=0.85,
            threatLevel="dangerous",
            reasons=["IP address in URL"],
            recommendation="Block this content."
        )
        assert verdict.isPhishing is True
        assert verdict.confidenceScore == 0.85
        assert verdict.threatLevel == "dangerous"

    def test_confidenceScoreRange(self):
        """Confidence score must be between 0 and 1."""
        # Valid
        VerdictResult(
            isPhishing=False,
            confidenceScore=0.5,
            threatLevel="safe",
            reasons=[],
            recommendation="Safe"
        )

        # Invalid (too high)
        with pytest.raises(ValidationError):
            VerdictResult(
                isPhishing=True,
                confidenceScore=1.5,
                threatLevel="critical",
                reasons=[],
                recommendation="Block"
            )


class TestOsintSummary:
    """Test OsintSummary model."""

    def test_validOsintSummary(self):
        """Valid OSINT summary should pass validation."""
        summary = OsintSummary(
            domain="example.com",
            domainAgeDays=365,
            registrar="GoDaddy",
            isPrivate=False,
            hasValidDns=True,
            reputationScore=0.9,
            inBlacklists=False
        )
        assert summary.domain == "example.com"
        assert summary.domainAgeDays == 365

    def test_requiredDomainField(self):
        """Domain field is required."""
        with pytest.raises(ValidationError):
            OsintSummary()


class TestFeatureSummary:
    """Test FeatureSummary model."""

    def test_validFeatureSummary(self):
        """Valid feature summary should pass validation."""
        summary = FeatureSummary(
            urlFeatures=12,
            textFeatures=5,
            osintFeatures=8,
            totalRiskIndicators=3
        )
        assert summary.urlFeatures == 12
        assert summary.textFeatures == 5

    def test_defaultValues(self):
        """Default values should be zero."""
        summary = FeatureSummary()
        assert summary.urlFeatures == 0
        assert summary.textFeatures == 0


class TestAnalysisResponse:
    """Test AnalysisResponse model."""

    def test_validAnalysisResponse(self):
        """Valid analysis response should pass validation."""
        verdict = VerdictResult(
            isPhishing=True,
            confidenceScore=0.85,
            threatLevel="dangerous",
            reasons=["IP address"],
            recommendation="Block"
        )
        features = FeatureSummary(totalRiskIndicators=3)

        response = AnalysisResponse(
            success=True,
            verdict=verdict,
            features=features,
            analysisTime=1500.0
        )

        assert response.success is True
        assert response.verdict == verdict
        assert response.analysisTime == 1500.0


class TestHealthResponse:
    """Test HealthResponse model."""

    def test_validHealthResponse(self):
        """Valid health response should pass validation."""
        health = HealthResponse(
            status="healthy",
            version="1.0.0",
            services={"osint": True, "ml": True, "analyzer": True}
        )
        assert health.status == "healthy"
        assert health.version == "1.0.0"


class TestSchemaSerialization:
    """Test JSON serialization of schemas."""

    def test_verdictResultToJson(self):
        """VerdictResult should serialize to JSON."""
        verdict = VerdictResult(
            isPhishing=True,
            confidenceScore=0.85,
            threatLevel="dangerous",
            reasons=["IP address"],
            recommendation="Block"
        )
        json_data = verdict.model_dump()
        assert json_data["isPhishing"] is True
        assert json_data["confidenceScore"] == 0.85
