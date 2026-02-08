"""
Unit Tests for ML Schemas Module
=================================

Comprehensive tests for ML Pydantic models and enumerations.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import pytest
from datetime import datetime

from backend.ml.schemas import (
    # Enumerations
    FeatureCategory,
    RiskLevel,
    # URL Features
    UrlFeatures,
    # OSINT Features
    OsintFeatures,
    # Combined Features
    FeatureSet,
    # Scoring Models
    ScoreComponent,
    RiskScore,
    # URL Analysis Models
    SuspiciousPattern,
    UrlAnalysisResult,
)


# =============================================================================
# Enumeration Tests
# =============================================================================

class TestEnumerations:
    """Tests for enumeration classes."""
    
    def test_riskLevelValues(self) -> None:
        """RiskLevel has expected values."""
        assert RiskLevel.SAFE == "safe"
        assert RiskLevel.LOW == "low"
        assert RiskLevel.MEDIUM == "medium"
        assert RiskLevel.HIGH == "high"
        assert RiskLevel.CRITICAL == "critical"
    
    def test_featureCategoryValues(self) -> None:
        """FeatureCategory has expected values."""
        assert FeatureCategory.URL_STRUCTURE == "url_structure"
        assert FeatureCategory.DOMAIN_ANALYSIS == "domain_analysis"
        assert FeatureCategory.OSINT_DERIVED == "osint_derived"
        assert FeatureCategory.REPUTATION == "reputation"


# =============================================================================
# UrlFeatures Tests
# =============================================================================

class TestUrlFeatures:
    """Tests for UrlFeatures model."""
    
    def test_defaultValues(self) -> None:
        """Default values are correct."""
        features = UrlFeatures()
        
        assert features.urlLength == 0
        assert features.domainLength == 0
        assert features.subdomainCount == 0
        assert features.pathDepth == 0
        assert features.hasIpAddress is False
        assert features.hasAtSymbol is False
        assert features.isHttps is False
        assert features.digitRatio == 0.0
    
    def test_setAllFields(self) -> None:
        """All fields can be set."""
        features = UrlFeatures(
            urlLength=100,
            domainLength=20,
            subdomainCount=2,
            pathDepth=3,
            hasIpAddress=True,
            hasAtSymbol=True,
            hasDoubleSlash=True,
            hasDashInDomain=True,
            hasUnderscoreInDomain=True,
            isHttps=True,
            hasPortNumber=True,
            hasSuspiciousTld=True,
            hasEncodedChars=True,
            hasSuspiciousKeywords=True,
            digitRatio=0.5,
            specialCharCount=5,
            queryParamCount=3,
        )
        
        assert features.urlLength == 100
        assert features.hasIpAddress is True
        assert features.digitRatio == 0.5
    
    def test_digitRatioValidation(self) -> None:
        """Digit ratio must be between 0 and 1."""
        # Valid
        features = UrlFeatures(digitRatio=0.5)
        assert features.digitRatio == 0.5
        
        # Invalid - below 0
        with pytest.raises(ValueError):
            UrlFeatures(digitRatio=-0.1)
        
        # Invalid - above 1
        with pytest.raises(ValueError):
            UrlFeatures(digitRatio=1.5)
    
    def test_suspiciousFeatureCountProperty(self) -> None:
        """suspiciousFeatureCount counts binary suspicious features."""
        # No suspicious features
        features = UrlFeatures()
        assert features.suspiciousFeatureCount == 0
        
        # Multiple suspicious features
        features = UrlFeatures(
            hasIpAddress=True,
            hasAtSymbol=True,
            hasSuspiciousTld=True,
        )
        assert features.suspiciousFeatureCount == 3
    
    def test_isHighlyStructuredProperty(self) -> None:
        """isHighlyStructured detects complex URLs."""
        # Simple URL
        features = UrlFeatures()
        assert features.isHighlyStructured is False
        
        # Complex - many subdomains
        features = UrlFeatures(subdomainCount=3)
        assert features.isHighlyStructured is True
        
        # Complex - deep path
        features = UrlFeatures(pathDepth=5)
        assert features.isHighlyStructured is True
        
        # Complex - many query params
        features = UrlFeatures(queryParamCount=4)
        assert features.isHighlyStructured is True


# =============================================================================
# OsintFeatures Tests
# =============================================================================

class TestOsintFeatures:
    """Tests for OsintFeatures model."""
    
    def test_defaultValues(self) -> None:
        """Default values are correct."""
        features = OsintFeatures()
        
        assert features.domainAgeDays is None
        assert features.isNewlyRegistered is False
        assert features.isYoungDomain is False
        assert features.hasPrivacyProtection is False
        assert features.hasValidMx is False
        assert features.reputationScore == 0.0
        assert features.isKnownMalicious is False
    
    def test_domainAgeDaysValidation(self) -> None:
        """Domain age days must be >= 0."""
        # Valid
        features = OsintFeatures(domainAgeDays=100)
        assert features.domainAgeDays == 100
        
        # Invalid
        with pytest.raises(ValueError):
            OsintFeatures(domainAgeDays=-1)
    
    def test_reputationScoreValidation(self) -> None:
        """Reputation score must be between 0 and 1."""
        # Valid
        features = OsintFeatures(reputationScore=0.5)
        assert features.reputationScore == 0.5
        
        # Invalid
        with pytest.raises(ValueError):
            OsintFeatures(reputationScore=1.5)
    
    def test_osintRiskIndicatorsProperty(self) -> None:
        """osintRiskIndicators counts risk factors."""
        # No risk factors
        features = OsintFeatures()
        assert features.osintRiskIndicators == 0
        
        # Multiple risk factors
        features = OsintFeatures(
            isNewlyRegistered=True,
            hasPrivacyProtection=True,
            isKnownMalicious=True,
        )
        assert features.osintRiskIndicators >= 3
    
    def test_dataCompletenessProperty(self) -> None:
        """dataCompleteness reflects data quality."""
        # No valid data
        features = OsintFeatures()
        assert features.dataCompleteness < 1.0
        
        # Complete data
        features = OsintFeatures(
            hasValidWhois=True,
            hasValidDns=True,
        )
        assert features.dataCompleteness == 1.0


# =============================================================================
# FeatureSet Tests
# =============================================================================

class TestFeatureSet:
    """Tests for FeatureSet model."""
    
    def test_requiredFields(self) -> None:
        """Required fields must be provided."""
        # Valid
        featureSet = FeatureSet(
            url="https://example.com",
            domain="example.com",
        )
        assert featureSet.url == "https://example.com"
        
        # Missing url
        with pytest.raises(ValueError):
            FeatureSet(domain="example.com")  # type: ignore
    
    def test_defaultSubModels(self) -> None:
        """Default sub-models are created."""
        featureSet = FeatureSet(
            url="https://example.com",
            domain="example.com",
        )
        
        assert isinstance(featureSet.urlFeatures, UrlFeatures)
        assert isinstance(featureSet.osintFeatures, OsintFeatures)
    
    def test_customSubModels(self) -> None:
        """Custom sub-models can be provided."""
        urlFeatures = UrlFeatures(urlLength=100, isHttps=True)
        osintFeatures = OsintFeatures(domainAgeDays=1000)
        
        featureSet = FeatureSet(
            url="https://example.com",
            domain="example.com",
            urlFeatures=urlFeatures,
            osintFeatures=osintFeatures,
        )
        
        assert featureSet.urlFeatures.urlLength == 100
        assert featureSet.osintFeatures.domainAgeDays == 1000
    
    def test_totalRiskIndicatorsProperty(self) -> None:
        """totalRiskIndicators combines URL and OSINT indicators."""
        urlFeatures = UrlFeatures(
            hasIpAddress=True,
            hasAtSymbol=True,
        )
        osintFeatures = OsintFeatures(
            isNewlyRegistered=True,
            isKnownMalicious=True,
        )
        
        featureSet = FeatureSet(
            url="https://example.com",
            domain="example.com",
            urlFeatures=urlFeatures,
            osintFeatures=osintFeatures,
        )
        
        # URL: 2 + OSINT: 2+
        assert featureSet.totalRiskIndicators >= 4
    
    def test_hasCompleteDataProperty(self) -> None:
        """hasCompleteData reflects OSINT completeness."""
        # Incomplete
        featureSet = FeatureSet(
            url="https://example.com",
            domain="example.com",
        )
        assert featureSet.hasCompleteData is False
        
        # Complete
        featureSet = FeatureSet(
            url="https://example.com",
            domain="example.com",
            osintFeatures=OsintFeatures(
                hasValidWhois=True,
                hasValidDns=True,
            ),
        )
        assert featureSet.hasCompleteData is True
    
    def test_extractedAtTimestamp(self) -> None:
        """extractedAt is automatically set."""
        featureSet = FeatureSet(
            url="https://example.com",
            domain="example.com",
        )
        
        assert isinstance(featureSet.extractedAt, datetime)


# =============================================================================
# ScoreComponent Tests
# =============================================================================

class TestScoreComponent:
    """Tests for ScoreComponent model."""
    
    def test_requiredFields(self) -> None:
        """Required fields must be provided."""
        comp = ScoreComponent(
            name="Test",
            category=FeatureCategory.URL_STRUCTURE,
        )
        
        assert comp.name == "Test"
        assert comp.category == FeatureCategory.URL_STRUCTURE
    
    def test_defaultValues(self) -> None:
        """Default values are correct."""
        comp = ScoreComponent(
            name="Test",
            category=FeatureCategory.URL_STRUCTURE,
        )
        
        assert comp.rawScore == 0.0
        assert comp.weight == 0.0
        assert comp.factors == []
    
    def test_weightedScoreProperty(self) -> None:
        """weightedScore is calculated correctly."""
        comp = ScoreComponent(
            name="Test",
            rawScore=0.8,
            weight=0.25,
            category=FeatureCategory.URL_STRUCTURE,
        )
        
        assert comp.weightedScore == 0.2  # 0.8 * 0.25
    
    def test_scoreValidation(self) -> None:
        """Scores must be between 0 and 1."""
        # Valid
        comp = ScoreComponent(
            name="Test",
            rawScore=0.5,
            weight=0.5,
            category=FeatureCategory.URL_STRUCTURE,
        )
        assert comp.rawScore == 0.5
        
        # Invalid rawScore
        with pytest.raises(ValueError):
            ScoreComponent(
                name="Test",
                rawScore=1.5,
                category=FeatureCategory.URL_STRUCTURE,
            )
    
    def test_factorsList(self) -> None:
        """Factors list works correctly."""
        comp = ScoreComponent(
            name="Test",
            category=FeatureCategory.URL_STRUCTURE,
            factors=["Factor 1", "Factor 2"],
        )
        
        assert len(comp.factors) == 2
        assert "Factor 1" in comp.factors


# =============================================================================
# RiskScore Tests
# =============================================================================

class TestRiskScore:
    """Tests for RiskScore model."""
    
    def test_requiredFields(self) -> None:
        """Required fields must be provided."""
        score = RiskScore(
            url="https://example.com",
            domain="example.com",
        )
        
        assert score.url == "https://example.com"
        assert score.domain == "example.com"
    
    def test_defaultValues(self) -> None:
        """Default values are correct."""
        score = RiskScore(
            url="https://example.com",
            domain="example.com",
        )
        
        assert score.finalScore == 0.0
        assert score.riskLevel == RiskLevel.SAFE
        assert score.confidence == 0.0
        assert score.components == []
        assert score.reasons == []
    
    def test_isPhishingProperty(self) -> None:
        """isPhishing returns True for HIGH/CRITICAL."""
        # Safe
        score = RiskScore(
            url="https://example.com",
            domain="example.com",
            riskLevel=RiskLevel.SAFE,
        )
        assert score.isPhishing is False
        
        # High
        score = RiskScore(
            url="https://example.com",
            domain="example.com",
            riskLevel=RiskLevel.HIGH,
        )
        assert score.isPhishing is True
        
        # Critical
        score = RiskScore(
            url="https://example.com",
            domain="example.com",
            riskLevel=RiskLevel.CRITICAL,
        )
        assert score.isPhishing is True
    
    def test_isSuspiciousProperty(self) -> None:
        """isSuspicious returns True for MEDIUM."""
        # Medium
        score = RiskScore(
            url="https://example.com",
            domain="example.com",
            riskLevel=RiskLevel.MEDIUM,
        )
        assert score.isSuspicious is True
        
        # Not medium
        score = RiskScore(
            url="https://example.com",
            domain="example.com",
            riskLevel=RiskLevel.LOW,
        )
        assert score.isSuspicious is False
    
    def test_componentBreakdownProperty(self) -> None:
        """componentBreakdown returns dictionary."""
        comp1 = ScoreComponent(
            name="URL",
            rawScore=0.3,
            weight=0.25,
            category=FeatureCategory.URL_STRUCTURE,
        )
        comp2 = ScoreComponent(
            name="OSINT",
            rawScore=0.4,
            weight=0.35,
            category=FeatureCategory.OSINT_DERIVED,
        )
        
        score = RiskScore(
            url="https://example.com",
            domain="example.com",
            components=[comp1, comp2],
        )
        
        breakdown = score.componentBreakdown
        
        assert breakdown["URL"] == pytest.approx(0.075, abs=1e-9)  # 0.3 * 0.25
        assert breakdown["OSINT"] == pytest.approx(0.14, abs=1e-9)  # 0.4 * 0.35
    
    def test_reasonsLimitedToTen(self) -> None:
        """Reasons are limited to 10."""
        manyReasons = [f"Reason {i}" for i in range(20)]
        
        score = RiskScore(
            url="https://example.com",
            domain="example.com",
            reasons=manyReasons,
        )
        
        assert len(score.reasons) == 10
    
    def test_scoredAtTimestamp(self) -> None:
        """scoredAt is automatically set."""
        score = RiskScore(
            url="https://example.com",
            domain="example.com",
        )
        
        assert isinstance(score.scoredAt, datetime)


# =============================================================================
# SuspiciousPattern Tests
# =============================================================================

class TestSuspiciousPattern:
    """Tests for SuspiciousPattern model."""
    
    def test_requiredFields(self) -> None:
        """Required fields must be provided."""
        pattern = SuspiciousPattern(
            patternType="brand_impersonation",
            matchedValue="paypal",
            description="Potential PayPal impersonation",
        )
        
        assert pattern.patternType == "brand_impersonation"
        assert pattern.matchedValue == "paypal"
    
    def test_defaultSeverity(self) -> None:
        """Default severity is 0.5."""
        pattern = SuspiciousPattern(
            patternType="test",
            matchedValue="test",
            description="Test",
        )
        
        assert pattern.severity == 0.5
    
    def test_severityValidation(self) -> None:
        """Severity must be between 0 and 1."""
        # Valid
        pattern = SuspiciousPattern(
            patternType="test",
            matchedValue="test",
            severity=0.9,
            description="Test",
        )
        assert pattern.severity == 0.9
        
        # Invalid
        with pytest.raises(ValueError):
            SuspiciousPattern(
                patternType="test",
                matchedValue="test",
                severity=1.5,
                description="Test",
            )


# =============================================================================
# UrlAnalysisResult Tests
# =============================================================================

class TestUrlAnalysisResult:
    """Tests for UrlAnalysisResult model."""
    
    def test_requiredFields(self) -> None:
        """Required fields must be provided."""
        result = UrlAnalysisResult(
            url="https://example.com",
            domain="example.com",
        )
        
        assert result.url == "https://example.com"
        assert result.domain == "example.com"
    
    def test_defaultValues(self) -> None:
        """Default values are correct."""
        result = UrlAnalysisResult(
            url="https://example.com",
            domain="example.com",
        )
        
        assert result.scheme == "http"
        assert result.subdomain is None
        assert result.tld == ""
        assert result.path == ""
        assert result.query is None
        assert result.fragment is None
        assert result.suspiciousPatterns == []
        assert result.structuralScore == 0.0
        assert result.analysisNotes == []
    
    def test_patternCountProperty(self) -> None:
        """patternCount returns pattern count."""
        result = UrlAnalysisResult(
            url="https://example.com",
            domain="example.com",
            suspiciousPatterns=[
                SuspiciousPattern(
                    patternType="test",
                    matchedValue="test",
                    description="Test",
                ),
                SuspiciousPattern(
                    patternType="test2",
                    matchedValue="test2",
                    description="Test2",
                ),
            ],
        )
        
        assert result.patternCount == 2
    
    def test_maxPatternSeverityProperty(self) -> None:
        """maxPatternSeverity returns highest severity."""
        result = UrlAnalysisResult(
            url="https://example.com",
            domain="example.com",
            suspiciousPatterns=[
                SuspiciousPattern(
                    patternType="low",
                    matchedValue="low",
                    severity=0.3,
                    description="Low",
                ),
                SuspiciousPattern(
                    patternType="high",
                    matchedValue="high",
                    severity=0.9,
                    description="High",
                ),
            ],
        )
        
        assert result.maxPatternSeverity == 0.9
    
    def test_averagePatternSeverityProperty(self) -> None:
        """averagePatternSeverity calculates correctly."""
        result = UrlAnalysisResult(
            url="https://example.com",
            domain="example.com",
            suspiciousPatterns=[
                SuspiciousPattern(
                    patternType="a",
                    matchedValue="a",
                    severity=0.4,
                    description="A",
                ),
                SuspiciousPattern(
                    patternType="b",
                    matchedValue="b",
                    severity=0.6,
                    description="B",
                ),
            ],
        )
        
        assert result.averagePatternSeverity == 0.5
    
    def test_noPatternsZeroSeverity(self) -> None:
        """No patterns means zero severity."""
        result = UrlAnalysisResult(
            url="https://example.com",
            domain="example.com",
        )
        
        assert result.maxPatternSeverity == 0.0
        assert result.averagePatternSeverity == 0.0
    
    def test_analyzedAtTimestamp(self) -> None:
        """analyzedAt is automatically set."""
        result = UrlAnalysisResult(
            url="https://example.com",
            domain="example.com",
        )
        
        assert isinstance(result.analyzedAt, datetime)


# =============================================================================
# Serialization Tests
# =============================================================================

class TestSerialization:
    """Tests for model serialization."""
    
    def test_urlFeaturesJson(self) -> None:
        """UrlFeatures can be serialized to JSON."""
        features = UrlFeatures(urlLength=100, isHttps=True)
        
        data = features.model_dump()
        
        assert data["urlLength"] == 100
        assert data["isHttps"] is True
    
    def test_featureSetJson(self) -> None:
        """FeatureSet can be serialized to JSON."""
        featureSet = FeatureSet(
            url="https://example.com",
            domain="example.com",
        )
        
        data = featureSet.model_dump()
        
        assert data["url"] == "https://example.com"
        assert "urlFeatures" in data
        assert "osintFeatures" in data
    
    def test_riskScoreJson(self) -> None:
        """RiskScore can be serialized to JSON."""
        score = RiskScore(
            url="https://example.com",
            domain="example.com",
            finalScore=0.5,
            riskLevel=RiskLevel.MEDIUM,
        )
        
        data = score.model_dump()
        
        assert data["finalScore"] == 0.5
        assert data["riskLevel"] == "medium"
    
    def test_urlAnalysisResultJson(self) -> None:
        """UrlAnalysisResult can be serialized to JSON."""
        result = UrlAnalysisResult(
            url="https://example.com",
            domain="example.com",
            structuralScore=0.3,
        )
        
        data = result.model_dump()
        
        assert data["structuralScore"] == 0.3
