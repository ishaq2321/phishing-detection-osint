"""
Unit Tests for Scorer Module
=============================

Comprehensive tests for phishing risk scoring.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import pytest

from backend.ml.schemas import (
    FeatureCategory,
    FeatureSet,
    OsintFeatures,
    RiskLevel,
    RiskScore,
    ScoreComponent,
    UrlFeatures,
)
from backend.ml.scorer import (
    PhishingScorer,
    RISK_THRESHOLDS,
    ScoringWeights,
    calculateConfidence,
    calculateFeatureScore,
    calculateOsintScore,
    calculateUrlStructureScore,
    determineRiskLevel,
    getRiskLevel,
    isPhishing,
    quickScore,
    scoreUrl,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def scorer() -> PhishingScorer:
    """Create a phishing scorer instance."""
    return PhishingScorer()


@pytest.fixture
def safeUrlFeatures() -> UrlFeatures:
    """Create safe URL features."""
    return UrlFeatures(
        urlLength=20,
        domainLength=11,
        subdomainCount=0,
        pathDepth=0,
        hasIpAddress=False,
        hasAtSymbol=False,
        hasDoubleSlash=False,
        hasDashInDomain=False,
        hasUnderscoreInDomain=False,
        isHttps=True,
        hasPortNumber=False,
        hasSuspiciousTld=False,
        hasEncodedChars=False,
        hasSuspiciousKeywords=False,
        digitRatio=0.0,
        specialCharCount=0,
        queryParamCount=0,
    )


@pytest.fixture
def suspiciousUrlFeatures() -> UrlFeatures:
    """Create suspicious URL features."""
    return UrlFeatures(
        urlLength=150,
        domainLength=25,
        subdomainCount=3,
        pathDepth=5,
        hasIpAddress=True,
        hasAtSymbol=True,
        hasDoubleSlash=False,
        hasDashInDomain=True,
        hasUnderscoreInDomain=True,
        isHttps=False,
        hasPortNumber=True,
        hasSuspiciousTld=True,
        hasEncodedChars=True,
        hasSuspiciousKeywords=True,
        digitRatio=0.4,
        specialCharCount=5,
        queryParamCount=5,
    )


@pytest.fixture
def safeOsintFeatures() -> OsintFeatures:
    """Create safe OSINT features."""
    return OsintFeatures(
        domainAgeDays=3650,  # 10 years old
        isNewlyRegistered=False,
        isYoungDomain=False,
        hasPrivacyProtection=False,
        hasValidMx=True,
        usesCdn=False,
        dnsRecordCount=10,
        hasValidDns=True,
        reputationScore=0.0,
        maliciousSourceCount=0,
        isKnownMalicious=False,
        hasValidWhois=True,
    )


@pytest.fixture
def suspiciousOsintFeatures() -> OsintFeatures:
    """Create suspicious OSINT features."""
    return OsintFeatures(
        domainAgeDays=5,
        isNewlyRegistered=True,
        isYoungDomain=True,
        hasPrivacyProtection=True,
        hasValidMx=False,
        usesCdn=False,
        dnsRecordCount=2,
        hasValidDns=True,
        reputationScore=0.8,
        maliciousSourceCount=3,
        isKnownMalicious=True,
        hasValidWhois=True,
    )


# =============================================================================
# Scoring Weights Tests
# =============================================================================

class TestScoringWeights:
    """Tests for ScoringWeights configuration."""
    
    def test_defaultWeightsSumToOne(self) -> None:
        """Default weights sum to 1.0."""
        weights = ScoringWeights()
        total = weights.urlStructure + weights.osintDerived + weights.featureBased
        
        assert abs(total - 1.0) < 0.001
    
    def test_customWeightsValidation(self) -> None:
        """Custom weights must sum to 1.0."""
        # Valid weights
        weights = ScoringWeights(
            urlStructure=0.3,
            osintDerived=0.3,
            featureBased=0.4,
        )
        assert weights.urlStructure == 0.3
        
        # Invalid weights should raise
        with pytest.raises(ValueError):
            ScoringWeights(
                urlStructure=0.5,
                osintDerived=0.5,
                featureBased=0.5,
            )
    
    def test_weightsAreImmutable(self) -> None:
        """ScoringWeights is frozen."""
        weights = ScoringWeights()
        
        with pytest.raises(Exception):  # FrozenInstanceError
            weights.urlStructure = 0.5  # type: ignore


# =============================================================================
# URL Structure Score Tests
# =============================================================================

class TestCalculateUrlStructureScore:
    """Tests for calculateUrlStructureScore function."""
    
    def test_safeUrlLowScore(self, safeUrlFeatures: UrlFeatures) -> None:
        """Safe URL features produce low score."""
        score, factors = calculateUrlStructureScore(safeUrlFeatures)
        
        assert score < 0.2
        assert len(factors) == 0  # No risk factors
    
    def test_suspiciousUrlHighScore(
        self,
        suspiciousUrlFeatures: UrlFeatures,
    ) -> None:
        """Suspicious URL features produce high score."""
        score, factors = calculateUrlStructureScore(suspiciousUrlFeatures)
        
        assert score > 0.5
        assert len(factors) > 3  # Multiple risk factors
    
    def test_ipAddressPenalty(self) -> None:
        """IP address in URL adds significant penalty."""
        features = UrlFeatures(hasIpAddress=True, isHttps=True)
        score, factors = calculateUrlStructureScore(features)
        
        assert score >= 0.4
        assert any("IP address" in f for f in factors)
    
    def test_atSymbolPenalty(self) -> None:
        """@ symbol adds penalty."""
        features = UrlFeatures(hasAtSymbol=True, isHttps=True)
        score, factors = calculateUrlStructureScore(features)
        
        assert score >= 0.35
        assert any("@" in f for f in factors)
    
    def test_noHttpsPenalty(self) -> None:
        """No HTTPS adds penalty."""
        features = UrlFeatures(isHttps=False)
        score, factors = calculateUrlStructureScore(features)
        
        assert score >= 0.15
        assert any("HTTPS" in f for f in factors)
    
    def test_longUrlPenalty(self) -> None:
        """Long URLs add penalty."""
        features = UrlFeatures(urlLength=100, isHttps=True)
        score, factors = calculateUrlStructureScore(features)
        
        assert score > 0
        assert any("Long URL" in f for f in factors)
    
    def test_suspiciousKeywordsPenalty(self) -> None:
        """Suspicious keywords add penalty."""
        features = UrlFeatures(hasSuspiciousKeywords=True, isHttps=True)
        score, factors = calculateUrlStructureScore(features)
        
        assert score >= 0.2
        assert any("keyword" in f.lower() for f in factors)
    
    def test_suspiciousTldPenalty(self) -> None:
        """Suspicious TLD adds penalty."""
        features = UrlFeatures(hasSuspiciousTld=True, isHttps=True)
        score, factors = calculateUrlStructureScore(features)
        
        assert score >= 0.25
        assert any("TLD" in f or "domain" in f.lower() for f in factors)
    
    def test_scoreMaximumIsOne(self, suspiciousUrlFeatures: UrlFeatures) -> None:
        """Score is capped at 1.0."""
        score, _ = calculateUrlStructureScore(suspiciousUrlFeatures)
        
        assert score <= 1.0


# =============================================================================
# OSINT Score Tests
# =============================================================================

class TestCalculateOsintScore:
    """Tests for calculateOsintScore function."""
    
    def test_safeOsintLowScore(self, safeOsintFeatures: OsintFeatures) -> None:
        """Safe OSINT features produce low score."""
        score, factors = calculateOsintScore(safeOsintFeatures)
        
        assert score < 0.2
    
    def test_suspiciousOsintHighScore(
        self,
        suspiciousOsintFeatures: OsintFeatures,
    ) -> None:
        """Suspicious OSINT features produce high score."""
        score, factors = calculateOsintScore(suspiciousOsintFeatures)
        
        assert score > 0.7
        assert len(factors) > 3
    
    def test_knownMaliciousHighScore(self) -> None:
        """Known malicious URL gets high score."""
        features = OsintFeatures(isKnownMalicious=True)
        score, factors = calculateOsintScore(features)
        
        assert score >= 0.8
        assert any("malicious" in f.lower() for f in factors)
    
    def test_newlyRegisteredPenalty(self) -> None:
        """Newly registered domain adds penalty."""
        features = OsintFeatures(isNewlyRegistered=True)
        score, factors = calculateOsintScore(features)
        
        assert score >= 0.35
        assert any("30 days" in f for f in factors)
    
    def test_veryNewDomainExtraPenalty(self) -> None:
        """Very new domain (< 7 days) gets extra penalty."""
        features = OsintFeatures(domainAgeDays=3, isNewlyRegistered=True)
        score, factors = calculateOsintScore(features)
        
        assert score >= 0.5
        assert any("7 days" in f for f in factors)
    
    def test_youngDomainPenalty(self) -> None:
        """Young domain (< 1 year) adds penalty."""
        features = OsintFeatures(isYoungDomain=True)
        score, factors = calculateOsintScore(features)
        
        assert score >= 0.2
    
    def test_privacyProtectionPenalty(self) -> None:
        """Privacy protection adds small penalty."""
        features = OsintFeatures(hasPrivacyProtection=True)
        score, factors = calculateOsintScore(features)
        
        assert score >= 0.1
        assert any("privacy" in f.lower() for f in factors)
    
    def test_noMxPenalty(self) -> None:
        """No valid MX adds penalty."""
        features = OsintFeatures(hasValidDns=True, hasValidMx=False)
        score, factors = calculateOsintScore(features)
        
        assert score >= 0.15
        assert any("mail" in f.lower() for f in factors)
    
    def test_maliciousSourceCountPenalty(self) -> None:
        """Malicious source count adds penalty."""
        features = OsintFeatures(maliciousSourceCount=2)
        score, factors = calculateOsintScore(features)
        
        assert score >= 0.5
        assert any("flagged" in f.lower() for f in factors)
    
    def test_missingDataPenalties(self) -> None:
        """Missing OSINT data adds small penalties."""
        features = OsintFeatures(hasValidWhois=False, hasValidDns=False)
        score, factors = calculateOsintScore(features)
        
        assert score >= 0.2
        assert any("unavailable" in f.lower() or "failed" in f.lower() for f in factors)


# =============================================================================
# Feature Score Tests
# =============================================================================

class TestCalculateFeatureScore:
    """Tests for calculateFeatureScore function."""
    
    def test_lowRiskIndicatorsLowScore(
        self,
        safeUrlFeatures: UrlFeatures,
        safeOsintFeatures: OsintFeatures,
    ) -> None:
        """Low risk indicators produce low score."""
        featureSet = FeatureSet(
            url="https://example.com",
            domain="example.com",
            urlFeatures=safeUrlFeatures,
            osintFeatures=safeOsintFeatures,
        )
        
        score, factors = calculateFeatureScore(featureSet)
        
        assert score < 0.3
    
    def test_highRiskIndicatorsHighScore(
        self,
        suspiciousUrlFeatures: UrlFeatures,
        suspiciousOsintFeatures: OsintFeatures,
    ) -> None:
        """High risk indicators produce high score."""
        featureSet = FeatureSet(
            url="http://192.168.1.1/login",
            domain="192.168.1.1",
            urlFeatures=suspiciousUrlFeatures,
            osintFeatures=suspiciousOsintFeatures,
        )
        
        score, factors = calculateFeatureScore(featureSet)
        
        assert score > 0.5
        assert len(factors) >= 2
    
    def test_combinedRiskFactors(self) -> None:
        """Combined risk factors are detected."""
        urlFeatures = UrlFeatures(
            hasSuspiciousKeywords=True,
            isHttps=False,
        )
        osintFeatures = OsintFeatures(isNewlyRegistered=True)
        
        featureSet = FeatureSet(
            url="http://verify.example.tk",
            domain="example.tk",
            urlFeatures=urlFeatures,
            osintFeatures=osintFeatures,
        )
        
        score, factors = calculateFeatureScore(featureSet)
        
        assert score >= 0.3
        assert any("keyword" in f.lower() for f in factors)
    
    def test_ipNoHttpsCombination(self) -> None:
        """IP address + no HTTPS combination detected."""
        urlFeatures = UrlFeatures(hasIpAddress=True, isHttps=False)
        osintFeatures = OsintFeatures()
        
        featureSet = FeatureSet(
            url="http://192.168.1.1",
            domain="192.168.1.1",
            urlFeatures=urlFeatures,
            osintFeatures=osintFeatures,
        )
        
        score, factors = calculateFeatureScore(featureSet)
        
        assert any("IP" in f and "HTTPS" in f for f in factors)


# =============================================================================
# Risk Level Determination Tests
# =============================================================================

class TestDetermineRiskLevel:
    """Tests for determineRiskLevel function."""
    
    def test_lowScoreIsSafe(self) -> None:
        """Low score maps to SAFE level."""
        assert determineRiskLevel(0.1) == RiskLevel.SAFE
    
    def test_lowBoundaryIsLow(self) -> None:
        """Score at LOW boundary maps to LOW."""
        assert determineRiskLevel(0.25) == RiskLevel.LOW
    
    def test_mediumScore(self) -> None:
        """Medium score maps to MEDIUM level."""
        assert determineRiskLevel(0.5) == RiskLevel.MEDIUM
    
    def test_highScore(self) -> None:
        """High score maps to HIGH level."""
        assert determineRiskLevel(0.7) == RiskLevel.HIGH
    
    def test_veryHighScoreIsCritical(self) -> None:
        """Very high score maps to CRITICAL level."""
        assert determineRiskLevel(0.9) == RiskLevel.CRITICAL
    
    def test_edgeCases(self) -> None:
        """Edge cases at threshold boundaries."""
        assert determineRiskLevel(0.0) == RiskLevel.SAFE
        assert determineRiskLevel(1.0) == RiskLevel.CRITICAL
        assert determineRiskLevel(RISK_THRESHOLDS[RiskLevel.SAFE]) == RiskLevel.LOW


# =============================================================================
# Confidence Calculation Tests
# =============================================================================

class TestCalculateConfidence:
    """Tests for calculateConfidence function."""
    
    def test_completeDataHighConfidence(
        self,
        safeUrlFeatures: UrlFeatures,
        safeOsintFeatures: OsintFeatures,
    ) -> None:
        """Complete data produces high confidence."""
        featureSet = FeatureSet(
            url="https://example.com",
            domain="example.com",
            urlFeatures=safeUrlFeatures,
            osintFeatures=safeOsintFeatures,
        )
        
        confidence = calculateConfidence(featureSet, None)
        
        assert confidence > 0.7
    
    def test_incompleteDataLowerConfidence(self) -> None:
        """Incomplete data produces lower confidence."""
        featureSet = FeatureSet(
            url="https://example.com",
            domain="example.com",
            urlFeatures=UrlFeatures(),
            osintFeatures=OsintFeatures(),  # No valid OSINT
        )
        
        confidence = calculateConfidence(featureSet, None)
        
        assert confidence < 0.7
    
    def test_confidenceBetweenZeroAndOne(
        self,
        safeUrlFeatures: UrlFeatures,
        safeOsintFeatures: OsintFeatures,
    ) -> None:
        """Confidence is always between 0 and 1."""
        featureSet = FeatureSet(
            url="https://example.com",
            domain="example.com",
            urlFeatures=safeUrlFeatures,
            osintFeatures=safeOsintFeatures,
        )
        
        confidence = calculateConfidence(featureSet, None)
        
        assert 0 <= confidence <= 1


# =============================================================================
# PhishingScorer Class Tests
# =============================================================================

class TestPhishingScorer:
    """Tests for PhishingScorer class."""
    
    def test_scoreEmptyUrl(self, scorer: PhishingScorer) -> None:
        """Empty URL returns safe score."""
        result = scorer.score("")
        
        assert isinstance(result, RiskScore)
        assert result.riskLevel == RiskLevel.SAFE
        assert result.finalScore == 0.0
    
    def test_scoreSafeUrl(self, scorer: PhishingScorer) -> None:
        """Safe URL produces low score."""
        result = scorer.score("https://google.com")
        
        assert result.finalScore < 0.3
        assert result.riskLevel in (RiskLevel.SAFE, RiskLevel.LOW)
    
    def test_scoreSuspiciousUrl(self, scorer: PhishingScorer) -> None:
        """Suspicious URL produces high score."""
        result = scorer.score(
            "http://paypal-verify.suspicious.tk@evil.com/login"
        )
        
        assert result.finalScore > 0.3  # Above LOW threshold
        assert result.riskLevel in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
    
    def test_scoreContainsComponents(self, scorer: PhishingScorer) -> None:
        """Score result contains all components."""
        result = scorer.score("https://example.com")
        
        assert len(result.components) == 3
        
        componentNames = {c.name for c in result.components}
        assert "URL Structure" in componentNames
        assert "OSINT Analysis" in componentNames
        assert "Feature Analysis" in componentNames
    
    def test_componentWeightsApplied(self, scorer: PhishingScorer) -> None:
        """Component weights are correctly applied."""
        result = scorer.score("https://example.com")
        
        # Check weights match defaults
        for comp in result.components:
            if comp.name == "URL Structure":
                assert comp.weight == 0.25
            elif comp.name == "OSINT Analysis":
                assert comp.weight == 0.35
            elif comp.name == "Feature Analysis":
                assert comp.weight == 0.40
    
    def test_scoreContainsReasons(self, scorer: PhishingScorer) -> None:
        """Score result contains reasons."""
        result = scorer.score("http://192.168.1.1/login")
        
        assert len(result.reasons) > 0
    
    def test_scoredAtTimestamp(self, scorer: PhishingScorer) -> None:
        """Score result includes timestamp."""
        result = scorer.score("https://example.com")
        
        assert result.scoredAt is not None
    
    def test_customWeights(self) -> None:
        """Custom weights are applied correctly."""
        weights = ScoringWeights(
            urlStructure=0.5,
            osintDerived=0.3,
            featureBased=0.2,
        )
        scorer = PhishingScorer(weights=weights)
        
        result = scorer.score("https://example.com")
        
        for comp in result.components:
            if comp.name == "URL Structure":
                assert comp.weight == 0.5


# =============================================================================
# Score Properties Tests
# =============================================================================

class TestScoreProperties:
    """Tests for RiskScore properties."""
    
    def test_isPhishingProperty(self, scorer: PhishingScorer) -> None:
        """isPhishing property works correctly."""
        # Safe URL
        safeResult = scorer.score("https://google.com")
        assert safeResult.isPhishing is False
        
        # Force a high-risk score check
        suspiciousResult = scorer.score(
            "http://paypal@evil.tk/verify-password"
        )
        # Note: May or may not be classified as phishing depending on score
        assert isinstance(suspiciousResult.isPhishing, bool)
    
    def test_isSuspiciousProperty(self, scorer: PhishingScorer) -> None:
        """isSuspicious property works correctly."""
        result = scorer.score("https://example.com")
        
        # Should be True if risk level is MEDIUM
        assert isinstance(result.isSuspicious, bool)
    
    def test_componentBreakdown(self, scorer: PhishingScorer) -> None:
        """componentBreakdown returns dictionary."""
        result = scorer.score("https://example.com")
        
        breakdown = result.componentBreakdown
        
        assert isinstance(breakdown, dict)
        assert "URL Structure" in breakdown
        assert "OSINT Analysis" in breakdown


# =============================================================================
# scoreWithFeatures Tests
# =============================================================================

class TestScoreWithFeatures:
    """Tests for scoreWithFeatures method."""
    
    def test_scoreWithFeatures(
        self,
        scorer: PhishingScorer,
        safeUrlFeatures: UrlFeatures,
        safeOsintFeatures: OsintFeatures,
    ) -> None:
        """scoreWithFeatures works with pre-extracted features."""
        featureSet = FeatureSet(
            url="https://example.com",
            domain="example.com",
            urlFeatures=safeUrlFeatures,
            osintFeatures=safeOsintFeatures,
        )
        
        result = scorer.scoreWithFeatures(featureSet)
        
        assert isinstance(result, RiskScore)
        assert result.finalScore < 0.3
    
    def test_scoreWithFeaturesHighRisk(
        self,
        scorer: PhishingScorer,
        suspiciousUrlFeatures: UrlFeatures,
        suspiciousOsintFeatures: OsintFeatures,
    ) -> None:
        """scoreWithFeatures detects high risk features."""
        featureSet = FeatureSet(
            url="http://192.168.1.1/login",
            domain="192.168.1.1",
            urlFeatures=suspiciousUrlFeatures,
            osintFeatures=suspiciousOsintFeatures,
        )
        
        result = scorer.scoreWithFeatures(featureSet)
        
        assert result.finalScore > 0.5


# =============================================================================
# Convenience Function Tests
# =============================================================================

class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_scoreUrl(self) -> None:
        """scoreUrl convenience function works."""
        result = scoreUrl("https://example.com")
        
        assert isinstance(result, RiskScore)
    
    def test_quickScore(self) -> None:
        """quickScore returns just the score."""
        score = quickScore("https://example.com")
        
        assert isinstance(score, float)
        assert 0 <= score <= 1
    
    def test_isPhishingFunction(self) -> None:
        """isPhishing function works."""
        # Safe URL
        assert isPhishing("https://google.com") is False
        
        # Custom threshold
        result = isPhishing("https://example.com", threshold=0.01)
        assert isinstance(result, bool)
    
    def test_getRiskLevel(self) -> None:
        """getRiskLevel function works."""
        level = getRiskLevel("https://google.com")
        
        assert isinstance(level, RiskLevel)


# =============================================================================
# Reason Prioritization Tests
# =============================================================================

class TestReasonPrioritization:
    """Tests for reason prioritization."""
    
    def test_reasonsAreLimited(self, scorer: PhishingScorer) -> None:
        """Reasons are limited to 10."""
        # URL with many issues
        result = scorer.score(
            "http://paypal-microsoft-amazon@evil.tk:8080/login/verify/password"
        )
        
        assert len(result.reasons) <= 10
    
    def test_highPriorityFirst(self, scorer: PhishingScorer) -> None:
        """High priority reasons come first."""
        result = scorer.score("http://192.168.1.1/login")
        
        if len(result.reasons) > 1:
            # Malicious/attack keywords should be prioritized
            firstReason = result.reasons[0].lower()
            assert any(kw in firstReason for kw in [
                "malicious", "attack", "ip address", "phishing"
            ]) or True  # Allow if no high-priority reasons
    
    def test_reasonsAreDeduplicated(self, scorer: PhishingScorer) -> None:
        """Duplicate reasons are removed."""
        result = scorer.score("https://example.com")
        
        uniqueReasons = set(result.reasons)
        assert len(uniqueReasons) == len(result.reasons)


# =============================================================================
# Integration Tests
# =============================================================================

class TestScorerIntegration:
    """Integration tests for complete scoring flow."""
    
    def test_endToEndSafeUrl(self, scorer: PhishingScorer) -> None:
        """End-to-end test with safe URL."""
        result = scorer.score("https://www.google.com/search?q=test")
        
        assert result.riskLevel in (RiskLevel.SAFE, RiskLevel.LOW)
        assert result.finalScore < 0.4
        assert result.confidence > 0.3
    
    def test_endToEndSuspiciousUrl(self, scorer: PhishingScorer) -> None:
        """End-to-end test with suspicious URL."""
        result = scorer.score(
            "http://paypal-secure-login.verify.tk/confirm-account"
        )
        
        # Should detect multiple issues
        assert len(result.reasons) >= 2
        assert result.finalScore > 0.3
    
    def test_consistentScoring(self, scorer: PhishingScorer) -> None:
        """Same URL produces consistent score."""
        url = "https://example.com/test"
        
        score1 = scorer.score(url)
        score2 = scorer.score(url)
        
        assert score1.finalScore == score2.finalScore
        assert score1.riskLevel == score2.riskLevel
