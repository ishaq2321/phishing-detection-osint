"""
Integration Tests for ML Feature Extraction Pipeline
=====================================================

Tests the complete feature extraction workflow:
- URL analysis → OSINT data → Feature extraction → Scoring
- Feature aggregation and risk assessment
- End-to-end ML pipeline validation

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import pytest
from datetime import datetime, timedelta

from backend.ml import (
    FeatureExtractor,
    UrlAnalyzer,
    PhishingScorer,
    extractFeatures,
    analyzeUrl,
    scoreUrl,
    FeatureSet,
    RiskLevel,
)
from osint import (
    OsintData,
    WhoisResult,
    DnsResult,
    ReputationResult,
    LookupStatus,
    DnsRecord,
    DnsRecordType,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def legitOsintData():
    """OSINT data for a legitimate, established domain."""
    return OsintData(
        url="https://google.com",
        domain="google.com",
        whois=WhoisResult(
            domain="google.com",
            status=LookupStatus.SUCCESS,
            registrar="MarkMonitor Inc.",
            creationDate=datetime.now() - timedelta(days=7300),  # 20 years old
            expirationDate=datetime.now() + timedelta(days=365),
            registrantName="Google LLC",
            nameServers=["ns1.google.com", "ns2.google.com"]
        ),
        dns=DnsResult(
            domain="google.com",
            status=LookupStatus.SUCCESS,
            records=[
                DnsRecord(recordType=DnsRecordType.A, value="142.250.185.46", ttl=300),
                DnsRecord(recordType=DnsRecordType.MX, value="smtp.google.com", ttl=3600),
            ]
        ),
        reputation=ReputationResult(
            domain="google.com",
            status=LookupStatus.SUCCESS,
            checks=[],
            aggregateScore=0.0
        )
    )


@pytest.fixture
def suspiciousOsintData():
    """OSINT data for a suspicious, newly registered domain."""
    return OsintData(
        url="http://paypal-verify.tk/login",
        domain="paypal-verify.tk",
        whois=WhoisResult(
            domain="paypal-verify.tk",
            status=LookupStatus.SUCCESS,
            registrar="Unknown Registrar",
            creationDate=datetime.now() - timedelta(days=5),  # 5 days old
            expirationDate=datetime.now() + timedelta(days=30),
            registrantName="REDACTED FOR PRIVACY",
            nameServers=["ns1.freenom.com"]
        ),
        dns=DnsResult(
            domain="paypal-verify.tk",
            status=LookupStatus.SUCCESS,
            records=[
                DnsRecord(recordType=DnsRecordType.A, value="185.220.101.45", ttl=300),
            ]
        ),
        reputation=ReputationResult(
            domain="paypal-verify.tk",
            status=LookupStatus.SUCCESS,
            checks=[],
            aggregateScore=0.6
        )
    )


# =============================================================================
# Feature Extraction Integration Tests
# =============================================================================

class TestFeatureExtractionPipeline:
    """Test URL → OSINT → Features pipeline."""
    
    def test_extractFeaturesFromLegitUrl(self, legitOsintData):
        """Test feature extraction for legitimate URL with OSINT data."""
        url = "https://www.google.com/search?q=test"
        
        # Extract features
        extractor = FeatureExtractor()
        features = extractor.extract(url, osintData=legitOsintData)
        
        # Verify feature extraction
        assert features.url == url
        assert features.domain == "google.com"
        
        # URL features should show safe characteristics
        assert features.urlFeatures.isHttps is True
        assert features.urlFeatures.hasIpAddress is False
        assert features.urlFeatures.hasSuspiciousTld is False
        assert features.urlFeatures.suspiciousFeatureCount < 3
        
        # OSINT features should show established domain
        assert features.osintFeatures.domainAgeDays > 1000
        assert features.osintFeatures.isPrivate is False
        assert features.osintFeatures.hasValidDns is True
        assert features.osintFeatures.reputationScore < 0.3
        
        # Overall assessment
        assert features.hasCompleteData is True
        assert features.totalRiskIndicators < 5
    
    def test_extractFeaturesFromSuspiciousUrl(self, suspiciousOsintData):
        """Test feature extraction for suspicious URL with OSINT data."""
        url = "http://paypal-verify.tk/login?update=account"
        
        # Extract features
        extractor = FeatureExtractor()
        features = extractor.extract(url, osintData=suspiciousOsintData)
        
        # Verify feature extraction
        assert features.url == url
        assert features.domain == "paypal-verify.tk"
        
        # URL features should show suspicious characteristics
        assert features.urlFeatures.isHttps is False  # No HTTPS
        assert features.urlFeatures.hasSuspiciousTld is True  # .tk TLD
        assert features.urlFeatures.suspiciousKeywordCount > 0  # "login", "update"
        assert features.urlFeatures.suspiciousFeatureCount >= 3
        
        # OSINT features should show new domain
        assert features.osintFeatures.domainAgeDays < 30
        assert features.osintFeatures.isPrivate is True
        assert features.osintFeatures.reputationScore > 0.3
        
        # Overall assessment
        assert features.totalRiskIndicators >= 5
    
    def test_extractFeaturesWithoutOsint(self):
        """Test feature extraction works without OSINT data."""
        url = "https://example.com/page"
        
        extractor = FeatureExtractor()
        features = extractor.extract(url)
        
        # Should still extract URL features
        assert features.url == url
        assert features.domain == "example.com"
        assert features.urlFeatures.isHttps is True
        
        # OSINT features should be defaults
        assert features.osintFeatures.domainAgeDays is None
        assert features.osintFeatures.reputationScore == 0.0
        
        # Incomplete data
        assert features.hasCompleteData is False


class TestUrlAnalysisIntegration:
    """Test URL analyzer integration with feature extraction."""
    
    def test_urlAnalysisWithFeatureExtraction(self):
        """Test URL analysis integrated with feature extraction."""
        url = "http://paypal-verify.tk/login"
        
        # Analyze URL structure
        analyzer = UrlAnalyzer()
        urlAnalysis = analyzer.analyze(url)
        
        # Extract features
        extractor = FeatureExtractor()
        features = extractor.extract(url)
        
        # URL analysis should detect brand impersonation
        assert urlAnalysis.patternCount > 0
        brandPatterns = [p for p in urlAnalysis.suspiciousPatterns 
                        if "paypal" in p.matchedValue.lower()]
        assert len(brandPatterns) > 0
        
        # Features should reflect suspicious patterns
        assert features.urlFeatures.suspiciousKeywordCount > 0
        assert features.urlFeatures.suspiciousFeatureCount >= 2
    
    def test_urlRiskLevelMatchesFeatures(self):
        """Test URL risk level aligns with extracted features."""
        # High-risk URL
        highRiskUrl = "http://192.168.1.1@paypal-secure.tk/verify"
        
        analysis = analyzeUrl(highRiskUrl)
        features = extractFeatures(highRiskUrl)
        
        # Both should indicate high risk
        assert analysis.structuralScore > 0.5
        assert features.urlFeatures.hasIpAddress is True
        assert features.urlFeatures.hasAtSymbol is True
        assert features.urlFeatures.suspiciousFeatureCount >= 3


# =============================================================================
# Scoring Integration Tests
# =============================================================================

class TestScoringPipeline:
    """Test complete scoring pipeline with features."""
    
    def test_scoreLegitUrlWithOsint(self, legitOsintData):
        """Test scoring legitimate URL with OSINT data."""
        url = "https://www.google.com/search"
        
        # Extract features
        features = extractFeatures(url, osintData=legitOsintData)
        
        # Score
        scorer = PhishingScorer()
        riskScore = scorer.score(features)
        
        # Should have low risk
        assert riskScore.finalScore < 0.3
        assert riskScore.riskLevel in [RiskLevel.SAFE, RiskLevel.LOW]
        assert riskScore.confidence > 0.7
        
        # Component scores should be low
        assert riskScore.components.urlStructure.score < 0.3
        assert riskScore.components.osintData.score < 0.3
        assert riskScore.components.featureAnalysis.score < 0.3
    
    def test_scoreSuspiciousUrlWithOsint(self, suspiciousOsintData):
        """Test scoring suspicious URL with OSINT data."""
        url = "http://paypal-verify.tk/login"
        
        # Extract features
        features = extractFeatures(url, osintData=suspiciousOsintData)
        
        # Score
        scorer = PhishingScorer()
        riskScore = scorer.score(features)
        
        # Should have high risk
        assert riskScore.finalScore > 0.5
        assert riskScore.riskLevel in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert riskScore.confidence > 0.6
        
        # Should have suspicious reasons
        assert len(riskScore.reasons) > 0
        assert any("http" in reason.lower() or "tld" in reason.lower() 
                  for reason in riskScore.reasons)
    
    def test_quickScoreWorkflow(self):
        """Test quick score convenience function."""
        legitUrl = "https://www.microsoft.com"
        suspiciousUrl = "http://microsoft-login.tk/verify"
        
        # Quick score
        legitScore = scoreUrl(legitUrl)
        suspiciousScore = scoreUrl(suspiciousUrl)
        
        # Legit should score lower
        assert legitScore.finalScore < suspiciousScore.finalScore
        assert legitScore.riskLevel.value < suspiciousScore.riskLevel.value


class TestFeatureSetAggregation:
    """Test feature set aggregation and computed properties."""
    
    def test_featureSetTotalRiskIndicators(self, suspiciousOsintData):
        """Test total risk indicator calculation."""
        url = "http://paypal-verify.tk/login?update=true"
        
        features = extractFeatures(url, osintData=suspiciousOsintData)
        
        # Total risk should aggregate from all sources
        urlRisk = features.urlFeatures.suspiciousFeatureCount
        osintRisk = features.osintFeatures.osintRiskIndicators
        
        assert features.totalRiskIndicators == urlRisk + osintRisk
        assert features.totalRiskIndicators > 5
    
    def test_featureSetDataCompleteness(self):
        """Test data completeness detection."""
        url = "https://example.com"
        
        # Without OSINT
        featuresIncomplete = extractFeatures(url)
        assert featuresIncomplete.hasCompleteData is False
        
        # With OSINT (mocked)
        osintData = OsintData(
            url="https://example.com",
            domain="example.com",
            whois=WhoisResult(
                domain="example.com",
                status=LookupStatus.SUCCESS,
                registrar="Test",
                creationDate=datetime.now() - timedelta(days=365)
            ),
            dns=DnsResult(
                domain="example.com",
                status=LookupStatus.SUCCESS,
                records=[]
            ),
            reputation=ReputationResult(
                domain="example.com",
                status=LookupStatus.SUCCESS,
                checks=[],
                aggregateScore=0.0
            )
        )
        
        featuresComplete = extractFeatures(url, osintData=osintData)
        assert featuresComplete.hasCompleteData is True


class TestEndToEndMLPipeline:
    """Test complete ML pipeline from URL to risk score."""
    
    def test_endToEndLegitUrl(self, legitOsintData):
        """Test complete pipeline for legitimate URL."""
        url = "https://www.google.com/search?q=python"
        
        # 1. Analyze URL structure
        urlAnalysis = analyzeUrl(url)
        assert urlAnalysis.structuralScore < 0.3
        
        # 2. Extract features
        features = extractFeatures(url, osintData=legitOsintData)
        assert features.totalRiskIndicators < 5
        
        # 3. Score
        riskScore = scoreUrl(features)
        assert riskScore.riskLevel in [RiskLevel.SAFE, RiskLevel.LOW]
        assert riskScore.finalScore < 0.4
        
        # 4. Verify component breakdown
        assert riskScore.componentBreakdown["urlStructure"] < 0.3
        assert riskScore.componentBreakdown["osintData"] < 0.3
    
    def test_endToEndSuspiciousUrl(self, suspiciousOsintData):
        """Test complete pipeline for suspicious URL."""
        url = "http://paypal-verify.tk/secure/login?confirm=true"
        
        # 1. Analyze URL structure
        urlAnalysis = analyzeUrl(url)
        assert urlAnalysis.structuralScore > 0.5
        assert urlAnalysis.patternCount > 0
        
        # 2. Extract features
        features = extractFeatures(url, osintData=suspiciousOsintData)
        assert features.totalRiskIndicators > 5
        
        # 3. Score
        riskScore = scoreUrl(features)
        assert riskScore.riskLevel in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert riskScore.finalScore > 0.5
        
        # 4. Verify reasons provided
        assert len(riskScore.reasons) > 0
        assert riskScore.confidence > 0.5
    
    def test_endToEndPerformance(self):
        """Test pipeline performance."""
        url = "https://example.com/test"
        
        startTime = datetime.now()
        
        # Full pipeline
        urlAnalysis = analyzeUrl(url)
        features = extractFeatures(url)
        riskScore = scoreUrl(features)
        
        endTime = datetime.now()
        duration = (endTime - startTime).total_seconds()
        
        # Should be very fast without real OSINT
        assert duration < 0.1
        
        # All should complete successfully
        assert urlAnalysis is not None
        assert features is not None
        assert riskScore is not None
