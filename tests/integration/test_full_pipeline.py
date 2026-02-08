"""
Integration Tests for Full Analysis Pipeline
============================================

Tests the complete end-to-end analysis workflow:
- URL/Email input → OSINT → NLP → ML → Risk Assessment
- Full orchestration through AnalysisOrchestrator
- Real-world phishing detection scenarios

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import pytest
from unittest.mock import AsyncMock
from datetime import datetime, timedelta

from backend.analyzer import NlpAnalyzer, ThreatLevel
from backend.api.orchestrator import AnalysisOrchestrator
from backend.ml import extractFeatures, scoreUrl, RiskLevel
from osint import OsintData, WhoisResult, DnsResult, ReputationResult, LookupStatus


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def mockOsintData():
    """Mock OSINT data for testing."""
    return OsintData(
        domain="example.com",
        whois=WhoisResult(
            domain="example.com",
            status=LookupStatus.SUCCESS,
            registrar="Test Registrar",
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


# =============================================================================
# NLP + ML Integration Tests
# =============================================================================

class TestAnalyzerIntegration:
    """Test NLP analyzer integration with ML pipeline."""
    
    def test_nlpAnalyzerWithUrlExtraction(self):
        """Test NLP analyzer extracts URLs and ML can analyze them."""
        email = """
        Dear customer,
        
        Your PayPal account has been suspended. Please verify immediately at:
        http://paypal-verify.tk/secure/login
        
        Click here to restore access within 24 hours!
        """
        
        # NLP analysis
        analyzer = NlpAnalyzer()
        nlpResult = analyzer.analyze(email, contentType="email")
        
        # Should detect threat
        assert nlpResult.threatLevel in [ThreatLevel.SUSPICIOUS, 
                                         ThreatLevel.DANGEROUS,
                                         ThreatLevel.CRITICAL]
        assert nlpResult.indicatorCount > 0
        
        # Should extract URLs
        extractedUrls = [i.value for i in nlpResult.indicators 
                        if "url" in i.type.lower()]
        assert len(extractedUrls) > 0
        
        # ML can analyze extracted URL
        if extractedUrls:
            url = extractedUrls[0]
            features = extractFeatures(url)
            riskScore = scoreUrl(features)
            
            # Should detect as suspicious
            assert riskScore.riskLevel in [RiskLevel.MEDIUM, 
                                           RiskLevel.HIGH,
                                           RiskLevel.CRITICAL]
    
    def test_nlpDetectsPhishingIndicators(self):
        """Test NLP detects key phishing indicators."""
        phishingEmail = """
        URGENT: Your account will be closed!
        
        We detected suspicious activity. Verify your identity now:
        Click: http://suspicious-bank.tk/verify?account=12345
        
        Enter your password to continue.
        """
        
        analyzer = NlpAnalyzer()
        result = analyzer.analyze(phishingEmail, contentType="email")
        
        # Should detect multiple indicators
        assert result.indicatorCount >= 3
        
        # Check for specific tactics
        tactics = [i.phishingTactic for i in result.indicators]
        assert any("URGENCY" in str(t) for t in tactics)
        assert any("CREDENTIAL" in str(t) for t in tactics)
        
        # High threat level
        assert result.threatLevel.value >= ThreatLevel.DANGEROUS.value


class TestOrchestrationPipeline:
    """Test AnalysisOrchestrator integration."""
    
    @pytest.mark.asyncio
    async def test_orchestrateUrlAnalysis(self, mockOsintData):
        """Test orchestrator coordinates URL analysis."""
        orchestrator = AnalysisOrchestrator()
        
        # Mock OSINT collection
        async def mockCollectOsint(url):
            return mockOsintData
        
        orchestrator.collectOsintData = mockCollectOsint
        
        # Analyze URL
        result = await orchestrator.analyzeUrl("https://example.com/test")
        
        # Should return complete analysis
        assert result is not None
        assert "verdict" in result
        assert "features" in result
        assert "analysisTime" in result
        
        # Verdict should have required fields
        verdict = result["verdict"]
        assert "isPhishing" in verdict
        assert "riskLevel" in verdict
        assert "confidence" in verdict
    
    @pytest.mark.asyncio
    async def test_orchestrateEmailAnalysis(self):
        """Test orchestrator analyzes email content."""
        orchestrator = AnalysisOrchestrator()
        
        email = """
        Hello,
        Thank you for your order. Your package will arrive soon.
        Best regards,
        Example Store
        """
        
        # Analyze email
        result = await orchestrator.analyzeEmail(email)
        
        # Should complete analysis
        assert result is not None
        assert "verdict" in result
        assert "contentAnalysis" in result
        
        # Legitimate email should score safe
        verdict = result["verdict"]
        assert verdict["riskLevel"] in ["SAFE", "LOW"]
    
    @pytest.mark.asyncio
    async def test_orchestratePhishingEmail(self):
        """Test orchestrator detects phishing email."""
        orchestrator = AnalysisOrchestrator()
        
        phishing = """
        URGENT: Account Verification Required
        
        Your PayPal account has been limited due to suspicious activity.
        Verify immediately: http://paypal-secure.tk/login
        
        Enter your password and billing information to restore access.
        """
        
        # Analyze phishing email
        result = await orchestrator.analyzeEmail(phishing)
        
        # Should detect as phishing
        verdict = result["verdict"]
        assert verdict["riskLevel"] in ["MEDIUM", "HIGH", "CRITICAL"]
        assert verdict["confidence"] > 0.5
        
        # Should provide reasons
        if "reasons" in result:
            assert len(result["reasons"]) > 0


class TestEndToEndScenarios:
    """Test real-world phishing detection scenarios."""
    
    @pytest.mark.asyncio
    async def test_legitimateWebsiteScenario(self, mockOsintData):
        """Test analysis of legitimate website."""
        orchestrator = AnalysisOrchestrator()
        
        # Mock OSINT to return safe data
        async def mockCollectOsint(url):
            return OsintData(
                domain="google.com",
                whois=WhoisResult(
                    domain="google.com",
                    status=LookupStatus.SUCCESS,
                    registrar="MarkMonitor",
                    creationDate=datetime.now() - timedelta(days=7300)
                ),
                dns=DnsResult(
                    domain="google.com",
                    status=LookupStatus.SUCCESS,
                    records=[]
                ),
                reputation=ReputationResult(
                    domain="google.com",
                    status=LookupStatus.SUCCESS,
                    checks=[],
                    aggregateScore=0.0
                )
            )
        
        orchestrator.collectOsintData = mockCollectOsint
        
        # Analyze legitimate URL
        result = await orchestrator.analyzeUrl("https://www.google.com/search")
        
        # Should classify as safe
        verdict = result["verdict"]
        assert verdict["riskLevel"] in ["SAFE", "LOW"]
        assert verdict["confidence"] > 0.7
    
    @pytest.mark.asyncio
    async def test_brandImpersonationScenario(self):
        """Test detection of brand impersonation phishing."""
        orchestrator = AnalysisOrchestrator()
        
        # Mock OSINT to return suspicious data
        async def mockCollectOsint(url):
            return OsintData(
                domain="paypal-verify.tk",
                whois=WhoisResult(
                    domain="paypal-verify.tk",
                    status=LookupStatus.SUCCESS,
                    registrar="Freenom",
                    creationDate=datetime.now() - timedelta(days=3),
                    registrantName="REDACTED FOR PRIVACY"
                ),
                dns=DnsResult(
                    domain="paypal-verify.tk",
                    status=LookupStatus.SUCCESS,
                    records=[]
                ),
                reputation=ReputationResult(
                    domain="paypal-verify.tk",
                    status=LookupStatus.SUCCESS,
                    checks=[],
                    aggregateScore=0.7
                )
            )
        
        orchestrator.collectOsintData = mockCollectOsint
        
        # Analyze phishing URL
        result = await orchestrator.analyzeUrl("http://paypal-verify.tk/login")
        
        # Should detect as phishing
        verdict = result["verdict"]
        assert verdict["riskLevel"] in ["HIGH", "CRITICAL"]
        assert verdict["isPhishing"] is True
    
    @pytest.mark.asyncio
    async def test_credentialHarvestingEmail(self):
        """Test detection of credential harvesting email."""
        orchestrator = AnalysisOrchestrator()
        
        phishing = """
        Microsoft Security Alert
        
        We detected unusual sign-in activity on your account.
        Verify your identity immediately:
        
        http://microsoft-security.tk/verify
        
        Please enter your email and password to confirm.
        If you don't verify within 24 hours, your account will be suspended.
        """
        
        result = await orchestrator.analyzeEmail(phishing)
        
        # Should detect credential harvesting
        verdict = result["verdict"]
        assert verdict["riskLevel"] in ["MEDIUM", "HIGH", "CRITICAL"]
        
        # Content analysis should detect urgency and credential requests
        if "contentAnalysis" in result:
            content = result["contentAnalysis"]
            assert content["indicatorCount"] >= 3


class TestPipelinePerformance:
    """Test analysis pipeline performance."""
    
    @pytest.mark.asyncio
    async def test_analysisCompletesFast(self, mockOsintData):
        """Test that full analysis completes in reasonable time."""
        orchestrator = AnalysisOrchestrator()
        
        # Mock OSINT to avoid real network calls
        async def mockCollectOsint(url):
            return mockOsintData
        
        orchestrator.collectOsintData = mockCollectOsint
        
        startTime = datetime.now()
        
        # Run full analysis
        result = await orchestrator.analyzeUrl("https://example.com")
        
        endTime = datetime.now()
        duration = (endTime - startTime).total_seconds()
        
        # Should complete quickly with mocked OSINT
        assert duration < 1.0
        
        # Analysis time should be recorded
        assert result["analysisTime"] >= 0
    
    @pytest.mark.asyncio
    async def test_emailAnalysisPerformance(self):
        """Test email analysis performance."""
        orchestrator = AnalysisOrchestrator()
        
        email = "This is a test email with some content."
        
        startTime = datetime.now()
        result = await orchestrator.analyzeEmail(email)
        endTime = datetime.now()
        
        duration = (endTime - startTime).total_seconds()
        
        # Email analysis should be very fast
        assert duration < 0.5
        assert result is not None


class TestErrorHandling:
    """Test error handling in full pipeline."""
    
    @pytest.mark.asyncio
    async def test_osintFailureHandling(self):
        """Test pipeline handles OSINT failure gracefully."""
        orchestrator = AnalysisOrchestrator()
        
        # Mock OSINT to fail
        async def mockCollectOsintFailing(url):
            return OsintData(
                domain="example.com",
                whois=WhoisResult(
                    domain="example.com",
                    status=LookupStatus.ERROR,
                    errorMessage="WHOIS lookup failed"
                ),
                dns=DnsResult(
                    domain="example.com",
                    status=LookupStatus.ERROR,
                    errorMessage="DNS lookup failed"
                ),
                reputation=ReputationResult(
                    domain="example.com",
                    status=LookupStatus.ERROR,
                    errorMessage="Reputation check failed"
                )
            )
        
        orchestrator.collectOsintData = mockCollectOsintFailing
        
        # Should still complete analysis
        result = await orchestrator.analyzeUrl("https://example.com")
        
        # Should return result with lower confidence
        assert result is not None
        verdict = result["verdict"]
        assert verdict["confidence"] < 1.0
    
    @pytest.mark.asyncio
    async def test_emptyContentHandling(self):
        """Test handling of empty/invalid content."""
        orchestrator = AnalysisOrchestrator()
        
        # Empty email should raise or return error
        with pytest.raises(Exception):
            await orchestrator.analyzeEmail("")
        
        # Empty URL should raise or return error
        with pytest.raises(Exception):
            await orchestrator.analyzeUrl("")
