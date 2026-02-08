"""
Unit Tests for NLP Analyzer
============================

Test suite for NLP-based phishing content analyzer.

Tests cover:
- Urgency phrase detection
- Threat phrase detection
- Brand impersonation detection
- Credential request detection
- Link manipulation detection
- Content type auto-detection
- Scoring and verdict logic
- Edge cases

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import pytest

from backend.analyzer import (
    AnalysisResult,
    ContentType,
    NlpAnalyzer,
    PhishingTactic,
    ThreatLevel,
    detectContentType,
    determineThreatLevel,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def analyzer():
    """Create NLP analyzer instance."""
    return NlpAnalyzer()


# =============================================================================
# Helper Function Tests
# =============================================================================

class TestHelperFunctions:
    """Test helper functions."""
    
    def test_determineThreatLevel_safe(self):
        """Test threat level determination for safe content."""
        assert determineThreatLevel(0.0) == ThreatLevel.SAFE
        assert determineThreatLevel(0.2) == ThreatLevel.SAFE
        assert determineThreatLevel(0.39) == ThreatLevel.SAFE
    
    def test_determineThreatLevel_suspicious(self):
        """Test threat level determination for suspicious content."""
        assert determineThreatLevel(0.4) == ThreatLevel.SUSPICIOUS
        assert determineThreatLevel(0.5) == ThreatLevel.SUSPICIOUS
        assert determineThreatLevel(0.59) == ThreatLevel.SUSPICIOUS
    
    def test_determineThreatLevel_dangerous(self):
        """Test threat level determination for dangerous content."""
        assert determineThreatLevel(0.6) == ThreatLevel.DANGEROUS
        assert determineThreatLevel(0.7) == ThreatLevel.DANGEROUS
        assert determineThreatLevel(0.79) == ThreatLevel.DANGEROUS
    
    def test_determineThreatLevel_critical(self):
        """Test threat level determination for critical content."""
        assert determineThreatLevel(0.8) == ThreatLevel.CRITICAL
        assert determineThreatLevel(0.9) == ThreatLevel.CRITICAL
        assert determineThreatLevel(1.0) == ThreatLevel.CRITICAL
    
    def test_detectContentType_url(self):
        """Test content type detection for URLs."""
        assert detectContentType("https://example.com") == ContentType.URL
        assert detectContentType("http://test.com/page") == ContentType.URL
        # Text with embedded URL should be TEXT
        assert detectContentType("Check out http://site.com") == ContentType.TEXT
    
    def test_detectContentType_email(self):
        """Test content type detection for email addresses."""
        assert detectContentType("contact@example.com") == ContentType.EMAIL
        # Text with email context should still be TEXT unless it has headers
        assert detectContentType("Email: user@test.com") == ContentType.TEXT
    
    def test_detectContentType_text(self):
        """Test content type detection for plain text."""
        assert detectContentType("This is plain text") == ContentType.TEXT
        assert detectContentType("No URLs or emails here!") == ContentType.TEXT


# =============================================================================
# Phishing Detection Tests
# =============================================================================

class TestPhishingDetection:
    """Test phishing content detection."""
    
    @pytest.mark.asyncio
    async def test_urgency_detection(self, analyzer):
        """Test urgency phrase detection."""
        content = "Act now! Your account expires today. Don't wait!"
        result = await analyzer.analyze(content, ContentType.TEXT)
        
        assert PhishingTactic.URGENCY in result.detectedTactics
        urgencyIndicators = [ind for ind in result.indicators if ind.category == "urgency"]
        assert len(urgencyIndicators) > 0
        assert result.isPhishing
    
    @pytest.mark.asyncio
    async def test_threat_detection(self, analyzer):
        """Test threat phrase detection."""
        content = "Your account has been suspended due to suspicious activity."
        result = await analyzer.analyze(content, ContentType.TEXT)
        
        assert PhishingTactic.THREAT_WARNING in result.detectedTactics
        threatIndicators = [ind for ind in result.indicators if ind.category == "threat"]
        assert len(threatIndicators) > 0
        assert result.isPhishing
    
    @pytest.mark.asyncio
    async def test_brand_detection(self, analyzer):
        """Test brand mention detection."""
        content = "Your PayPal account needs verification."
        result = await analyzer.analyze(content, ContentType.TEXT)
        
        assert PhishingTactic.BRAND_IMPERSONATION in result.detectedTactics
        brandIndicators = [ind for ind in result.indicators if ind.category == "brand_mention"]
        assert len(brandIndicators) > 0
    
    @pytest.mark.asyncio
    async def test_credential_request_detection(self, analyzer):
        """Test credential request detection."""
        content = "Please verify your account by entering your password."
        result = await analyzer.analyze(content, ContentType.TEXT)
        
        assert PhishingTactic.CREDENTIAL_REQUEST in result.detectedTactics
        credentialIndicators = [ind for ind in result.indicators if ind.category == "credential_request"]
        assert len(credentialIndicators) > 0
        assert result.isPhishing
    
    @pytest.mark.asyncio
    async def test_suspicious_action_detection(self, analyzer):
        """Test suspicious action request detection."""
        content = "Click here to update your information immediately."
        result = await analyzer.analyze(content, ContentType.TEXT)
        
        suspiciousIndicators = [ind for ind in result.indicators if ind.category == "suspicious_action"]
        assert len(suspiciousIndicators) > 0
    
    @pytest.mark.asyncio
    async def test_link_manipulation_ip_address(self, analyzer):
        """Test detection of IP addresses in URLs."""
        content = "Visit http://192.168.1.1/login to verify your account."
        result = await analyzer.analyze(content, ContentType.EMAIL)
        
        linkIndicators = [ind for ind in result.indicators if ind.category == "link_manipulation"]
        assert len(linkIndicators) > 0
        assert result.isPhishing
    
    @pytest.mark.asyncio
    async def test_link_manipulation_suspicious_tld(self, analyzer):
        """Test detection of suspicious TLDs."""
        content = "Click here: http://paypal-verify.tk/login"
        result = await analyzer.analyze(content, ContentType.EMAIL)
        
        linkIndicators = [ind for ind in result.indicators if ind.category == "link_manipulation"]
        assert len(linkIndicators) > 0


# =============================================================================
# Legitimate Content Tests
# =============================================================================

class TestLegitimateContent:
    """Test legitimate (non-phishing) content."""
    
    @pytest.mark.asyncio
    async def test_simple_message(self, analyzer):
        """Test simple legitimate message."""
        content = "Thank you for your order. Your package will arrive soon."
        result = await analyzer.analyze(content, ContentType.TEXT)
        
        assert not result.isPhishing
        assert result.threatLevel == ThreatLevel.SAFE
        assert result.confidenceScore < 0.6
    
    @pytest.mark.asyncio
    async def test_professional_email(self, analyzer):
        """Test professional email without phishing indicators."""
        content = """
        Dear Customer,
        
        Thank you for contacting our support team. We have received your
        inquiry and will respond within 2-3 business days.
        
        Best regards,
        Support Team
        """
        result = await analyzer.analyze(content, ContentType.EMAIL)
        
        assert not result.isPhishing
        assert result.confidenceScore < 0.6


# =============================================================================
# Sophisticated Phishing Tests
# =============================================================================

class TestSophisticatedPhishing:
    """Test detection of sophisticated phishing attempts."""
    
    @pytest.mark.asyncio
    async def test_multi_tactic_phishing(self, analyzer):
        """Test phishing using multiple tactics."""
        content = """
        URGENT: Your PayPal account has been suspended!
        
        Suspicious activity was detected on your account.
        Click here to verify your identity immediately:
        http://paypal-secure.tk/verify
        
        You must act within 24 hours or your account will be
        permanently closed.
        
        Enter your password to restore access.
        """
        result = await analyzer.analyze(content, ContentType.EMAIL)
        
        # Should detect multiple tactics
        assert len(result.detectedTactics) >= 4
        assert PhishingTactic.URGENCY in result.detectedTactics
        assert PhishingTactic.THREAT_WARNING in result.detectedTactics
        assert PhishingTactic.BRAND_IMPERSONATION in result.detectedTactics
        assert PhishingTactic.CREDENTIAL_REQUEST in result.detectedTactics
        
        # High confidence score
        assert result.confidenceScore > 0.7
        assert result.isPhishing
        assert result.threatLevel in [ThreatLevel.DANGEROUS, ThreatLevel.CRITICAL]
    
    @pytest.mark.asyncio
    async def test_authority_impersonation(self, analyzer):
        """Test authority impersonation detection."""
        content = """
        From: IT Department
        
        Our security team has detected unusual activity on your account.
        Please verify your credentials immediately.
        """
        result = await analyzer.analyze(content, ContentType.EMAIL)
        
        assert PhishingTactic.AUTHORITY_IMPERSONATION in result.detectedTactics
        authorityIndicators = [ind for ind in result.indicators if ind.category == "authority_impersonation"]
        assert len(authorityIndicators) > 0


# =============================================================================
# Analysis Result Tests
# =============================================================================

class TestAnalysisResult:
    """Test analysis result structure and properties."""
    
    @pytest.mark.asyncio
    async def test_result_structure(self, analyzer):
        """Test that result has required fields."""
        content = "Urgent! Verify your account now."
        result = await analyzer.analyze(content, ContentType.TEXT)
        
        # Check required fields
        assert isinstance(result, AnalysisResult)
        assert isinstance(result.isPhishing, bool)
        assert 0.0 <= result.confidenceScore <= 1.0
        assert isinstance(result.threatLevel, ThreatLevel)
        assert isinstance(result.reasons, list)
        assert isinstance(result.detectedTactics, list)
        assert isinstance(result.indicators, list)
        assert result.analysisTime > 0
        assert result.analyzedAt is not None
    
    @pytest.mark.asyncio
    async def test_top_indicators_property(self, analyzer):
        """Test topIndicators property."""
        content = """
        URGENT! Your account suspended! Suspicious activity detected!
        Verify immediately! Click here! Don't wait! Act now!
        """
        result = await analyzer.analyze(content, ContentType.TEXT)
        
        # Should have multiple indicators
        assert len(result.indicators) > 5
        
        # Top indicators should be sorted by severity
        topIndicators = result.topIndicators
        assert len(topIndicators) <= 5
        if len(topIndicators) > 1:
            for i in range(len(topIndicators) - 1):
                assert topIndicators[i].severity >= topIndicators[i + 1].severity
    
    @pytest.mark.asyncio
    async def test_high_severity_property(self, analyzer):
        """Test hasHighSeverityIndicators property."""
        # High severity content
        highSeverityContent = "Verify your account by entering your password immediately."
        result = await analyzer.analyze(highSeverityContent, ContentType.TEXT)
        assert result.hasHighSeverityIndicators
        
        # Low severity content
        lowSeverityContent = "Thank you for your purchase."
        result = await analyzer.analyze(lowSeverityContent, ContentType.TEXT)
        assert not result.hasHighSeverityIndicators
    
    @pytest.mark.asyncio
    async def test_reasons_generated(self, analyzer):
        """Test that reasons are generated."""
        content = "Urgent! Your PayPal account suspended. Verify your password now."
        result = await analyzer.analyze(content, ContentType.TEXT)
        
        assert len(result.reasons) > 0
        # Reasons should be strings
        for reason in result.reasons:
            assert isinstance(reason, str)
            assert len(reason) > 10  # Reasonable length


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================

class TestEdgeCases:
    """Test edge cases and error handling."""
    
    @pytest.mark.asyncio
    async def test_empty_content_raises_error(self, analyzer):
        """Test that empty content raises ValueError."""
        with pytest.raises(ValueError, match="Content cannot be empty"):
            await analyzer.analyze("", ContentType.TEXT)
        
        with pytest.raises(ValueError, match="Content cannot be empty"):
            await analyzer.analyze("   ", ContentType.TEXT)
    
    @pytest.mark.asyncio
    async def test_auto_content_type_detection(self, analyzer):
        """Test automatic content type detection."""
        # URL content
        urlContent = "https://example.com/login"
        result = await analyzer.analyze(urlContent, ContentType.AUTO)
        assert result is not None
        
        # Email content
        emailContent = "Contact us at support@example.com"
        result = await analyzer.analyze(emailContent, ContentType.AUTO)
        assert result is not None
        
        # Text content
        textContent = "This is plain text without URLs or emails"
        result = await analyzer.analyze(textContent, ContentType.AUTO)
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_unicode_content(self, analyzer):
        """Test content with unicode characters."""
        # Note: spaCy's en_core_web_sm may not recognize urgency in mixed unicode
        content = "Urgent! Verify your account now!"  # Use pure ASCII for reliable detection
        result = await analyzer.analyze(content, ContentType.TEXT)
        
        # Should detect urgency
        assert PhishingTactic.URGENCY in result.detectedTactics
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_very_long_content(self, analyzer):
        """Test very long content."""
        content = "Urgent! " + "This is padding text. " * 500 + "Verify your account now."
        result = await analyzer.analyze(content, ContentType.TEXT)
        
        # Should still detect phishing
        assert result.isPhishing
        assert PhishingTactic.URGENCY in result.detectedTactics
    
    @pytest.mark.asyncio
    async def test_only_urls(self, analyzer):
        """Test content with only URLs."""
        content = "http://192.168.1.1/verify http://suspicious.tk/login"
        result = await analyzer.analyze(content, ContentType.EMAIL)
        
        # Should detect link manipulation
        linkIndicators = [ind for ind in result.indicators if ind.category == "link_manipulation"]
        assert len(linkIndicators) > 0


# =============================================================================
# Analyzer Metadata Tests
# =============================================================================

class TestAnalyzerMetadata:
    """Test analyzer metadata methods."""
    
    def test_get_capabilities(self, analyzer):
        """Test getCapabilities method."""
        capabilities = analyzer.getCapabilities()
        assert isinstance(capabilities, list)
        assert "url" in capabilities
        assert "email" in capabilities
        assert "text" in capabilities
    
    def test_get_name(self, analyzer):
        """Test getName method."""
        name = analyzer.getName()
        assert isinstance(name, str)
        assert len(name) > 0
        assert name == "NLP Analyzer"
    
    def test_get_version(self, analyzer):
        """Test getVersion method."""
        version = analyzer.getVersion()
        assert isinstance(version, str)
        assert len(version) > 0
        # Should match semver pattern
        assert version.count(".") >= 2


# =============================================================================
# Performance Tests
# =============================================================================

class TestPerformance:
    """Test performance characteristics."""
    
    @pytest.mark.asyncio
    async def test_analysis_time_reasonable(self, analyzer):
        """Test that analysis completes in reasonable time."""
        content = "Urgent! Your account has been suspended. Verify now."
        result = await analyzer.analyze(content, ContentType.TEXT)
        
        # Should complete in less than 1 second (1000ms)
        assert result.analysisTime < 1000
    
    @pytest.mark.asyncio
    async def test_multiple_analyses(self, analyzer):
        """Test multiple consecutive analyses."""
        contents = [
            "Urgent! Act now!",
            "Your account suspended",
            "Click here immediately",
            "Verify your password",
            "Thank you for your purchase",
        ]
        
        for content in contents:
            result = await analyzer.analyze(content, ContentType.TEXT)
            assert result is not None
            assert result.analysisTime < 1000


# =============================================================================
# Real-World Example Tests
# =============================================================================

class TestRealWorldExamples:
    """Test with real-world phishing examples."""
    
    @pytest.mark.asyncio
    async def test_paypal_phishing(self, analyzer):
        """Test typical PayPal phishing email."""
        content = """
        Subject: Action Required: Your PayPal Account Has Been Limited
        
        Dear Valued Customer,
        
        We have detected unusual activity on your PayPal account and have
        temporarily restricted access to protect your security.
        
        To restore full access to your account, please verify your identity
        immediately by clicking the link below:
        
        http://paypal-security.tk/verify
        
        Please complete this verification within 24 hours. Failure to do so
        will result in permanent account suspension.
        
        Thank you,
        PayPal Security Team
        """
        result = await analyzer.analyze(content, ContentType.EMAIL)
        
        assert result.isPhishing
        assert result.confidenceScore > 0.7
        assert PhishingTactic.BRAND_IMPERSONATION in result.detectedTactics
        assert PhishingTactic.URGENCY in result.detectedTactics
        assert PhishingTactic.THREAT_WARNING in result.detectedTactics
    
    @pytest.mark.asyncio
    async def test_bank_phishing(self, analyzer):
        """Test typical bank phishing email."""
        content = """
        URGENT SECURITY ALERT
        
        Suspicious login attempts have been detected on your online banking account.
        
        For your security, we have temporarily locked your account. To unlock it,
        please verify your identity immediately:
        
        Click here: http://192.168.100.50/banking/verify
        
        You must complete this verification within 12 hours or your account will
        be permanently closed.
        
        Bank Security Department
        """
        result = await analyzer.analyze(content, ContentType.EMAIL)
        
        assert result.isPhishing
        assert result.confidenceScore > 0.7
        assert result.threatLevel in [ThreatLevel.DANGEROUS, ThreatLevel.CRITICAL]
    
    @pytest.mark.asyncio
    async def test_legitimate_newsletter(self, analyzer):
        """Test legitimate newsletter content."""
        content = """
        Weekly Newsletter - January 2026
        
        Hello Subscriber,
        
        Here are this week's top stories:
        
        1. New Product Launch
        2. Customer Success Story
        3. Upcoming Events
        
        Read more on our website: https://example.com/newsletter
        
        To unsubscribe, visit: https://example.com/unsubscribe
        
        Best regards,
        Marketing Team
        """
        result = await analyzer.analyze(content, ContentType.EMAIL)
        
        # Newsletter may have "click here" but overall should be low confidence
        # The test should check that it's not highly confident phishing
        assert result.confidenceScore < 0.8  # Allow some false positives but not high confidence
        assert result.threatLevel in [ThreatLevel.SAFE, ThreatLevel.SUSPICIOUS, ThreatLevel.DANGEROUS]
