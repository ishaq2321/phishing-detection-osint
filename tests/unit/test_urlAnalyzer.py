"""
Unit Tests for URL Analyzer Module
===================================

Comprehensive tests for URL structural analysis and pattern detection.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import pytest

from backend.ml.urlAnalyzer import (
    ALL_PATTERNS,
    BRAND_PATTERNS,
    CREDENTIAL_PATTERNS,
    LEGITIMATE_BRAND_DOMAINS,
    OBFUSCATION_PATTERNS,
    STRUCTURE_PATTERNS,
    SUSPICIOUS_TLD_PATTERNS,
    URGENCY_PATTERNS,
    UrlAnalyzer,
    analyzeUrl,
    detectBrandImpersonation,
    detectUrlObfuscation,
    getUrlRiskLevel,
)
from backend.ml.schemas import SuspiciousPattern, UrlAnalysisResult


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def urlAnalyzer() -> UrlAnalyzer:
    """Create a URL analyzer instance."""
    return UrlAnalyzer()


# =============================================================================
# URL Analyzer Class Tests
# =============================================================================

class TestUrlAnalyzerBasics:
    """Basic tests for UrlAnalyzer class."""
    
    def test_analyzeEmptyUrl(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Empty URL returns appropriate result."""
        result = urlAnalyzer.analyze("")
        
        assert result.url == ""
        assert result.domain == ""
        assert "Empty URL" in result.analysisNotes[0]
    
    def test_analyzeSimpleUrl(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Simple URL is analyzed correctly."""
        result = urlAnalyzer.analyze("https://example.com")
        
        assert result.url == "https://example.com"
        assert result.scheme == "https"
        assert result.domain == "example.com"
        assert result.structuralScore < 0.2  # Should be low risk
    
    def test_analyzeUrlWithoutScheme(self, urlAnalyzer: UrlAnalyzer) -> None:
        """URL without scheme is normalized."""
        result = urlAnalyzer.analyze("example.com")
        
        assert result.domain == "example.com"
        assert result.scheme == "http"  # Default
    
    def test_analyzeHttpVsHttps(self, urlAnalyzer: UrlAnalyzer) -> None:
        """HTTP URLs have higher score than HTTPS."""
        httpResult = urlAnalyzer.analyze("http://example.com")
        httpsResult = urlAnalyzer.analyze("https://example.com")
        
        # HTTP should have slightly higher score (less secure)
        assert httpResult.structuralScore >= httpsResult.structuralScore
        assert "HTTPS" in str(httpResult.analysisNotes)
    
    def test_analyzedAtTimestamp(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Analysis includes timestamp."""
        result = urlAnalyzer.analyze("https://example.com")
        
        assert result.analyzedAt is not None


# =============================================================================
# Domain Component Parsing Tests
# =============================================================================

class TestDomainParsing:
    """Tests for domain component parsing."""
    
    def test_simpledomainParsing(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Simple domain is parsed correctly."""
        result = urlAnalyzer.analyze("https://example.com")
        
        assert result.domain == "example.com"
        assert result.tld == "com"
        assert result.subdomain is None
    
    def test_subdomainParsing(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Subdomain is parsed correctly."""
        result = urlAnalyzer.analyze("https://www.example.com")
        
        assert result.subdomain == "www"
        assert result.tld == "com"
    
    def test_multipleSubdomainParsing(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Multiple subdomains are parsed correctly."""
        result = urlAnalyzer.analyze("https://mail.secure.example.com")
        
        assert result.subdomain == "mail.secure"
        assert result.tld == "com"
    
    def test_twoPartTldParsing(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Two-part TLDs are handled correctly."""
        result = urlAnalyzer.analyze("https://www.example.co.uk")
        
        assert result.tld == "co.uk"
        assert result.subdomain == "www"
    
    def test_ipAddressDomain(self, urlAnalyzer: UrlAnalyzer) -> None:
        """IP address domains are handled."""
        result = urlAnalyzer.analyze("http://192.168.1.1/login")
        
        assert result.domain == "192.168.1.1"
        assert result.tld == ""
        assert result.subdomain is None


# =============================================================================
# URL Path and Query Tests
# =============================================================================

class TestUrlComponents:
    """Tests for URL component extraction."""
    
    def test_pathExtraction(self, urlAnalyzer: UrlAnalyzer) -> None:
        """URL path is extracted correctly."""
        result = urlAnalyzer.analyze("https://example.com/a/b/c")
        
        assert result.path == "/a/b/c"
    
    def test_queryExtraction(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Query string is extracted correctly."""
        result = urlAnalyzer.analyze("https://example.com?a=1&b=2")
        
        assert result.query == "a=1&b=2"
    
    def test_fragmentExtraction(self, urlAnalyzer: UrlAnalyzer) -> None:
        """URL fragment is extracted correctly."""
        result = urlAnalyzer.analyze("https://example.com#section")
        
        assert result.fragment == "section"
    
    def test_emptyQueryIsNone(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Empty query string is None."""
        result = urlAnalyzer.analyze("https://example.com")
        
        assert result.query is None


# =============================================================================
# Brand Impersonation Detection Tests
# =============================================================================

class TestBrandImpersonation:
    """Tests for brand impersonation detection."""
    
    def test_paypalImpersonationDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """PayPal impersonation is detected."""
        result = urlAnalyzer.analyze("https://paypal-secure.example.tk")
        
        brandPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "brand_impersonation"
        ]
        assert len(brandPatterns) >= 1
        assert any("PayPal" in p.description for p in brandPatterns)
    
    def test_microsoftImpersonationDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Microsoft impersonation is detected."""
        result = urlAnalyzer.analyze("https://microsoft-login.fake.com")
        
        brandPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "brand_impersonation"
        ]
        assert len(brandPatterns) >= 1
    
    def test_legitPaypalNotFlagged(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Legitimate PayPal domain is not flagged."""
        result = urlAnalyzer.analyze("https://www.paypal.com/login")
        
        brandPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "brand_impersonation"
        ]
        assert len(brandPatterns) == 0
    
    def test_legitGoogleNotFlagged(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Legitimate Google domain is not flagged."""
        result = urlAnalyzer.analyze("https://accounts.google.com")
        
        brandPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "brand_impersonation"
        ]
        assert len(brandPatterns) == 0
    
    def test_multipleBrandsDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Multiple brand impersonations can be detected."""
        result = urlAnalyzer.analyze(
            "https://paypal-microsoft-amazon.fake.tk"
        )
        
        brandPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "brand_impersonation"
        ]
        assert len(brandPatterns) >= 2


# =============================================================================
# URL Obfuscation Detection Tests
# =============================================================================

class TestUrlObfuscation:
    """Tests for URL obfuscation detection."""
    
    def test_atSymbolDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """@ symbol obfuscation is detected."""
        result = urlAnalyzer.analyze("https://legitimate.com@evil.com")
        
        obfuscationPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "url_obfuscation"
        ]
        assert len(obfuscationPatterns) >= 1
        assert any("@" in p.description for p in obfuscationPatterns)
    
    def test_doubleSlashDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Double slash obfuscation is detected."""
        result = urlAnalyzer.analyze("https://example.com//redirect//page")
        
        obfuscationPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "url_obfuscation"
        ]
        assert len(obfuscationPatterns) >= 1
    
    def test_nullByteDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Null byte injection is detected."""
        result = urlAnalyzer.analyze("https://example.com/path%00.html")
        
        obfuscationPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "url_obfuscation"
        ]
        assert len(obfuscationPatterns) >= 1
    
    def test_excessiveEncodingDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Excessive URL encoding is detected."""
        result = urlAnalyzer.analyze("https://example.com/%2F%2F%2F%2F")
        
        obfuscationPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "url_obfuscation"
        ]
        assert len(obfuscationPatterns) >= 1
    
    def test_hexIpDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Hexadecimal IP encoding is detected."""
        result = urlAnalyzer.analyze("http://0x7f000001/login")
        
        obfuscationPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "url_obfuscation"
        ]
        assert len(obfuscationPatterns) >= 1


# =============================================================================
# Credential Harvesting Detection Tests
# =============================================================================

class TestCredentialHarvesting:
    """Tests for credential harvesting pattern detection."""
    
    def test_loginKeywordDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Login keyword is detected."""
        result = urlAnalyzer.analyze("https://example.com/login")
        
        credPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "credential_harvesting"
        ]
        assert len(credPatterns) >= 1
    
    def test_verifyKeywordDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Verify keyword is detected."""
        result = urlAnalyzer.analyze("https://example.com/verify-account")
        
        credPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "credential_harvesting"
        ]
        assert len(credPatterns) >= 1
    
    def test_passwordKeywordDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Password keyword is detected."""
        result = urlAnalyzer.analyze("https://example.com/reset-password")
        
        credPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "credential_harvesting"
        ]
        assert len(credPatterns) >= 1
    
    def test_paymentUpdateDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Payment update request is detected."""
        result = urlAnalyzer.analyze("https://example.com/update-payment-card")
        
        credPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "credential_harvesting"
        ]
        assert len(credPatterns) >= 1


# =============================================================================
# Suspicious Structure Tests
# =============================================================================

class TestSuspiciousStructure:
    """Tests for suspicious URL structure detection."""
    
    def test_multipleHyphensDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Multiple consecutive hyphens are detected."""
        result = urlAnalyzer.analyze("https://my--weird--domain.com")
        
        structPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "suspicious_structure"
        ]
        assert len(structPatterns) >= 1
    
    def test_longRandomStringDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Long random-looking strings are detected."""
        randomStr = "a" * 35
        result = urlAnalyzer.analyze(f"https://example.com/{randomStr}")
        
        structPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "suspicious_structure"
        ]
        assert len(structPatterns) >= 1


# =============================================================================
# Urgency Pattern Tests
# =============================================================================

class TestUrgencyPatterns:
    """Tests for urgency pattern detection."""
    
    def test_suspendedKeywordDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Suspended keyword is detected."""
        result = urlAnalyzer.analyze("https://example.com/account-suspended")
        
        urgencyPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "urgency_indicator"
        ]
        assert len(urgencyPatterns) >= 1
    
    def test_urgentKeywordDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Urgent keyword is detected."""
        result = urlAnalyzer.analyze("https://example.com/urgent-action")
        
        urgencyPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "urgency_indicator"
        ]
        assert len(urgencyPatterns) >= 1
    
    def test_timePressureDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Time pressure language is detected."""
        result = urlAnalyzer.analyze("https://example.com/24hours-to-act")
        
        urgencyPatterns = [
            p for p in result.suspiciousPatterns
            if p.patternType == "urgency_indicator"
        ]
        assert len(urgencyPatterns) >= 1


# =============================================================================
# Suspicious TLD Tests
# =============================================================================

class TestSuspiciousTld:
    """Tests for suspicious TLD detection."""
    
    def test_freeTldDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Free domain TLDs are detected."""
        for tld in ["tk", "ml", "ga", "cf", "gq"]:
            result = urlAnalyzer.analyze(f"https://example.{tld}")
            
            tldPatterns = [
                p for p in result.suspiciousPatterns
                if p.patternType == "suspicious_tld"
            ]
            assert len(tldPatterns) >= 1, f"Failed for TLD: {tld}"
    
    def test_lowCostTldDetected(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Low-cost TLDs are detected."""
        for tld in ["xyz", "top", "work"]:
            result = urlAnalyzer.analyze(f"https://example.{tld}")
            
            tldPatterns = [
                p for p in result.suspiciousPatterns
                if p.patternType == "suspicious_tld"
            ]
            assert len(tldPatterns) >= 1, f"Failed for TLD: {tld}"
    
    def test_legitTldNotFlagged(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Legitimate TLDs are not flagged as suspicious."""
        for tld in ["com", "org", "net", "edu"]:
            result = urlAnalyzer.analyze(f"https://example.{tld}")
            
            tldPatterns = [
                p for p in result.suspiciousPatterns
                if p.patternType == "suspicious_tld"
            ]
            assert len(tldPatterns) == 0, f"False positive for TLD: {tld}"


# =============================================================================
# Structural Score Tests
# =============================================================================

class TestStructuralScore:
    """Tests for structural score calculation."""
    
    def test_safeUrlHasLowScore(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Safe URLs have low structural scores."""
        result = urlAnalyzer.analyze("https://google.com")
        
        assert result.structuralScore < 0.2
    
    def test_suspiciousUrlHasHighScore(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Suspicious URLs have high structural scores."""
        result = urlAnalyzer.analyze(
            "http://paypal-verify-account.suspicious.tk@evil.com/login"
        )
        
        assert result.structuralScore > 0.5
    
    def test_morePatternsMeansHigherScore(self, urlAnalyzer: UrlAnalyzer) -> None:
        """More patterns increase the structural score."""
        simpleUrl = urlAnalyzer.analyze("https://example.tk")
        complexUrl = urlAnalyzer.analyze(
            "http://paypal-login.example.tk/verify-password"
        )
        
        assert complexUrl.structuralScore > simpleUrl.structuralScore
    
    def test_httpPenalty(self, urlAnalyzer: UrlAnalyzer) -> None:
        """HTTP URLs have score penalty."""
        httpResult = urlAnalyzer.analyze("http://example.com/suspicious")
        httpsResult = urlAnalyzer.analyze("https://example.com/suspicious")
        
        assert httpResult.structuralScore >= httpsResult.structuralScore


# =============================================================================
# Pattern Severity Tests
# =============================================================================

class TestPatternSeverity:
    """Tests for pattern severity properties."""
    
    def test_patternCountProperty(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Pattern count property works correctly."""
        result = urlAnalyzer.analyze("https://paypal-login.example.tk")
        
        assert result.patternCount >= 2
    
    def test_maxSeverityProperty(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Max severity property returns highest severity."""
        result = urlAnalyzer.analyze("https://paypal@evil.tk")
        
        # @ has severity 0.95, paypal has 0.9
        assert result.maxPatternSeverity >= 0.9
    
    def test_averageSeverityProperty(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Average severity is calculated correctly."""
        result = urlAnalyzer.analyze("https://paypal-login.example.tk")
        
        if result.patternCount > 0:
            assert 0 < result.averagePatternSeverity <= 1
    
    def test_noPatternsSeverityZero(self, urlAnalyzer: UrlAnalyzer) -> None:
        """No patterns means zero severity."""
        result = urlAnalyzer.analyze("https://example.com")
        
        if result.patternCount == 0:
            assert result.maxPatternSeverity == 0
            assert result.averagePatternSeverity == 0


# =============================================================================
# Analysis Notes Tests
# =============================================================================

class TestAnalysisNotes:
    """Tests for analysis notes generation."""
    
    def test_legitDomainNoted(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Legitimate domains are noted."""
        result = urlAnalyzer.analyze("https://www.google.com")
        
        assert any("legitimate" in note.lower() for note in result.analysisNotes)
    
    def test_httpNoted(self, urlAnalyzer: UrlAnalyzer) -> None:
        """HTTP usage is noted."""
        result = urlAnalyzer.analyze("http://example.com")
        
        assert any("https" in note.lower() for note in result.analysisNotes)
    
    def test_noPatternsNoted(self, urlAnalyzer: UrlAnalyzer) -> None:
        """No suspicious patterns is noted."""
        result = urlAnalyzer.analyze("https://example.com")
        
        if result.patternCount == 0:
            assert any("no suspicious" in note.lower() for note in result.analysisNotes)
    
    def test_highSeverityNoted(self, urlAnalyzer: UrlAnalyzer) -> None:
        """High severity patterns are noted."""
        result = urlAnalyzer.analyze("https://paypal@evil.tk/login")
        
        assert any("high-severity" in note.lower() for note in result.analysisNotes)


# =============================================================================
# Convenience Function Tests
# =============================================================================

class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_analyzeUrl(self) -> None:
        """analyzeUrl convenience function works."""
        result = analyzeUrl("https://example.com")
        
        assert isinstance(result, UrlAnalysisResult)
        assert result.domain == "example.com"
    
    def test_detectBrandImpersonation(self) -> None:
        """detectBrandImpersonation returns only brand patterns."""
        patterns = detectBrandImpersonation("https://paypal-fake.tk")
        
        assert all(p.patternType == "brand_impersonation" for p in patterns)
        assert len(patterns) >= 1
    
    def test_detectUrlObfuscation(self) -> None:
        """detectUrlObfuscation returns only obfuscation patterns."""
        patterns = detectUrlObfuscation("https://example.com@evil.tk")
        
        assert all(p.patternType == "url_obfuscation" for p in patterns)
        assert len(patterns) >= 1
    
    def test_getUrlRiskLevelSafe(self) -> None:
        """getUrlRiskLevel returns safe for safe URLs."""
        level = getUrlRiskLevel("https://google.com")
        
        assert level == "safe"
    
    def test_getUrlRiskLevelHigh(self) -> None:
        """getUrlRiskLevel returns high for suspicious URLs."""
        level = getUrlRiskLevel("http://paypal-verify@evil.tk/login")
        
        assert level in ["high", "critical"]


# =============================================================================
# Pattern Constant Tests
# =============================================================================

class TestPatternConstants:
    """Tests for pattern constants."""
    
    def test_brandPatternsNotEmpty(self) -> None:
        """BRAND_PATTERNS is not empty."""
        assert len(BRAND_PATTERNS) > 0
    
    def test_obfuscationPatternsNotEmpty(self) -> None:
        """OBFUSCATION_PATTERNS is not empty."""
        assert len(OBFUSCATION_PATTERNS) > 0
    
    def test_credentialPatternsNotEmpty(self) -> None:
        """CREDENTIAL_PATTERNS is not empty."""
        assert len(CREDENTIAL_PATTERNS) > 0
    
    def test_structurePatternsNotEmpty(self) -> None:
        """STRUCTURE_PATTERNS is not empty."""
        assert len(STRUCTURE_PATTERNS) > 0
    
    def test_urgencyPatternsNotEmpty(self) -> None:
        """URGENCY_PATTERNS is not empty."""
        assert len(URGENCY_PATTERNS) > 0
    
    def test_suspiciousTldPatternsNotEmpty(self) -> None:
        """SUSPICIOUS_TLD_PATTERNS is not empty."""
        assert len(SUSPICIOUS_TLD_PATTERNS) > 0
    
    def test_allPatternsCombined(self) -> None:
        """ALL_PATTERNS contains all pattern categories."""
        totalExpected = (
            len(BRAND_PATTERNS)
            + len(OBFUSCATION_PATTERNS)
            + len(CREDENTIAL_PATTERNS)
            + len(STRUCTURE_PATTERNS)
            + len(URGENCY_PATTERNS)
            + len(SUSPICIOUS_TLD_PATTERNS)
        )
        assert len(ALL_PATTERNS) == totalExpected
    
    def test_legitimateDomainsNotEmpty(self) -> None:
        """LEGITIMATE_BRAND_DOMAINS is not empty."""
        assert len(LEGITIMATE_BRAND_DOMAINS) > 0
    
    def test_legitimateDomainsAreLowercase(self) -> None:
        """All legitimate domains are lowercase."""
        for domain in LEGITIMATE_BRAND_DOMAINS:
            assert domain == domain.lower()


# =============================================================================
# Edge Case Tests
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases."""
    
    def test_veryLongUrl(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Very long URLs are handled."""
        longPath = "/segment" * 100
        result = urlAnalyzer.analyze(f"https://example.com{longPath}")
        
        assert isinstance(result, UrlAnalysisResult)
    
    def test_unicodeInUrl(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Unicode in URLs is handled."""
        result = urlAnalyzer.analyze("https://example.com/путь")
        
        assert isinstance(result, UrlAnalysisResult)
    
    def test_specialCharactersInUrl(self, urlAnalyzer: UrlAnalyzer) -> None:
        """Special characters in URLs are handled."""
        result = urlAnalyzer.analyze(
            "https://example.com/path?q=a&b=c#section"
        )
        
        assert isinstance(result, UrlAnalysisResult)
        assert result.query == "q=a&b=c"
        assert result.fragment == "section"
    
    def test_portInUrl(self, urlAnalyzer: UrlAnalyzer) -> None:
        """URLs with ports are handled."""
        result = urlAnalyzer.analyze("https://example.com:8080/path")
        
        assert result.domain == "example.com"
    
    def test_ipv6Url(self, urlAnalyzer: UrlAnalyzer) -> None:
        """IPv6 URLs are handled."""
        result = urlAnalyzer.analyze("http://[::1]/test")
        
        assert isinstance(result, UrlAnalysisResult)
