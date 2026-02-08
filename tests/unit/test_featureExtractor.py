"""
Unit Tests for Feature Extractor Module
========================================

Comprehensive tests for URL and OSINT feature extraction.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import pytest

from backend.ml.featureExtractor import (
    FeatureExtractor,
    extractFeatures,
    extractOsintFeatures,
    extractUrlFeatures,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
)
from backend.ml.schemas import FeatureSet, OsintFeatures, UrlFeatures


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def featureExtractor() -> FeatureExtractor:
    """Create a feature extractor instance."""
    return FeatureExtractor()


class MockWhoisResult:
    """Mock WHOIS result for testing."""
    
    def __init__(
        self,
        isSuccess: bool = True,
        domainAgeDays: int | None = 365,
        recentlyRegistered: bool = False,
        isPrivacyProtected: bool = False,
    ) -> None:
        self.isSuccess = isSuccess
        self.domainAgeDays = domainAgeDays
        self.recentlyRegistered = recentlyRegistered
        self.isPrivacyProtected = isPrivacyProtected


class MockDnsResult:
    """Mock DNS result for testing."""
    
    def __init__(
        self,
        isSuccess: bool = True,
        hasValidMx: bool = True,
        usesCdn: bool = False,
        aRecords: list | None = None,
        aaaaRecords: list | None = None,
        mxRecords: list | None = None,
        nsRecords: list | None = None,
        txtRecords: list | None = None,
    ) -> None:
        self.isSuccess = isSuccess
        self.hasValidMx = hasValidMx
        self.usesCdn = usesCdn
        self.aRecords = aRecords or ["1.2.3.4"]
        self.aaaaRecords = aaaaRecords or []
        self.mxRecords = mxRecords or [{"value": "mail.example.com"}]
        self.nsRecords = nsRecords or ["ns1.example.com"]
        self.txtRecords = txtRecords or ["v=spf1 include:example.com"]


class MockReputationResult:
    """Mock reputation result for testing."""
    
    def __init__(
        self,
        isSuccess: bool = True,
        aggregateScore: float = 0.0,
        knownMalicious: bool = False,
        maliciousCount: int = 0,
    ) -> None:
        self.isSuccess = isSuccess
        self.aggregateScore = aggregateScore
        self.knownMalicious = knownMalicious
        self.maliciousCount = maliciousCount


class MockOsintData:
    """Mock OSINT data for testing."""
    
    def __init__(
        self,
        whois: MockWhoisResult | None = None,
        dns: MockDnsResult | None = None,
        reputation: MockReputationResult | None = None,
    ) -> None:
        self.whois = whois
        self.dns = dns
        self.reputation = reputation


# =============================================================================
# URL Feature Extraction Tests
# =============================================================================

class TestExtractUrlFeatures:
    """Tests for extractUrlFeatures function."""
    
    def test_emptyUrlReturnsDefaultFeatures(self) -> None:
        """Empty URL returns default feature values."""
        features = extractUrlFeatures("")
        
        assert features.urlLength == 0
        assert features.domainLength == 0
        assert not features.hasIpAddress
        assert not features.isHttps
    
    def test_simpleHttpsUrl(self) -> None:
        """Simple HTTPS URL is correctly analyzed."""
        features = extractUrlFeatures("https://example.com")
        
        assert features.isHttps is True
        assert features.domainLength == len("example.com")
        assert features.subdomainCount == 0
        assert features.pathDepth == 0
        assert not features.hasSuspiciousTld
    
    def test_httpUrlNotSecure(self) -> None:
        """HTTP URL is marked as not HTTPS."""
        features = extractUrlFeatures("http://example.com")
        
        assert features.isHttps is False
    
    def test_urlWithoutScheme(self) -> None:
        """URL without scheme is normalized with http://."""
        features = extractUrlFeatures("example.com")
        
        assert features.domainLength == len("example.com")
    
    def test_ipAddressDetection(self) -> None:
        """IP address in URL is detected."""
        features = extractUrlFeatures("http://192.168.1.1/login")
        
        assert features.hasIpAddress is True
    
    def test_ipv6AddressDetection(self) -> None:
        """IPv6 address in URL is detected."""
        features = extractUrlFeatures("http://[::1]/test")
        
        assert features.hasIpAddress is True
    
    def test_subdomainCounting(self) -> None:
        """Subdomains are correctly counted."""
        # No subdomains
        features = extractUrlFeatures("https://example.com")
        assert features.subdomainCount == 0
        
        # One subdomain
        features = extractUrlFeatures("https://www.example.com")
        assert features.subdomainCount == 1
        
        # Multiple subdomains
        features = extractUrlFeatures("https://mail.secure.example.com")
        assert features.subdomainCount == 2
    
    def test_twoPartTldHandling(self) -> None:
        """Two-part TLDs (e.g., .co.uk) are handled correctly."""
        features = extractUrlFeatures("https://www.example.co.uk")
        
        # www is the only subdomain
        assert features.subdomainCount == 1
    
    def test_pathDepthCalculation(self) -> None:
        """Path depth is correctly calculated."""
        # No path
        features = extractUrlFeatures("https://example.com")
        assert features.pathDepth == 0
        
        # Root path
        features = extractUrlFeatures("https://example.com/")
        assert features.pathDepth == 0
        
        # Shallow path
        features = extractUrlFeatures("https://example.com/page")
        assert features.pathDepth == 1
        
        # Deep path
        features = extractUrlFeatures("https://example.com/a/b/c/d")
        assert features.pathDepth == 4
    
    def test_atSymbolDetection(self) -> None:
        """@ symbol in URL is detected."""
        features = extractUrlFeatures("https://legitimate.com@evil.com")
        
        assert features.hasAtSymbol is True
    
    def test_doubleSlashDetection(self) -> None:
        """Double slash in path is detected."""
        features = extractUrlFeatures("https://example.com//redirect//page")
        
        assert features.hasDoubleSlash is True
    
    def test_dashInDomainDetection(self) -> None:
        """Dash in domain is detected."""
        features = extractUrlFeatures("https://my-domain.com")
        
        assert features.hasDashInDomain is True
    
    def test_underscoreInDomainDetection(self) -> None:
        """Underscore in domain is detected."""
        features = extractUrlFeatures("https://my_domain.com")
        
        assert features.hasUnderscoreInDomain is True
    
    def test_suspiciousTldDetection(self) -> None:
        """Suspicious TLDs are detected."""
        for tld in ["tk", "ml", "ga", "xyz", "click"]:
            features = extractUrlFeatures(f"https://example.{tld}")
            assert features.hasSuspiciousTld is True, f"Failed for TLD: {tld}"
    
    def test_legitimateTldNotFlagged(self) -> None:
        """Legitimate TLDs are not flagged."""
        for tld in ["com", "org", "net", "edu", "gov"]:
            features = extractUrlFeatures(f"https://example.{tld}")
            assert features.hasSuspiciousTld is False, f"Flagged TLD: {tld}"
    
    def test_digitRatioCalculation(self) -> None:
        """Digit ratio is correctly calculated."""
        # No digits
        features = extractUrlFeatures("https://example.com")
        assert features.digitRatio == 0.0
        
        # Some digits
        features = extractUrlFeatures("https://example123.com")
        # "example123.com" has 3 digits out of 14 chars
        assert 0.2 < features.digitRatio < 0.25
    
    def test_queryParameterCounting(self) -> None:
        """Query parameters are correctly counted."""
        # No params
        features = extractUrlFeatures("https://example.com")
        assert features.queryParamCount == 0
        
        # Single param
        features = extractUrlFeatures("https://example.com?id=1")
        assert features.queryParamCount == 1
        
        # Multiple params
        features = extractUrlFeatures("https://example.com?a=1&b=2&c=3")
        assert features.queryParamCount == 3
    
    def test_encodedCharDetection(self) -> None:
        """URL-encoded characters are detected."""
        features = extractUrlFeatures("https://example.com/%2F%2F")
        
        assert features.hasEncodedChars is True
    
    def test_suspiciousKeywordDetection(self) -> None:
        """Suspicious keywords are detected."""
        for keyword in ["login", "verify", "secure", "account"]:
            features = extractUrlFeatures(f"https://example.com/{keyword}")
            assert features.hasSuspiciousKeywords is True, f"Missed keyword: {keyword}"
    
    def test_portNumberDetection(self) -> None:
        """Explicit port numbers are detected."""
        # Standard ports are not flagged
        features = extractUrlFeatures("https://example.com:443/")
        assert features.hasPortNumber is False
        
        # Non-standard ports are flagged
        features = extractUrlFeatures("https://example.com:8080/")
        assert features.hasPortNumber is True
    
    def test_suspiciousFeatureCount(self) -> None:
        """Suspicious feature count is calculated correctly."""
        # Highly suspicious URL
        features = extractUrlFeatures("http://192.168.1.1@verify.example.tk:8080")
        
        # Should have multiple suspicious features
        assert features.suspiciousFeatureCount >= 3
    
    def test_isHighlyStructured(self) -> None:
        """Complex URL structure is detected."""
        # Simple URL
        features = extractUrlFeatures("https://example.com")
        assert features.isHighlyStructured is False
        
        # Complex URL
        features = extractUrlFeatures(
            "https://a.b.c.example.com/1/2/3/4/5?x=1&y=2&z=3"
        )
        assert features.isHighlyStructured is True


# =============================================================================
# OSINT Feature Extraction Tests
# =============================================================================

class TestExtractOsintFeatures:
    """Tests for extractOsintFeatures function."""
    
    def test_noOsintDataReturnsDefaults(self) -> None:
        """No OSINT data returns default features."""
        features = extractOsintFeatures()
        
        assert features.domainAgeDays is None
        assert features.isNewlyRegistered is False
        assert features.hasValidWhois is False
        assert features.hasValidDns is False
    
    def test_whoisFeaturesExtracted(self) -> None:
        """WHOIS features are correctly extracted."""
        whois = MockWhoisResult(
            isSuccess=True,
            domainAgeDays=30,
            recentlyRegistered=True,
            isPrivacyProtected=True,
        )
        
        features = extractOsintFeatures(whoisResult=whois)
        
        assert features.domainAgeDays == 30
        assert features.isNewlyRegistered is True
        assert features.hasPrivacyProtection is True
        assert features.hasValidWhois is True
    
    def test_youngDomainDetection(self) -> None:
        """Young domains (< 365 days) are detected."""
        whois = MockWhoisResult(domainAgeDays=200)
        
        features = extractOsintFeatures(whoisResult=whois)
        
        assert features.isYoungDomain is True
    
    def test_oldDomainNotYoung(self) -> None:
        """Old domains are not marked as young."""
        whois = MockWhoisResult(domainAgeDays=500)
        
        features = extractOsintFeatures(whoisResult=whois)
        
        assert features.isYoungDomain is False
    
    def test_failedWhoisNotExtracted(self) -> None:
        """Failed WHOIS lookup doesn't set features."""
        whois = MockWhoisResult(isSuccess=False)
        
        features = extractOsintFeatures(whoisResult=whois)
        
        assert features.hasValidWhois is False
    
    def test_dnsFeaturesExtracted(self) -> None:
        """DNS features are correctly extracted."""
        dns = MockDnsResult(
            isSuccess=True,
            hasValidMx=True,
            usesCdn=True,
            aRecords=["1.2.3.4", "5.6.7.8"],
            mxRecords=[{"value": "mx1.example.com"}],
        )
        
        features = extractOsintFeatures(dnsResult=dns)
        
        assert features.hasValidMx is True
        assert features.usesCdn is True
        assert features.hasValidDns is True
        assert features.dnsRecordCount >= 2
    
    def test_failedDnsNotExtracted(self) -> None:
        """Failed DNS lookup doesn't set features."""
        dns = MockDnsResult(isSuccess=False)
        
        features = extractOsintFeatures(dnsResult=dns)
        
        assert features.hasValidDns is False
    
    def test_reputationFeaturesExtracted(self) -> None:
        """Reputation features are correctly extracted."""
        reputation = MockReputationResult(
            isSuccess=True,
            aggregateScore=0.7,
            knownMalicious=True,
            maliciousCount=3,
        )
        
        features = extractOsintFeatures(reputationResult=reputation)
        
        assert features.reputationScore == 0.7
        assert features.isKnownMalicious is True
        assert features.maliciousSourceCount == 3
    
    def test_combinedOsintFeatures(self) -> None:
        """All OSINT sources are combined correctly."""
        whois = MockWhoisResult(domainAgeDays=100, recentlyRegistered=False)
        dns = MockDnsResult(hasValidMx=True, usesCdn=False)
        reputation = MockReputationResult(aggregateScore=0.2)
        
        features = extractOsintFeatures(
            whoisResult=whois,
            dnsResult=dns,
            reputationResult=reputation,
        )
        
        assert features.domainAgeDays == 100
        assert features.hasValidMx is True
        assert features.reputationScore == 0.2
        assert features.dataCompleteness == 1.0
    
    def test_osintRiskIndicators(self) -> None:
        """OSINT risk indicators are correctly counted."""
        whois = MockWhoisResult(
            domainAgeDays=10,
            recentlyRegistered=True,
            isPrivacyProtected=True,
        )
        dns = MockDnsResult(hasValidMx=False)
        reputation = MockReputationResult(maliciousCount=1)
        
        features = extractOsintFeatures(
            whoisResult=whois,
            dnsResult=dns,
            reputationResult=reputation,
        )
        
        # Should have: newly registered, privacy, no MX, malicious count
        assert features.osintRiskIndicators >= 3


# =============================================================================
# Feature Extractor Class Tests
# =============================================================================

class TestFeatureExtractor:
    """Tests for FeatureExtractor class."""
    
    def test_extractWithUrlOnly(
        self,
        featureExtractor: FeatureExtractor,
    ) -> None:
        """Extract features from URL only."""
        features = featureExtractor.extract("https://example.com")
        
        assert isinstance(features, FeatureSet)
        assert features.url == "https://example.com"
        assert features.domain == "example.com"
        assert features.urlFeatures.isHttps is True
        assert features.extractionDurationMs >= 0
    
    def test_extractWithOsintData(
        self,
        featureExtractor: FeatureExtractor,
    ) -> None:
        """Extract features with OSINT data."""
        osintData = MockOsintData(
            whois=MockWhoisResult(domainAgeDays=1000),
            dns=MockDnsResult(hasValidMx=True),
            reputation=MockReputationResult(aggregateScore=0.0),
        )
        
        features = featureExtractor.extract("https://example.com", osintData)
        
        assert features.osintFeatures.domainAgeDays == 1000
        assert features.osintFeatures.hasValidMx is True
        assert features.osintFeatures.reputationScore == 0.0
    
    def test_extractUrlFeaturesOnly(
        self,
        featureExtractor: FeatureExtractor,
    ) -> None:
        """Extract only URL features."""
        features = featureExtractor.extractUrlFeaturesOnly(
            "https://suspicious.tk/login"
        )
        
        assert isinstance(features, UrlFeatures)
        assert features.hasSuspiciousTld is True
        assert features.hasSuspiciousKeywords is True
    
    def test_extractOsintFeaturesOnly(
        self,
        featureExtractor: FeatureExtractor,
    ) -> None:
        """Extract only OSINT features."""
        whois = MockWhoisResult(domainAgeDays=500)
        dns = MockDnsResult(usesCdn=True)
        
        features = featureExtractor.extractOsintFeaturesOnly(
            whoisResult=whois,
            dnsResult=dns,
        )
        
        assert isinstance(features, OsintFeatures)
        assert features.domainAgeDays == 500
        assert features.usesCdn is True
    
    def test_domainExtraction(
        self,
        featureExtractor: FeatureExtractor,
    ) -> None:
        """Domain is correctly extracted from URL."""
        testCases = [
            ("https://example.com", "example.com"),
            ("http://www.example.com", "www.example.com"),
            ("https://example.com:8080", "example.com"),
            ("example.com/path", "example.com"),
        ]
        
        for url, expectedDomain in testCases:
            features = featureExtractor.extract(url)
            assert features.domain == expectedDomain, f"Failed for URL: {url}"
    
    def test_totalRiskIndicators(
        self,
        featureExtractor: FeatureExtractor,
    ) -> None:
        """Total risk indicators combines URL and OSINT indicators."""
        osintData = MockOsintData(
            whois=MockWhoisResult(recentlyRegistered=True),
            reputation=MockReputationResult(maliciousCount=1),
        )
        
        features = featureExtractor.extract(
            "http://192.168.1.1@verify.example.tk",
            osintData,
        )
        
        # URL: IP address, @, suspicious TLD, keywords
        # OSINT: newly registered, malicious count
        assert features.totalRiskIndicators >= 4
    
    def test_hasCompleteData(
        self,
        featureExtractor: FeatureExtractor,
    ) -> None:
        """hasCompleteData reflects OSINT completeness."""
        # Incomplete data
        features = featureExtractor.extract("https://example.com")
        assert features.hasCompleteData is False
        
        # Complete data
        osintData = MockOsintData(
            whois=MockWhoisResult(),
            dns=MockDnsResult(),
            reputation=MockReputationResult(),
        )
        features = featureExtractor.extract("https://example.com", osintData)
        assert features.hasCompleteData is True


# =============================================================================
# Convenience Function Tests
# =============================================================================

class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_extractFeatures(self) -> None:
        """extractFeatures convenience function works."""
        features = extractFeatures("https://example.com")
        
        assert isinstance(features, FeatureSet)
        assert features.url == "https://example.com"
    
    def test_extractFeaturesWithOsint(self) -> None:
        """extractFeatures works with OSINT data."""
        osintData = MockOsintData(
            whois=MockWhoisResult(domainAgeDays=3000),
        )
        
        features = extractFeatures("https://google.com", osintData)
        
        assert features.osintFeatures.domainAgeDays == 3000


# =============================================================================
# Constants Tests
# =============================================================================

class TestConstants:
    """Tests for module constants."""
    
    def test_suspiciousTldsNotEmpty(self) -> None:
        """SUSPICIOUS_TLDS constant is not empty."""
        assert len(SUSPICIOUS_TLDS) > 0
    
    def test_suspiciousTldsAreLowercase(self) -> None:
        """All suspicious TLDs are lowercase."""
        for tld in SUSPICIOUS_TLDS:
            assert tld == tld.lower()
    
    def test_suspiciousKeywordsNotEmpty(self) -> None:
        """SUSPICIOUS_KEYWORDS constant is not empty."""
        assert len(SUSPICIOUS_KEYWORDS) > 0
    
    def test_suspiciousKeywordsAreLowercase(self) -> None:
        """All suspicious keywords are lowercase."""
        for keyword in SUSPICIOUS_KEYWORDS:
            assert keyword == keyword.lower()


# =============================================================================
# Edge Case Tests
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""
    
    def test_invalidUrlHandled(self) -> None:
        """Invalid URLs are handled gracefully."""
        features = extractUrlFeatures("not a valid url :::///")
        
        # Should return some features without crashing
        assert isinstance(features, UrlFeatures)
    
    def test_veryLongUrl(self) -> None:
        """Very long URLs are handled."""
        longPath = "/a" * 500
        features = extractUrlFeatures(f"https://example.com{longPath}")
        
        assert features.urlLength > 1000
        assert features.pathDepth > 100
    
    def test_unicodeInUrl(self) -> None:
        """Unicode in URLs is handled."""
        features = extractUrlFeatures("https://example.com/путь")
        
        assert isinstance(features, UrlFeatures)
    
    def test_emptyDomain(self) -> None:
        """Empty domain is handled."""
        features = extractUrlFeatures("http:///path")
        
        assert features.domainLength == 0
    
    def test_nullBytesInUrl(self) -> None:
        """Null bytes in URLs are handled."""
        features = extractUrlFeatures("https://example.com/path%00")
        
        assert features.hasEncodedChars is True
