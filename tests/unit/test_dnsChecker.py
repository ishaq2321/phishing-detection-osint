"""
Unit Tests for DNS Checker Module.

Comprehensive test coverage for DNS resolution functionality including:
- Record type parsing (A, AAAA, MX, NS, TXT, CNAME)
- CDN detection
- Mail configuration validation
- Error handling (timeout, NXDOMAIN, etc.)
- Domain normalization
- Retry logic

Author: Ishaq Muhammad
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import pytest
from unittest.mock import MagicMock

from osint.dnsChecker import (
    DnsChecker,
    DnsError,
    DnsTimeoutError,
    DnsNotFoundError,
    CDN_PATTERNS,
)
from osint.schemas import (
    DnsRecordType,
    LookupStatus,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mockDnsResolver():
    """Create a mock DNS resolver for testing."""
    resolver = MagicMock()
    resolver.resolve = MagicMock()
    return resolver


@pytest.fixture
def sampleDnsData():
    """Sample DNS data for a legitimate domain."""
    return {
        "A": [
            {"value": "93.184.216.34", "ttl": 3600},
        ],
        "AAAA": [
            {"value": "2606:2800:220:1:248:1893:25c8:1946", "ttl": 3600},
        ],
        "MX": [
            {"value": "mail.example.com", "ttl": 3600, "priority": 10},
            {"value": "mail2.example.com", "ttl": 3600, "priority": 20},
        ],
        "NS": [
            {"value": "ns1.example.com", "ttl": 86400},
            {"value": "ns2.example.com", "ttl": 86400},
        ],
        "TXT": [
            {"value": "v=spf1 include:_spf.example.com ~all", "ttl": 3600},
        ],
        "CNAME": [],
    }


@pytest.fixture
def cdnDnsData():
    """DNS data for a domain behind Cloudflare CDN."""
    return {
        "A": [
            {"value": "104.21.234.56", "ttl": 300},
            {"value": "172.67.123.45", "ttl": 300},
        ],
        "AAAA": [],
        "MX": [],
        "NS": [
            {"value": "bob.ns.cloudflare.com", "ttl": 86400},
            {"value": "lisa.ns.cloudflare.com", "ttl": 86400},
        ],
        "TXT": [],
        "CNAME": [],
    }


@pytest.fixture
def minimalDnsData():
    """DNS data with only A records (suspicious for phishing)."""
    return {
        "A": [{"value": "192.168.1.100", "ttl": 300}],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": [],
    }


@pytest.fixture
def mockResolverWithData(mockDnsResolver, sampleDnsData):
    """Configure mock resolver to return sample data."""
    def resolveFunc(domain: str, recordType: str):
        return sampleDnsData.get(recordType, [])
    
    mockDnsResolver.resolve.side_effect = resolveFunc
    return mockDnsResolver


@pytest.fixture
def mockResolverNotFound(mockDnsResolver):
    """Configure mock resolver to raise NXDOMAIN."""
    mockDnsResolver.resolve.side_effect = DnsNotFoundError(
        "Domain not found", "nonexistent.invalid"
    )
    return mockDnsResolver


@pytest.fixture
def mockResolverTimeout(mockDnsResolver):
    """Configure mock resolver to raise timeout."""
    mockDnsResolver.resolve.side_effect = DnsTimeoutError(
        "DNS timeout", "slow.example.com"
    )
    return mockDnsResolver


# =============================================================================
# DnsChecker Basic Tests
# =============================================================================

class TestDnsCheckerBasic:
    """Test basic DnsChecker functionality."""
    
    @pytest.mark.asyncio
    async def test_lookupSuccess(self, mockResolverWithData):
        """Test successful DNS lookup returns all records."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("example.com")
        
        assert result.status == LookupStatus.SUCCESS
        assert result.domain == "example.com"
        assert result.isSuccess
        assert not result.hasFailed
        assert result.durationMs > 0
    
    @pytest.mark.asyncio
    async def test_lookupReturnsARecords(self, mockResolverWithData):
        """Test A records are extracted correctly."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("example.com")
        
        assert len(result.aRecords) == 1
        assert "93.184.216.34" in result.aRecords
    
    @pytest.mark.asyncio
    async def test_lookupReturnsAAAARecords(self, mockResolverWithData):
        """Test AAAA (IPv6) records are extracted correctly."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("example.com")
        
        assert len(result.aaaaRecords) == 1
        assert "2606:2800:220:1:248:1893:25c8:1946" in result.aaaaRecords
    
    @pytest.mark.asyncio
    async def test_lookupReturnsMxRecords(self, mockResolverWithData):
        """Test MX records are extracted with priority."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("example.com")
        
        assert len(result.mxRecords) == 2
        assert result.mxRecords[0].recordType == DnsRecordType.MX
        assert result.mxRecords[0].value == "mail.example.com"
        assert result.mxRecords[0].priority == 10
    
    @pytest.mark.asyncio
    async def test_lookupReturnsNsRecords(self, mockResolverWithData):
        """Test NS records are extracted correctly."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("example.com")
        
        assert len(result.nsRecords) == 2
        assert "ns1.example.com" in result.nsRecords
    
    @pytest.mark.asyncio
    async def test_lookupReturnsTxtRecords(self, mockResolverWithData):
        """Test TXT records are extracted correctly."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("example.com")
        
        assert len(result.txtRecords) == 1
        assert "v=spf1" in result.txtRecords[0]
    
    @pytest.mark.asyncio
    async def test_ipAddressesProperty(self, mockResolverWithData):
        """Test ipAddresses property combines A and AAAA."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("example.com")
        
        assert len(result.ipAddresses) == 2
        assert result.hasIpAddresses


# =============================================================================
# CDN Detection Tests
# =============================================================================

class TestCdnDetection:
    """Test CDN detection functionality."""
    
    @pytest.mark.asyncio
    async def test_detectsCloudflare(self, mockDnsResolver, cdnDnsData):
        """Test Cloudflare CDN is detected from NS records."""
        def resolveFunc(domain: str, recordType: str):
            return cdnDnsData.get(recordType, [])
        
        mockDnsResolver.resolve.side_effect = resolveFunc
        checker = DnsChecker(resolver=mockDnsResolver)
        result = await checker.lookup("cdn-site.com")
        
        assert result.usesCdn
    
    @pytest.mark.asyncio
    async def test_detectsCdnFromCname(self, mockDnsResolver):
        """Test CDN detected from CNAME records."""
        def resolveFunc(domain: str, recordType: str):
            if recordType == "CNAME":
                return [{"value": "site.azureedge.net", "ttl": 300}]
            elif recordType == "A":
                return [{"value": "1.2.3.4", "ttl": 300}]
            return []
        
        mockDnsResolver.resolve.side_effect = resolveFunc
        checker = DnsChecker(resolver=mockDnsResolver)
        result = await checker.lookup("azure-site.com")
        
        assert result.usesCdn
    
    @pytest.mark.asyncio
    async def test_noCdnDetectedForRegularDomain(self, mockResolverWithData):
        """Test regular domain without CDN."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("example.com")
        
        assert not result.usesCdn
    
    def test_cdnPatternsIncludesMajorProviders(self):
        """Verify CDN patterns include major providers."""
        expectedProviders = ["cloudflare", "cloudfront", "akamai", "fastly"]
        for provider in expectedProviders:
            assert provider in CDN_PATTERNS


# =============================================================================
# Mail Configuration Tests
# =============================================================================

class TestMailConfiguration:
    """Test mail configuration validation."""
    
    @pytest.mark.asyncio
    async def test_hasValidMxWithMxRecords(self, mockResolverWithData):
        """Test hasValidMx is True when MX records exist."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("example.com")
        
        assert result.hasValidMx
    
    @pytest.mark.asyncio
    async def test_hasValidMxWithSpfOnly(self, mockDnsResolver):
        """Test hasValidMx is True with SPF record but no MX."""
        def resolveFunc(domain: str, recordType: str):
            if recordType == "TXT":
                return [{"value": "v=spf1 include:_spf.google.com ~all", "ttl": 3600}]
            elif recordType == "A":
                return [{"value": "1.2.3.4", "ttl": 300}]
            return []
        
        mockDnsResolver.resolve.side_effect = resolveFunc
        checker = DnsChecker(resolver=mockDnsResolver)
        result = await checker.lookup("spf-only.com")
        
        assert result.hasValidMx
    
    @pytest.mark.asyncio
    async def test_noValidMxWithoutMailRecords(self, mockDnsResolver, minimalDnsData):
        """Test hasValidMx is False without MX or SPF."""
        def resolveFunc(domain: str, recordType: str):
            return minimalDnsData.get(recordType, [])
        
        mockDnsResolver.resolve.side_effect = resolveFunc
        checker = DnsChecker(resolver=mockDnsResolver)
        result = await checker.lookup("no-mail.com")
        
        assert not result.hasValidMx


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestDnsErrorHandling:
    """Test DNS error handling."""
    
    @pytest.mark.asyncio
    async def test_lookupNotFound(self, mockResolverNotFound):
        """Test NXDOMAIN returns NOT_FOUND status."""
        checker = DnsChecker(resolver=mockResolverNotFound, maxRetries=0)
        result = await checker.lookup("nonexistent.invalid")
        
        assert result.status == LookupStatus.NOT_FOUND
        assert not result.isSuccess
        assert "not found" in result.errorMessage.lower()
    
    @pytest.mark.asyncio
    async def test_lookupTimeout(self, mockResolverTimeout):
        """Test timeout returns TIMEOUT status."""
        checker = DnsChecker(resolver=mockResolverTimeout, maxRetries=0)
        result = await checker.lookup("slow.example.com")
        
        assert result.status == LookupStatus.TIMEOUT
        assert not result.isSuccess
    
    @pytest.mark.asyncio
    async def test_lookupGenericError(self, mockDnsResolver):
        """Test generic DNS error returns ERROR status."""
        mockDnsResolver.resolve.side_effect = DnsError(
            "DNS server unavailable", "broken.com"
        )
        
        checker = DnsChecker(resolver=mockDnsResolver, maxRetries=0)
        result = await checker.lookup("broken.com")
        
        assert result.status == LookupStatus.ERROR
        assert not result.isSuccess
    
    @pytest.mark.asyncio
    async def test_emptyDomainReturnsError(self, mockResolverWithData):
        """Test empty domain returns error."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("")
        
        assert result.status == LookupStatus.ERROR
        assert "invalid" in result.errorMessage.lower()
    
    @pytest.mark.asyncio
    async def test_whitespaceDomainReturnsError(self, mockResolverWithData):
        """Test whitespace-only domain returns error."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("   ")
        
        assert result.status == LookupStatus.ERROR


# =============================================================================
# Retry Logic Tests
# =============================================================================

class TestDnsRetryLogic:
    """Test DNS retry functionality."""
    
    @pytest.mark.asyncio
    async def test_retryOnTransientError(self, mockDnsResolver, sampleDnsData):
        """Test retry succeeds after transient failure."""
        callCount = {"value": 0}
        
        def resolveFunc(domain: str, recordType: str):
            callCount["value"] += 1
            if callCount["value"] <= 6:  # First call per record type fails
                raise DnsError("Temporary error", domain)
            return sampleDnsData.get(recordType, [])
        
        mockDnsResolver.resolve.side_effect = resolveFunc
        checker = DnsChecker(resolver=mockDnsResolver, maxRetries=2, retryDelay=0.01)
        result = await checker.lookup("retry-test.com")
        
        # Should succeed after retries
        assert result.status == LookupStatus.SUCCESS
    
    @pytest.mark.asyncio
    async def test_noRetryOnNxdomain(self, mockDnsResolver):
        """Test NXDOMAIN does not trigger retry."""
        callCount = {"value": 0}
        
        def resolveFunc(domain: str, recordType: str):
            callCount["value"] += 1
            raise DnsNotFoundError("Domain not found", domain)
        
        mockDnsResolver.resolve.side_effect = resolveFunc
        checker = DnsChecker(resolver=mockDnsResolver, maxRetries=3, retryDelay=0.01)
        result = await checker.lookup("nxdomain.invalid")
        
        # Should not retry - only 6 calls (one per record type)
        assert callCount["value"] == 6
        assert result.status == LookupStatus.NOT_FOUND
    
    @pytest.mark.asyncio
    async def test_maxRetriesExhausted(self, mockDnsResolver):
        """Test all retries exhausted returns error."""
        mockDnsResolver.resolve.side_effect = DnsTimeoutError(
            "DNS timeout", "always-slow.com"
        )
        
        checker = DnsChecker(resolver=mockDnsResolver, maxRetries=2, retryDelay=0.01)
        result = await checker.lookup("always-slow.com")
        
        assert result.status == LookupStatus.TIMEOUT


# =============================================================================
# Domain Normalization Tests
# =============================================================================

class TestDomainNormalization:
    """Test domain normalization for DNS lookups."""
    
    @pytest.mark.asyncio
    async def test_removesHttpsProtocol(self, mockResolverWithData):
        """Test HTTPS protocol is removed."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("https://example.com")
        
        assert result.domain == "example.com"
    
    @pytest.mark.asyncio
    async def test_removesHttpProtocol(self, mockResolverWithData):
        """Test HTTP protocol is removed."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("http://example.com")
        
        assert result.domain == "example.com"
    
    @pytest.mark.asyncio
    async def test_removesWwwPrefix(self, mockResolverWithData):
        """Test www prefix is removed."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("www.example.com")
        
        assert result.domain == "example.com"
    
    @pytest.mark.asyncio
    async def test_removesPath(self, mockResolverWithData):
        """Test URL path is removed."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("example.com/path/to/page")
        
        assert result.domain == "example.com"
    
    @pytest.mark.asyncio
    async def test_removesQueryString(self, mockResolverWithData):
        """Test query string is removed."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("example.com?query=value")
        
        assert result.domain == "example.com"
    
    @pytest.mark.asyncio
    async def test_removesPort(self, mockResolverWithData):
        """Test port number is removed."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("example.com:8080")
        
        assert result.domain == "example.com"
    
    @pytest.mark.asyncio
    async def test_convertsToLowercase(self, mockResolverWithData):
        """Test domain is converted to lowercase."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("EXAMPLE.COM")
        
        assert result.domain == "example.com"
    
    @pytest.mark.asyncio
    async def test_complexUrlNormalization(self, mockResolverWithData):
        """Test complex URL is fully normalized."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("https://WWW.Example.COM:443/path?q=1#hash")
        
        assert result.domain == "example.com"


# =============================================================================
# Convenience Function Tests
# =============================================================================

class TestLookupDnsFunction:
    """Test the lookupDns convenience function."""
    
    @pytest.mark.asyncio
    async def test_lookupDnsFunction(self, mockResolverWithData, monkeypatch):
        """Test lookupDns convenience function works."""
        # This test would need to monkeypatch DnsChecker
        # For now, we just verify the function signature
        from osint.dnsChecker import lookupDns as lookupDnsFunc
        
        # Verify function exists and is callable
        assert callable(lookupDnsFunc)


# =============================================================================
# Exception Tests
# =============================================================================

class TestDnsExceptions:
    """Test DNS exception classes."""
    
    def test_dnsErrorMessage(self):
        """Test DnsError stores message and domain."""
        error = DnsError("Test error", "test.com")
        
        assert str(error) == "Test error"
        assert error.domain == "test.com"
    
    def test_dnsTimeoutError(self):
        """Test DnsTimeoutError is a DnsError."""
        error = DnsTimeoutError("Timeout", "slow.com")
        
        assert isinstance(error, DnsError)
        assert error.domain == "slow.com"
    
    def test_dnsNotFoundError(self):
        """Test DnsNotFoundError is a DnsError."""
        error = DnsNotFoundError("Not found", "missing.com")
        
        assert isinstance(error, DnsError)
        assert error.domain == "missing.com"


# =============================================================================
# Context Manager Tests
# =============================================================================

class TestDnsContextManager:
    """Test async context manager functionality."""
    
    @pytest.mark.asyncio
    async def test_asyncContextManager(self, mockResolverWithData):
        """Test DnsChecker works as async context manager."""
        async with DnsChecker(resolver=mockResolverWithData) as checker:
            result = await checker.lookup("example.com")
        
        assert result.status == LookupStatus.SUCCESS


# =============================================================================
# Result Properties Tests
# =============================================================================

class TestDnsResultProperties:
    """Test DnsResult computed properties."""
    
    @pytest.mark.asyncio
    async def test_sourceIsDns(self, mockResolverWithData):
        """Test source is always DNS."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("example.com")
        
        from osint.schemas import DataSource
        assert result.source == DataSource.DNS
    
    @pytest.mark.asyncio
    async def test_hasIpAddressesTrue(self, mockResolverWithData):
        """Test hasIpAddresses returns True when IPs exist."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("example.com")
        
        assert result.hasIpAddresses
    
    @pytest.mark.asyncio
    async def test_hasIpAddressesFalse(self, mockDnsResolver):
        """Test hasIpAddresses returns False when no IPs."""
        def resolveFunc(domain: str, recordType: str):
            if recordType == "MX":
                return [{"value": "mail.example.com", "ttl": 3600, "priority": 10}]
            return []
        
        mockDnsResolver.resolve.side_effect = resolveFunc
        checker = DnsChecker(resolver=mockDnsResolver)
        result = await checker.lookup("mail-only.com")
        
        assert not result.hasIpAddresses
        assert result.ipAddresses == []


# =============================================================================
# Edge Cases Tests
# =============================================================================

class TestDnsEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_domainWithTrailingDot(self, mockResolverWithData):
        """Test domain with trailing dot is handled."""
        checker = DnsChecker(resolver=mockResolverWithData)
        result = await checker.lookup("example.com.")
        
        assert result.domain == "example.com"
    
    @pytest.mark.asyncio
    async def test_zeroRetries(self, mockDnsResolver):
        """Test with zero retries configured."""
        mockDnsResolver.resolve.side_effect = DnsError("Error", "test.com")
        
        checker = DnsChecker(resolver=mockDnsResolver, maxRetries=0)
        result = await checker.lookup("test.com")
        
        assert result.status == LookupStatus.ERROR
    
    @pytest.mark.asyncio
    async def test_emptyRecordsFromResolver(self, mockDnsResolver):
        """Test all record types returning empty."""
        mockDnsResolver.resolve.return_value = []
        
        checker = DnsChecker(resolver=mockDnsResolver)
        result = await checker.lookup("empty-records.com")
        
        # Empty records = domain not found
        assert result.status == LookupStatus.NOT_FOUND
