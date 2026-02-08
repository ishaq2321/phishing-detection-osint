"""
Integration Tests for OSINT Pipeline
=====================================

Tests the complete OSINT data collection workflow:
- WHOIS lookup → DNS resolution → Reputation check
- OsintData aggregation
- Error handling and graceful degradation

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timedelta

from osint import (
    WhoisLookup,
    DnsChecker,
    ReputationChecker,
    OsintData,
    WhoisResult,
    DnsResult,
    ReputationResult,
    LookupStatus,
    DataSource,
    DnsRecord,
    DnsRecordType,
    ReputationCheck,
    ReputationSource,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def mockWhoisClient():
    """Mock WHOIS client returning valid data."""
    client = MagicMock()
    client.lookup = AsyncMock(return_value={
        "domain_name": "example.com",
        "registrar": "Example Registrar",
        "creation_date": datetime.now() - timedelta(days=365),
        "expiration_date": datetime.now() + timedelta(days=365),
        "registrant_name": "John Doe",
        "registrant_email": "john@example.com",
        "name_servers": ["ns1.example.com", "ns2.example.com"],
    })
    return client


@pytest.fixture
def mockDnsResolver():
    """Mock DNS resolver returning A records."""
    resolver = MagicMock()
    mockAnswer = MagicMock()
    mockAnswer.address = "93.184.216.34"
    resolver.resolve.return_value = [mockAnswer]
    return resolver


@pytest.fixture
def mockReputationClient():
    """Mock reputation client returning clean result."""
    client = MagicMock()
    client.checkDomain = AsyncMock(return_value=ReputationCheck(
        source=ReputationSource.INTERNAL,
        isMalicious=False,
        confidence=0.95,
        category="clean"
    ))
    client.checkIp = AsyncMock(return_value=ReputationCheck(
        source=ReputationSource.INTERNAL,
        isMalicious=False,
        confidence=0.95,
        category="clean"
    ))
    return client


# =============================================================================
# Full OSINT Pipeline Tests
# =============================================================================

class TestOsintPipelineSuccess:
    """Test successful OSINT data collection."""
    
    @pytest.mark.asyncio
    async def test_collectAllOsintData(
        self,
        mockWhoisClient,
        mockDnsResolver,
        mockReputationClient
    ):
        """Test complete OSINT collection with all sources."""
        # Setup checkers
        whoisLookup = WhoisLookup(client=mockWhoisClient)
        dnsChecker = DnsChecker(resolver=mockDnsResolver)
        reputationChecker = ReputationChecker(
            client=mockReputationClient,
            sources=[ReputationSource.INTERNAL]
        )
        
        # Collect WHOIS data
        whoisResult = await whoisLookup.lookup("example.com")
        assert whoisResult.status == LookupStatus.SUCCESS
        assert whoisResult.domainAgeDays is None or whoisResult.domainAgeDays >= 365
        
        # Collect DNS data
        dnsResult = await dnsChecker.lookup("example.com")
        assert dnsResult.status == LookupStatus.SUCCESS
        assert len(dnsResult.ipAddresses) > 0
        
        # Collect reputation data
        reputationResult = await reputationChecker.lookup(
            "example.com",
            ipAddresses=dnsResult.ipAddresses
        )
        assert reputationResult.status == LookupStatus.SUCCESS
        assert reputationResult.aggregateScore < 0.5
        
        # Aggregate into OsintData
        osintData = OsintData(
            domain="example.com",
            whois=whoisResult,
            dns=dnsResult,
            reputation=reputationResult
        )
        
        # Verify aggregation
        assert osintData.domain == "example.com"
        assert osintData.hasWhois is True
        assert osintData.dataQualityScore >= 0.8
        
    @pytest.mark.asyncio
    async def test_osintDataWithPartialFailure(
        self,
        mockWhoisClient,
        mockReputationClient
    ):
        """Test OSINT collection when DNS fails but other sources work."""
        whoisLookup = WhoisLookup(client=mockWhoisClient)
        
        # DNS that fails
        failingResolver = MagicMock()
        failingResolver.resolve.side_effect = Exception("DNS error")
        dnsChecker = DnsChecker(resolver=failingResolver, maxRetries=0)
        
        reputationChecker = ReputationChecker(
            client=mockReputationClient,
            sources=[ReputationSource.INTERNAL]
        )
        
        # Collect data
        whoisResult = await whoisLookup.lookup("example.com")
        dnsResult = await dnsChecker.lookup("example.com")
        reputationResult = await reputationChecker.lookup("example.com")
        
        # Verify partial success
        assert whoisResult.status == LookupStatus.SUCCESS
        assert dnsResult.status == LookupStatus.ERROR
        assert reputationResult.status == LookupStatus.SUCCESS
        
        # OsintData should still work
        osintData = OsintData(
            domain="example.com",
            whois=whoisResult,
            dns=dnsResult,
            reputation=reputationResult
        )
        
        assert osintData.hasWhois is True
        assert osintData.dataQualityScore < 1.0  # Lower due to DNS failure


class TestOsintPipelineTimings:
    """Test OSINT pipeline performance and timing."""
    
    @pytest.mark.asyncio
    async def test_osintCollectionTiming(
        self,
        mockWhoisClient,
        mockDnsResolver,
        mockReputationClient
    ):
        """Test that OSINT collection completes in reasonable time."""
        whoisLookup = WhoisLookup(client=mockWhoisClient)
        dnsChecker = DnsChecker(resolver=mockDnsResolver)
        reputationChecker = ReputationChecker(
            client=mockReputationClient,
            sources=[ReputationSource.INTERNAL]
        )
        
        startTime = datetime.now()
        
        # Run in sequence (parallel execution tested elsewhere)
        whoisResult = await whoisLookup.lookup("example.com")
        dnsResult = await dnsChecker.lookup("example.com")
        reputationResult = await reputationChecker.lookup("example.com")
        
        endTime = datetime.now()
        duration = (endTime - startTime).total_seconds()
        
        # Should complete quickly with mocks
        assert duration < 1.0
        
        # All should have timing data
        assert whoisResult.durationMs >= 0
        assert dnsResult.durationMs >= 0
        assert reputationResult.durationMs >= 0


class TestOsintDataAggregation:
    """Test OsintData aggregation and computed properties."""
    
    def test_osintDataQualityScore(self):
        """Test data quality score calculation."""
        # All successful
        whoisResult = WhoisResult(
            domain="example.com",
            status=LookupStatus.SUCCESS,
            registrar="Test",
            creationDate=datetime.now() - timedelta(days=365)
        )
        dnsResult = DnsResult(
            domain="example.com",
            status=LookupStatus.SUCCESS,
            records=[
                DnsRecord(
                    recordType=DnsRecordType.A,
                    value="1.2.3.4",
                    ttl=300
                )
            ]
        )
        reputationResult = ReputationResult(
            domain="example.com",
            status=LookupStatus.SUCCESS,
            checks=[],
            aggregateScore=0.0
        )
        
        osintData = OsintData(
            domain="example.com",
            whois=whoisResult,
            dns=dnsResult,
            reputation=reputationResult
        )
        
        # All successful = high quality
        assert osintData.dataQualityScore == 1.0
        
        # With DNS failure
        dnsResult.status = LookupStatus.ERROR
        osintDataPartial = OsintData(
            domain="example.com",
            whois=whoisResult,
            dns=dnsResult,
            reputation=reputationResult
        )
        
        # Lower quality due to missing DNS
        assert 0.6 <= osintDataPartial.dataQualityScore < 1.0


class TestOsintErrorHandling:
    """Test OSINT pipeline error handling and recovery."""
    
    @pytest.mark.asyncio
    async def test_allSourcesFailGracefully(self):
        """Test behavior when all OSINT sources fail."""
        # All failing clients
        failingWhoisClient = MagicMock()
        failingWhoisClient.lookup = AsyncMock(side_effect=Exception("WHOIS error"))
        
        failingResolver = MagicMock()
        failingResolver.resolve.side_effect = Exception("DNS error")
        
        failingReputationClient = MagicMock()
        failingReputationClient.checkDomain = AsyncMock(side_effect=Exception("API error"))
        
        whoisLookup = WhoisLookup(client=failingWhoisClient, maxRetries=0)
        dnsChecker = DnsChecker(resolver=failingResolver, maxRetries=0)
        reputationChecker = ReputationChecker(
            client=failingReputationClient,
            maxRetries=0,
            sources=[ReputationSource.INTERNAL]
        )
        
        # All should return ERROR status, not raise
        whoisResult = await whoisLookup.lookup("example.com")
        dnsResult = await dnsChecker.lookup("example.com")
        reputationResult = await reputationChecker.lookup("example.com")
        
        assert whoisResult.status == LookupStatus.ERROR
        assert dnsResult.status == LookupStatus.ERROR
        assert reputationResult.status == LookupStatus.ERROR
        
        # OsintData should still be creatable
        osintData = OsintData(
            domain="example.com",
            whois=whoisResult,
            dns=dnsResult,
            reputation=reputationResult
        )
        
        # Very low quality but doesn't crash
        assert osintData.dataQualityScore < 0.5


class TestOsintDomainNormalization:
    """Test domain normalization across OSINT modules."""
    
    @pytest.mark.asyncio
    async def test_domainNormalizedConsistently(self, mockWhoisClient):
        """Test that all OSINT modules normalize domains the same way."""
        whoisLookup = WhoisLookup(client=mockWhoisClient)
        
        # Test various URL formats
        testUrls = [
            "https://example.com/path",
            "http://www.example.com",
            "EXAMPLE.COM",
            "example.com/page?query=1"
        ]
        
        for url in testUrls:
            result = await whoisLookup.lookup(url)
            # Should all normalize to "example.com"
            assert result.domain == "example.com"
