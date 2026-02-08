"""
Unit Tests for Reputation Checker Module.

Comprehensive test coverage for reputation lookup functionality including:
- VirusTotal API integration
- AbuseIPDB API integration
- Aggregate scoring
- Error handling (timeout, rate limit, API errors)
- Retry logic

Author: Ishaq Muhammad
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import pytest
from unittest.mock import MagicMock, AsyncMock

from osint.reputationChecker import (
    ReputationChecker,
    ReputationError,
    ReputationTimeoutError,
    ReputationApiError,
    ReputationRateLimitError,
)
from osint.schemas import (
    ReputationCheck,
    ReputationSource,
    LookupStatus,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mockReputationClient():
    """Create a mock reputation client for testing."""
    client = MagicMock()
    client.checkDomain = AsyncMock()
    client.checkIp = AsyncMock()
    client.close = AsyncMock()
    return client


@pytest.fixture
def cleanReputationCheck():
    """Reputation check indicating clean domain."""
    return ReputationCheck(
        source=ReputationSource.VIRUSTOTAL,
        isMalicious=False,
        confidence=0.0,
        category=None
    )


@pytest.fixture
def maliciousReputationCheck():
    """Reputation check indicating malicious domain."""
    return ReputationCheck(
        source=ReputationSource.VIRUSTOTAL,
        isMalicious=True,
        confidence=0.85,
        category="phishing"
    )


@pytest.fixture
def suspiciousReputationCheck():
    """Reputation check indicating suspicious domain."""
    return ReputationCheck(
        source=ReputationSource.ABUSEIPDB,
        isMalicious=True,
        confidence=0.65,
        category="web_spam"
    )


@pytest.fixture
def mockClientClean(mockReputationClient, cleanReputationCheck):
    """Configure mock client to return clean results."""
    mockReputationClient.checkDomain.return_value = cleanReputationCheck
    mockReputationClient.checkIp.return_value = cleanReputationCheck
    return mockReputationClient


@pytest.fixture
def mockClientMalicious(mockReputationClient, maliciousReputationCheck):
    """Configure mock client to return malicious results."""
    mockReputationClient.checkDomain.return_value = maliciousReputationCheck
    mockReputationClient.checkIp.return_value = maliciousReputationCheck
    return mockReputationClient


# =============================================================================
# ReputationChecker Basic Tests
# =============================================================================

class TestReputationCheckerBasic:
    """Test basic ReputationChecker functionality."""
    
    @pytest.mark.asyncio
    async def test_lookupSuccess(self, mockClientClean):
        """Test successful reputation lookup."""
        checker = ReputationChecker(
            client=mockClientClean,
            sources=[ReputationSource.INTERNAL]
        )
        result = await checker.lookup("example.com")
        
        assert result.status == LookupStatus.SUCCESS
        assert result.domain == "example.com"
        assert result.isSuccess
        assert result.durationMs > 0
    
    @pytest.mark.asyncio
    async def test_lookupReturnsChecks(self, mockClientClean):
        """Test lookup returns reputation checks."""
        checker = ReputationChecker(
            client=mockClientClean,
            sources=[ReputationSource.VIRUSTOTAL]
        )
        result = await checker.lookup("example.com")
        
        assert len(result.checks) >= 1
    
    @pytest.mark.asyncio
    async def test_cleanDomainNotMalicious(self, mockClientClean):
        """Test clean domain is not marked malicious."""
        checker = ReputationChecker(
            client=mockClientClean,
            sources=[ReputationSource.VIRUSTOTAL]
        )
        result = await checker.lookup("example.com")
        
        assert not result.knownMalicious
        assert result.aggregateScore < 0.5
    
    @pytest.mark.asyncio
    async def test_maliciousDomainDetected(self, mockClientMalicious):
        """Test malicious domain is properly detected."""
        checker = ReputationChecker(
            client=mockClientMalicious,
            sources=[ReputationSource.VIRUSTOTAL]
        )
        result = await checker.lookup("phishing-site.com")
        
        assert result.knownMalicious
        assert result.aggregateScore > 0.5
    
    @pytest.mark.asyncio
    async def test_categoriesExtracted(self, mockClientMalicious):
        """Test threat categories are extracted."""
        checker = ReputationChecker(
            client=mockClientMalicious,
            sources=[ReputationSource.VIRUSTOTAL]
        )
        result = await checker.lookup("phishing-site.com")
        
        assert "phishing" in result.categories


# =============================================================================
# Aggregate Score Tests
# =============================================================================

class TestAggregateScore:
    """Test aggregate score calculation."""
    
    @pytest.mark.asyncio
    async def test_cleanScoreNearZero(self, mockClientClean):
        """Test clean domain has low score."""
        checker = ReputationChecker(
            client=mockClientClean,
            sources=[ReputationSource.VIRUSTOTAL]
        )
        result = await checker.lookup("safe-site.com")
        
        assert result.aggregateScore == 0.0
    
    @pytest.mark.asyncio
    async def test_maliciousScoreHigh(self, mockClientMalicious):
        """Test malicious domain has high score."""
        checker = ReputationChecker(
            client=mockClientMalicious,
            sources=[ReputationSource.VIRUSTOTAL]
        )
        result = await checker.lookup("bad-site.com")
        
        assert result.aggregateScore > 0.7
    
    @pytest.mark.asyncio
    async def test_virusTotalWeightedHigher(self, mockReputationClient):
        """Test VirusTotal results are weighted higher."""
        # Configure two sources with same confidence
        vtCheck = ReputationCheck(
            source=ReputationSource.VIRUSTOTAL,
            isMalicious=True,
            confidence=0.5,
            category="malware"
        )
        internalCheck = ReputationCheck(
            source=ReputationSource.INTERNAL,
            isMalicious=False,
            confidence=0.0
        )
        
        async def checkDomain(domain, source):
            if source == ReputationSource.VIRUSTOTAL:
                return vtCheck
            return internalCheck
        
        mockReputationClient.checkDomain = AsyncMock(side_effect=checkDomain)
        
        checker = ReputationChecker(
            client=mockReputationClient,
            sources=[ReputationSource.VIRUSTOTAL, ReputationSource.INTERNAL]
        )
        result = await checker.lookup("test.com")
        
        # VT weight is 2.0, Internal is 1.0
        # Expected: (0.5 * 2.0 + 0 * 1.0) / (2.0 + 1.0) = 0.333...
        assert 0.3 < result.aggregateScore < 0.4
    
    @pytest.mark.asyncio
    async def test_scoreCapAtOne(self, mockReputationClient):
        """Test aggregate score is capped at 1.0."""
        highConfidenceCheck = ReputationCheck(
            source=ReputationSource.VIRUSTOTAL,
            isMalicious=True,
            confidence=1.0,
            category="phishing"
        )
        mockReputationClient.checkDomain.return_value = highConfidenceCheck
        
        checker = ReputationChecker(
            client=mockReputationClient,
            sources=[ReputationSource.VIRUSTOTAL]
        )
        result = await checker.lookup("very-bad.com")
        
        assert result.aggregateScore <= 1.0


# =============================================================================
# IP Address Check Tests
# =============================================================================

class TestIpAddressChecks:
    """Test IP address reputation checking."""
    
    @pytest.mark.asyncio
    async def test_checksIpAddresses(self, mockClientClean):
        """Test IP addresses are checked when provided."""
        checker = ReputationChecker(
            client=mockClientClean,
            sources=[ReputationSource.VIRUSTOTAL]
        )
        result = await checker.lookup(
            "example.com",
            ipAddresses=["1.2.3.4", "5.6.7.8"]
        )
        
        # Should call checkIp for each IP
        assert mockClientClean.checkIp.call_count >= 1
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_limitsIpChecks(self, mockClientClean):
        """Test IP checks are limited to prevent abuse."""
        checker = ReputationChecker(
            client=mockClientClean,
            sources=[ReputationSource.VIRUSTOTAL]
        )
        
        # Provide more than 5 IPs
        manyIps = [f"192.168.1.{i}" for i in range(20)]
        result = await checker.lookup("example.com", ipAddresses=manyIps)
        
        # Should only check first 5 IPs
        assert mockClientClean.checkIp.call_count <= 5
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_maliciousIpDetected(self, mockReputationClient, maliciousReputationCheck):
        """Test malicious IP contributes to score."""
        mockReputationClient.checkDomain.return_value = ReputationCheck(
            source=ReputationSource.VIRUSTOTAL,
            isMalicious=False,
            confidence=0.0
        )
        mockReputationClient.checkIp.return_value = maliciousReputationCheck
        
        checker = ReputationChecker(
            client=mockReputationClient,
            sources=[ReputationSource.VIRUSTOTAL]
        )
        result = await checker.lookup("example.com", ipAddresses=["1.2.3.4"])
        
        # IP check should contribute to malicious finding
        assert len(result.checks) >= 2


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestReputationErrorHandling:
    """Test reputation check error handling."""
    
    @pytest.mark.asyncio
    async def test_emptyDomainReturnsError(self, mockClientClean):
        """Test empty domain returns error."""
        checker = ReputationChecker(
            client=mockClientClean,
            sources=[ReputationSource.INTERNAL]
        )
        result = await checker.lookup("")
        
        assert result.status == LookupStatus.ERROR
        assert "invalid" in result.errorMessage.lower()
    
    @pytest.mark.asyncio
    async def test_apiErrorHandled(self, mockReputationClient):
        """Test API errors are handled gracefully."""
        mockReputationClient.checkDomain.side_effect = ReputationApiError(
            "API unavailable",
            source="virustotal",
            statusCode=500
        )
        
        checker = ReputationChecker(
            client=mockReputationClient,
            sources=[ReputationSource.VIRUSTOTAL],
            maxRetries=0
        )
        result = await checker.lookup("example.com")
        
        # Should return success with failed check, not crash
        assert result.status == LookupStatus.SUCCESS
    
    @pytest.mark.asyncio
    async def test_timeoutHandled(self, mockReputationClient):
        """Test timeout errors are handled."""
        mockReputationClient.checkDomain.side_effect = ReputationTimeoutError(
            "Request timeout",
            source="virustotal"
        )
        
        checker = ReputationChecker(
            client=mockReputationClient,
            sources=[ReputationSource.VIRUSTOTAL],
            maxRetries=0
        )
        result = await checker.lookup("slow-site.com")
        
        assert result.status == LookupStatus.SUCCESS
    
    @pytest.mark.asyncio
    async def test_rateLimitHandled(self, mockReputationClient):
        """Test rate limit errors are handled."""
        mockReputationClient.checkDomain.side_effect = ReputationRateLimitError(
            "Rate limit exceeded",
            source="virustotal",
            statusCode=429
        )
        
        checker = ReputationChecker(
            client=mockReputationClient,
            sources=[ReputationSource.VIRUSTOTAL],
            maxRetries=2
        )
        result = await checker.lookup("example.com")
        
        # Rate limits should not retry
        assert mockReputationClient.checkDomain.call_count == 1
        assert result is not None


# =============================================================================
# Retry Logic Tests
# =============================================================================

class TestReputationRetryLogic:
    """Test reputation check retry functionality."""
    
    @pytest.mark.asyncio
    async def test_retryOnTransientError(self, mockReputationClient, cleanReputationCheck):
        """Test retry succeeds after transient failure."""
        callCount = {"value": 0}
        
        async def checkDomain(domain, source):
            callCount["value"] += 1
            if callCount["value"] == 1:
                raise ReputationError("Temporary error", "virustotal")
            return cleanReputationCheck
        
        mockReputationClient.checkDomain = AsyncMock(side_effect=checkDomain)
        
        checker = ReputationChecker(
            client=mockReputationClient,
            sources=[ReputationSource.VIRUSTOTAL],
            maxRetries=2
        )
        result = await checker.lookup("retry-test.com")
        
        assert callCount["value"] == 2  # Initial + 1 retry
        assert result.status == LookupStatus.SUCCESS
    
    @pytest.mark.asyncio
    async def test_noRetryOnRateLimit(self, mockReputationClient):
        """Test rate limit does not trigger retry."""
        mockReputationClient.checkDomain.side_effect = ReputationRateLimitError(
            "Rate limit",
            source="virustotal",
            statusCode=429
        )
        
        checker = ReputationChecker(
            client=mockReputationClient,
            sources=[ReputationSource.VIRUSTOTAL],
            maxRetries=3
        )
        result = await checker.lookup("example.com")
        
        # Should only try once
        assert mockReputationClient.checkDomain.call_count == 1
        assert result is not None


# =============================================================================
# Domain Normalization Tests
# =============================================================================

class TestDomainNormalization:
    """Test domain normalization for reputation checks."""
    
    @pytest.mark.asyncio
    async def test_removesHttpsProtocol(self, mockClientClean):
        """Test HTTPS protocol is removed."""
        checker = ReputationChecker(
            client=mockClientClean,
            sources=[ReputationSource.INTERNAL]
        )
        result = await checker.lookup("https://example.com")
        
        assert result.domain == "example.com"
    
    @pytest.mark.asyncio
    async def test_removesWwwPrefix(self, mockClientClean):
        """Test www prefix is removed."""
        checker = ReputationChecker(
            client=mockClientClean,
            sources=[ReputationSource.INTERNAL]
        )
        result = await checker.lookup("www.example.com")
        
        assert result.domain == "example.com"
    
    @pytest.mark.asyncio
    async def test_removesPath(self, mockClientClean):
        """Test URL path is removed."""
        checker = ReputationChecker(
            client=mockClientClean,
            sources=[ReputationSource.INTERNAL]
        )
        result = await checker.lookup("example.com/phishing/page.html")
        
        assert result.domain == "example.com"
    
    @pytest.mark.asyncio
    async def test_convertsToLowercase(self, mockClientClean):
        """Test domain is converted to lowercase."""
        checker = ReputationChecker(
            client=mockClientClean,
            sources=[ReputationSource.INTERNAL]
        )
        result = await checker.lookup("EXAMPLE.COM")
        
        assert result.domain == "example.com"


# =============================================================================
# Exception Tests
# =============================================================================

class TestReputationExceptions:
    """Test reputation exception classes."""
    
    def test_reputationErrorMessage(self):
        """Test ReputationError stores message and source."""
        error = ReputationError("Test error", "virustotal")
        
        assert str(error) == "Test error"
        assert error.source == "virustotal"
    
    def test_reputationTimeoutError(self):
        """Test ReputationTimeoutError is a ReputationError."""
        error = ReputationTimeoutError("Timeout", "abuseipdb")
        
        assert isinstance(error, ReputationError)
        assert error.source == "abuseipdb"
    
    def test_reputationApiError(self):
        """Test ReputationApiError stores status code."""
        error = ReputationApiError("API error", "virustotal", statusCode=500)
        
        assert isinstance(error, ReputationError)
        assert error.statusCode == 500
    
    def test_reputationRateLimitError(self):
        """Test ReputationRateLimitError is an ApiError."""
        error = ReputationRateLimitError("Rate limit", "virustotal", statusCode=429)
        
        assert isinstance(error, ReputationApiError)
        assert error.statusCode == 429


# =============================================================================
# Context Manager Tests
# =============================================================================

class TestReputationContextManager:
    """Test async context manager functionality."""
    
    @pytest.mark.asyncio
    async def test_asyncContextManager(self, mockClientClean):
        """Test ReputationChecker works as async context manager."""
        async with ReputationChecker(
            client=mockClientClean,
            sources=[ReputationSource.INTERNAL]
        ) as checker:
            result = await checker.lookup("example.com")
        
        assert result.status == LookupStatus.SUCCESS
    
    @pytest.mark.asyncio
    async def test_contextManagerClosesClient(self, mockClientClean):
        """Test context manager closes client on exit."""
        async with ReputationChecker(
            client=mockClientClean,
            sources=[ReputationSource.INTERNAL]
        ):
            pass
        
        mockClientClean.close.assert_called_once()


# =============================================================================
# Result Properties Tests
# =============================================================================

class TestReputationResultProperties:
    """Test ReputationResult computed properties."""
    
    @pytest.mark.asyncio
    async def test_sourceIsReputation(self, mockClientClean):
        """Test source is always REPUTATION."""
        checker = ReputationChecker(
            client=mockClientClean,
            sources=[ReputationSource.INTERNAL]
        )
        result = await checker.lookup("example.com")
        
        from osint.schemas import DataSource
        assert result.source == DataSource.REPUTATION
    
    @pytest.mark.asyncio
    async def test_maliciousCountProperty(self, mockReputationClient):
        """Test maliciousCount property works."""
        maliciousCheck = ReputationCheck(
            source=ReputationSource.VIRUSTOTAL,
            isMalicious=True,
            confidence=0.9
        )
        cleanCheck = ReputationCheck(
            source=ReputationSource.INTERNAL,
            isMalicious=False,
            confidence=0.0
        )
        
        async def checkDomain(domain, source):
            if source == ReputationSource.VIRUSTOTAL:
                return maliciousCheck
            return cleanCheck
        
        mockReputationClient.checkDomain = AsyncMock(side_effect=checkDomain)
        
        checker = ReputationChecker(
            client=mockReputationClient,
            sources=[ReputationSource.VIRUSTOTAL, ReputationSource.INTERNAL]
        )
        result = await checker.lookup("example.com")
        
        assert result.maliciousCount == 1


# =============================================================================
# Convenience Function Tests
# =============================================================================

class TestLookupReputationFunction:
    """Test the lookupReputation convenience function."""
    
    @pytest.mark.asyncio
    async def test_lookupReputationFunction(self):
        """Test lookupReputation convenience function exists."""
        from osint.reputationChecker import lookupReputation as lookupReputationFunc
        
        # Verify function exists and is callable
        assert callable(lookupReputationFunc)


# =============================================================================
# Multiple Sources Tests
# =============================================================================

class TestMultipleSources:
    """Test behavior with multiple reputation sources."""
    
    @pytest.mark.asyncio
    async def test_queriesAllSources(self, mockReputationClient, cleanReputationCheck):
        """Test all configured sources are queried."""
        mockReputationClient.checkDomain.return_value = cleanReputationCheck
        
        checker = ReputationChecker(
            client=mockReputationClient,
            sources=[
                ReputationSource.VIRUSTOTAL,
                ReputationSource.INTERNAL
            ]
        )
        result = await checker.lookup("example.com")
        
        assert mockReputationClient.checkDomain.call_count == 2
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_combinesResultsFromSources(self, mockReputationClient):
        """Test results from all sources are combined."""
        vtCheck = ReputationCheck(
            source=ReputationSource.VIRUSTOTAL,
            isMalicious=True,
            confidence=0.6,
            category="phishing"
        )
        internalCheck = ReputationCheck(
            source=ReputationSource.INTERNAL,
            isMalicious=False,
            confidence=0.0
        )
        
        async def checkDomain(domain, source):
            if source == ReputationSource.VIRUSTOTAL:
                return vtCheck
            return internalCheck
        
        mockReputationClient.checkDomain = AsyncMock(side_effect=checkDomain)
        
        checker = ReputationChecker(
            client=mockReputationClient,
            sources=[
                ReputationSource.VIRUSTOTAL,
                ReputationSource.INTERNAL
            ]
        )
        result = await checker.lookup("example.com")
        
        assert len(result.checks) == 2
        assert "phishing" in result.categories
