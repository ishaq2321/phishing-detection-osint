"""
Unit Tests for WHOIS Lookup Module
==================================

Comprehensive tests for whoisLookup.py including:
- Successful lookups with various data formats
- Error handling (timeout, not found, parse errors)
- Retry logic
- Domain normalization
- Privacy protection detection
- Phishing indicator detection

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

from osint.schemas import DataSource, LookupStatus
from osint.whoisLookup import (
    DefaultWhoisClient,
    WhoisError,
    WhoisLookup,
    WhoisNotFoundError,
    WhoisParser,
    WhoisTimeoutError,
    lookupWhois,
)


# =============================================================================
# WhoisParser Tests
# =============================================================================

class TestWhoisParser:
    """Tests for the WhoisParser class."""
    
    def test_parseValidData(self, sampleWhoisData):
        """Parser should extract all fields from valid data."""
        parser = WhoisParser()
        result = parser.parse("example.com", sampleWhoisData)
        
        assert result.domain == "example.com"
        assert result.status == LookupStatus.SUCCESS
        assert result.registrar == "MarkMonitor Inc."
        assert result.creationDate == datetime(2015, 8, 14)
        assert result.expirationDate == datetime(2026, 8, 14)
        assert "ns1.example.com" in result.nameServers
    
    def test_parseExtractsRegistrant(self, sampleWhoisData):
        """Parser should extract registrant contact info."""
        parser = WhoisParser()
        result = parser.parse("example.com", sampleWhoisData)
        
        assert result.registrant is not None
        assert result.registrant.organization == "Example Corporation"
        assert result.registrant.country == "US"
    
    def test_parsCalculatesDomainAge(self, sampleWhoisData):
        """Parser should calculate domain age in days."""
        parser = WhoisParser()
        result = parser.parse("example.com", sampleWhoisData)
        
        assert result.domainAgeDays is not None
        assert result.domainAgeDays > 0
        
        # Should be roughly the days since August 14, 2015
        expectedDays = (datetime.utcnow() - datetime(2015, 8, 14)).days
        assert abs(result.domainAgeDays - expectedDays) <= 1
    
    def test_parseDetectsPrivacyProtection(self, privacyProtectedWhoisData):
        """Parser should detect WHOIS privacy protection."""
        parser = WhoisParser()
        result = parser.parse("privacy-example.com", privacyProtectedWhoisData)
        
        assert result.isPrivacyProtected is True
    
    def test_parseNoPrivacyProtection(self, sampleWhoisData):
        """Parser should not flag regular domains as privacy protected."""
        parser = WhoisParser()
        result = parser.parse("example.com", sampleWhoisData)
        
        assert result.isPrivacyProtected is False
    
    def test_parseDetectsRecentlyRegistered(self, suspiciousWhoisData):
        """Parser should detect recently registered domains."""
        parser = WhoisParser()
        result = parser.parse("suspicious.com", suspiciousWhoisData)
        
        assert result.recentlyRegistered is True
        assert result.domainAgeDays is not None
        assert result.domainAgeDays < 30
    
    def test_parseDetectsShortLifespan(self, suspiciousWhoisData):
        """Parser should detect domains with short registration period."""
        parser = WhoisParser()
        result = parser.parse("suspicious.com", suspiciousWhoisData)
        
        assert result.shortLifespan is True
    
    def test_parseHandlesListValues(self, whoisDataWithLists):
        """Parser should handle fields returned as lists."""
        parser = WhoisParser()
        result = parser.parse("example.com", whoisDataWithLists)
        
        # Should take first value from list
        assert result.creationDate == datetime(2018, 5, 20)
        # Should include all name servers
        assert len(result.nameServers) == 3
    
    def test_parseHandlesMissingFields(self):
        """Parser should handle missing optional fields."""
        parser = WhoisParser()
        minimalData = {
            "domain_name": "minimal.com",
            "creation_date": datetime(2020, 1, 1),
        }
        
        result = parser.parse("minimal.com", minimalData)
        
        assert result.domain == "minimal.com"
        assert result.registrar is None
        assert result.expirationDate is None
        assert result.registrant is None
    
    def test_parseHandlesNoneValues(self):
        """Parser should handle None values gracefully."""
        parser = WhoisParser()
        dataWithNones = {
            "domain_name": "test.com",
            "creation_date": None,
            "expiration_date": None,
            "registrar": None,
            "name_servers": None,
        }
        
        result = parser.parse("test.com", dataWithNones)
        
        assert result.domain == "test.com"
        assert result.creationDate is None
        assert result.domainAgeDays is None
        assert result.nameServers == []
    
    def test_parseDateStringFormats(self):
        """Parser should handle various date string formats."""
        parser = WhoisParser()
        
        # Test different formats
        testCases = [
            ("2020-01-15", datetime(2020, 1, 15)),
            ("2020/01/15", datetime(2020, 1, 15)),
            ("2020.01.15", datetime(2020, 1, 15)),
        ]
        
        for dateStr, expected in testCases:
            result = parser._parseDate(dateStr)
            assert result == expected, f"Failed for format: {dateStr}"
    
    def test_sanitizeRawDataConvertsDates(self, sampleWhoisData):
        """Sanitized raw data should have serializable dates."""
        parser = WhoisParser()
        result = parser.parse("example.com", sampleWhoisData)
        
        assert result.rawData is not None
        # Dates should be ISO strings
        for key, value in result.rawData.items():
            if "date" in key.lower():
                assert isinstance(value, (str, list))


# =============================================================================
# WhoisLookup Tests
# =============================================================================

class TestWhoisLookup:
    """Tests for the WhoisLookup class."""
    
    @pytest.mark.asyncio
    async def test_lookupSuccess(self, mockWhoisClientSuccess):
        """Successful lookup should return complete result."""
        lookup = WhoisLookup(
            client=mockWhoisClientSuccess,
            timeout=5,
            maxRetries=0,
        )
        
        result = await lookup.lookup("example.com")
        
        assert result.isSuccess is True
        assert result.status == LookupStatus.SUCCESS
        assert result.domain == "example.com"
        assert result.durationMs > 0
    
    @pytest.mark.asyncio
    async def test_lookupCallsClient(self, mockWhoisClient, sampleWhoisData):
        """Lookup should call client with normalized domain."""
        mockWhoisClient.query.return_value = sampleWhoisData
        
        lookup = WhoisLookup(client=mockWhoisClient, timeout=5)
        await lookup.lookup("EXAMPLE.COM")
        
        mockWhoisClient.query.assert_called_once_with("example.com")
    
    @pytest.mark.asyncio
    async def test_lookupNotFound(self, mockWhoisClientNotFound):
        """Not found lookup should return NOT_FOUND status."""
        lookup = WhoisLookup(
            client=mockWhoisClientNotFound,
            timeout=5,
            maxRetries=0,
        )
        
        result = await lookup.lookup("nonexistent-domain-xyz.com")
        
        # NOT_FOUND is not considered a failure (domain simply doesn't exist)
        assert result.isSuccess is False
        assert result.status == LookupStatus.NOT_FOUND
        assert result.errorMessage is not None
    
    @pytest.mark.asyncio
    async def test_lookupError(self, mockWhoisClientError):
        """Error during lookup should return ERROR status."""
        lookup = WhoisLookup(
            client=mockWhoisClientError,
            timeout=5,
            maxRetries=0,
        )
        
        result = await lookup.lookup("error-domain.com")
        
        assert result.hasFailed is True
        assert result.status == LookupStatus.ERROR
        assert "WHOIS server unavailable" in result.errorMessage
    
    @pytest.mark.asyncio
    async def test_lookupRetry(self, mockWhoisClient, sampleWhoisData):
        """Lookup should retry on transient errors."""
        # First call fails, second succeeds
        mockWhoisClient.query.side_effect = [
            Exception("Temporary error"),
            sampleWhoisData,
        ]
        
        lookup = WhoisLookup(
            client=mockWhoisClient,
            timeout=5,
            maxRetries=2,
            retryDelay=0.01,  # Fast for testing
        )
        
        result = await lookup.lookup("retry-test.com")
        
        assert result.isSuccess is True
        assert mockWhoisClient.query.call_count == 2
    
    @pytest.mark.asyncio
    async def test_lookupMaxRetriesExhausted(self, mockWhoisClientError):
        """Lookup should fail after exhausting retries."""
        lookup = WhoisLookup(
            client=mockWhoisClientError,
            timeout=5,
            maxRetries=2,
            retryDelay=0.01,
        )
        
        result = await lookup.lookup("always-fails.com")
        
        assert result.hasFailed is True
        assert result.status == LookupStatus.ERROR
        # Should have tried 3 times (initial + 2 retries)
        assert mockWhoisClientError.query.call_count == 3
    
    @pytest.mark.asyncio
    async def test_lookupNoRetryForNotFound(self, mockWhoisClientNotFound):
        """NOT_FOUND should not trigger retries."""
        lookup = WhoisLookup(
            client=mockWhoisClientNotFound,
            timeout=5,
            maxRetries=2,
        )
        
        result = await lookup.lookup("not-found.com")
        
        assert result.status == LookupStatus.NOT_FOUND
        # Should only call once, no retries
        assert mockWhoisClientNotFound.query.call_count == 1
    
    @pytest.mark.asyncio
    async def test_contextManager(self, mockWhoisClientSuccess):
        """Should work as async context manager."""
        async with WhoisLookup(client=mockWhoisClientSuccess) as lookup:
            result = await lookup.lookup("example.com")
        
        assert result.isSuccess is True
    
    @pytest.mark.asyncio
    async def test_suspiciousDomainDetection(self, mockWhoisClientSuspicious):
        """Should detect suspicious domain indicators."""
        lookup = WhoisLookup(
            client=mockWhoisClientSuspicious,
            timeout=5,
        )
        
        result = await lookup.lookup("paypal-secure-login.com")
        
        assert result.isSuccess is True
        assert result.recentlyRegistered is True
        assert result.isPrivacyProtected is True


class TestDomainNormalization:
    """Tests for domain normalization."""
    
    @pytest.mark.asyncio
    async def test_normalizeRemovesProtocol(self, mockWhoisClientSuccess):
        """Normalization should remove http/https."""
        lookup = WhoisLookup(client=mockWhoisClientSuccess)
        
        await lookup.lookup("https://example.com")
        mockWhoisClientSuccess.query.assert_called_with("example.com")
        
        mockWhoisClientSuccess.reset_mock()
        await lookup.lookup("http://example.com")
        mockWhoisClientSuccess.query.assert_called_with("example.com")
    
    @pytest.mark.asyncio
    async def test_normalizeRemovesWww(self, mockWhoisClientSuccess):
        """Normalization should remove www prefix."""
        lookup = WhoisLookup(client=mockWhoisClientSuccess)
        
        await lookup.lookup("www.example.com")
        mockWhoisClientSuccess.query.assert_called_with("example.com")
    
    @pytest.mark.asyncio
    async def test_normalizeRemovesPath(self, mockWhoisClientSuccess):
        """Normalization should remove URL path."""
        lookup = WhoisLookup(client=mockWhoisClientSuccess)
        
        await lookup.lookup("example.com/path/to/page")
        mockWhoisClientSuccess.query.assert_called_with("example.com")
    
    @pytest.mark.asyncio
    async def test_normalizeRemovesQueryString(self, mockWhoisClientSuccess):
        """Normalization should remove query string."""
        lookup = WhoisLookup(client=mockWhoisClientSuccess)
        
        await lookup.lookup("example.com?param=value")
        mockWhoisClientSuccess.query.assert_called_with("example.com")
    
    @pytest.mark.asyncio
    async def test_normalizeRemovesPort(self, mockWhoisClientSuccess):
        """Normalization should remove port number."""
        lookup = WhoisLookup(client=mockWhoisClientSuccess)
        
        await lookup.lookup("example.com:8080")
        mockWhoisClientSuccess.query.assert_called_with("example.com")
    
    @pytest.mark.asyncio
    async def test_normalizeToLowercase(self, mockWhoisClientSuccess):
        """Normalization should convert to lowercase."""
        lookup = WhoisLookup(client=mockWhoisClientSuccess)
        
        await lookup.lookup("EXAMPLE.COM")
        mockWhoisClientSuccess.query.assert_called_with("example.com")
    
    @pytest.mark.asyncio
    async def test_normalizeStripsWhitespace(self, mockWhoisClientSuccess):
        """Normalization should strip whitespace."""
        lookup = WhoisLookup(client=mockWhoisClientSuccess)
        
        await lookup.lookup("  example.com  ")
        mockWhoisClientSuccess.query.assert_called_with("example.com")
    
    @pytest.mark.asyncio
    async def test_normalizeComplexUrl(self, mockWhoisClientSuccess):
        """Normalization should handle complex URLs."""
        lookup = WhoisLookup(client=mockWhoisClientSuccess)
        
        await lookup.lookup("https://www.EXAMPLE.COM:443/path?query=1#hash")
        mockWhoisClientSuccess.query.assert_called_with("example.com")


class TestConvenienceFunction:
    """Tests for the lookupWhois convenience function."""
    
    @pytest.mark.asyncio
    async def test_lookupWhoisFunction(self, mockWhoisClientSuccess, monkeypatch):
        """lookupWhois should work as standalone function."""
        # Patch the default client
        with patch("osint.whoisLookup.DefaultWhoisClient") as MockClient:
            MockClient.return_value = mockWhoisClientSuccess
            
            result = await lookupWhois("example.com")
            
            assert result.isSuccess is True


class TestWhoisExceptions:
    """Tests for WHOIS exception classes."""
    
    def test_whoisErrorMessage(self):
        """WhoisError should include domain in message."""
        error = WhoisError("example.com", "Test error")
        assert "example.com" in str(error)
        assert "Test error" in str(error)
    
    def test_whoisTimeoutError(self):
        """WhoisTimeoutError should be a WhoisError."""
        error = WhoisTimeoutError("example.com", "Timeout")
        assert isinstance(error, WhoisError)
        assert error.domain == "example.com"
    
    def test_whoisNotFoundError(self):
        """WhoisNotFoundError should be a WhoisError."""
        error = WhoisNotFoundError("example.com", "Not found")
        assert isinstance(error, WhoisError)


class TestResultProperties:
    """Tests for WhoisResult computed properties."""
    
    @pytest.mark.asyncio
    async def test_isSuccessProperty(self, mockWhoisClientSuccess):
        """isSuccess should return True for successful lookups."""
        lookup = WhoisLookup(client=mockWhoisClientSuccess)
        result = await lookup.lookup("example.com")
        
        assert result.isSuccess is True
        assert result.hasFailed is False
    
    @pytest.mark.asyncio
    async def test_hasFailedProperty(self, mockWhoisClientError):
        """hasFailed should return True for failed lookups."""
        lookup = WhoisLookup(client=mockWhoisClientError, maxRetries=0)
        result = await lookup.lookup("example.com")
        
        assert result.hasFailed is True
        assert result.isSuccess is False
    
    @pytest.mark.asyncio
    async def test_sourceIsWhois(self, mockWhoisClientSuccess):
        """Source should always be WHOIS."""
        lookup = WhoisLookup(client=mockWhoisClientSuccess)
        result = await lookup.lookup("example.com")
        
        assert result.source == DataSource.WHOIS


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_emptyDomain(self, mockWhoisClientSuccess):
        """Empty domain should return error result."""
        lookup = WhoisLookup(client=mockWhoisClientSuccess, maxRetries=0)
        
        # Empty domain should result in error (validation fails)
        result = await lookup.lookup("  ")  # Whitespace only
        
        # Should return error status due to empty domain
        assert result.status == LookupStatus.ERROR
        assert "empty" in result.errorMessage.lower()
    
    @pytest.mark.asyncio
    async def test_zeroRetries(self, mockWhoisClientError):
        """Zero retries should still attempt once."""
        lookup = WhoisLookup(
            client=mockWhoisClientError,
            maxRetries=0,
        )
        
        result = await lookup.lookup("test.com")
        
        assert result.hasFailed is True
        assert mockWhoisClientError.query.call_count == 1
    
    def test_parserHandlesUnexpectedTypes(self):
        """Parser should handle unexpected data types."""
        parser = WhoisParser()
        
        weirdData = {
            "domain_name": 12345,  # Number instead of string
            "creation_date": "invalid-date",
            "name_servers": 42,  # Number instead of list
        }
        
        # Should not raise, should handle gracefully
        result = parser.parse("weird.com", weirdData)
        assert result.domain == "weird.com"
