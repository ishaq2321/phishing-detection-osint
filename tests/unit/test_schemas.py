"""
Unit Tests for OSINT Schemas
=============================

Tests for Pydantic models in osint/schemas.py including:
- Model validation
- Serialization/deserialization
- Computed properties
- Edge cases

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError

from osint.schemas import (
    DataSource,
    DnsRecord,
    DnsRecordType,
    DnsResult,
    LookupStatus,
    OsintData,
    OsintResult,
    ReputationCheck,
    ReputationResult,
    ReputationSource,
    RiskLevel,
    WhoisContact,
    WhoisResult,
)


# =============================================================================
# DataSource Enum Tests
# =============================================================================

class TestDataSourceEnum:
    """Tests for DataSource enumeration."""
    
    def test_allSourcesExist(self):
        """All expected data sources should exist."""
        assert DataSource.WHOIS.value == "whois"
        assert DataSource.DNS.value == "dns"
        assert DataSource.REPUTATION.value == "reputation"
        assert DataSource.SSL.value == "ssl"
        assert DataSource.HTTP_HEADERS.value == "http_headers"


class TestLookupStatusEnum:
    """Tests for LookupStatus enumeration."""
    
    def test_allStatusesExist(self):
        """All expected statuses should exist."""
        assert LookupStatus.SUCCESS.value == "success"
        assert LookupStatus.TIMEOUT.value == "timeout"
        assert LookupStatus.NOT_FOUND.value == "not_found"
        assert LookupStatus.ERROR.value == "error"
        assert LookupStatus.RATE_LIMITED.value == "rate_limited"


# =============================================================================
# OsintResult Base Model Tests
# =============================================================================

class TestOsintResult:
    """Tests for the base OsintResult model."""
    
    def test_createValidResult(self):
        """Should create valid result with required fields."""
        result = OsintResult(
            source=DataSource.WHOIS,
            status=LookupStatus.SUCCESS,
            domain="example.com",
        )
        
        assert result.source == DataSource.WHOIS
        assert result.status == LookupStatus.SUCCESS
        assert result.domain == "example.com"
    
    def test_domainNormalization(self):
        """Domain should be normalized to lowercase."""
        result = OsintResult(
            source=DataSource.WHOIS,
            status=LookupStatus.SUCCESS,
            domain="  EXAMPLE.COM  ",
        )
        
        assert result.domain == "example.com"
    
    def test_isSuccessProperty(self):
        """isSuccess should return True only for SUCCESS status."""
        successResult = OsintResult(
            source=DataSource.WHOIS,
            status=LookupStatus.SUCCESS,
            domain="test.com",
        )
        
        failedResult = OsintResult(
            source=DataSource.WHOIS,
            status=LookupStatus.ERROR,
            domain="test.com",
        )
        
        assert successResult.isSuccess is True
        assert failedResult.isSuccess is False
    
    def test_hasFailedProperty(self):
        """hasFailed should return True for error states."""
        errorResult = OsintResult(
            source=DataSource.WHOIS,
            status=LookupStatus.ERROR,
            domain="test.com",
        )
        
        timeoutResult = OsintResult(
            source=DataSource.WHOIS,
            status=LookupStatus.TIMEOUT,
            domain="test.com",
        )
        
        notFoundResult = OsintResult(
            source=DataSource.WHOIS,
            status=LookupStatus.NOT_FOUND,
            domain="test.com",
        )
        
        assert errorResult.hasFailed is True
        assert timeoutResult.hasFailed is True
        assert notFoundResult.hasFailed is False  # NOT_FOUND is not a failure
    
    def test_defaultQueriedAt(self):
        """queriedAt should default to current UTC time."""
        result = OsintResult(
            source=DataSource.WHOIS,
            status=LookupStatus.SUCCESS,
            domain="test.com",
        )
        
        assert result.queriedAt is not None
        # Should be within last second
        assert (datetime.utcnow() - result.queriedAt).seconds < 2
    
    def test_durationMsDefault(self):
        """durationMs should default to 0."""
        result = OsintResult(
            source=DataSource.WHOIS,
            status=LookupStatus.SUCCESS,
            domain="test.com",
        )
        
        assert result.durationMs == 0.0
    
    def test_domainMinLength(self):
        """Domain should have minimum length of 1."""
        with pytest.raises(ValidationError):
            OsintResult(
                source=DataSource.WHOIS,
                status=LookupStatus.SUCCESS,
                domain="",
            )


# =============================================================================
# WhoisContact Tests
# =============================================================================

class TestWhoisContact:
    """Tests for WhoisContact model."""
    
    def test_createCompleteContact(self):
        """Should create contact with all fields."""
        contact = WhoisContact(
            name="John Doe",
            organization="Example Inc.",
            email="admin@example.com",
            country="US",
            state="California",
            city="San Francisco",
        )
        
        assert contact.name == "John Doe"
        assert contact.organization == "Example Inc."
    
    def test_createPartialContact(self):
        """Should create contact with partial fields."""
        contact = WhoisContact(organization="Test Corp")
        
        assert contact.organization == "Test Corp"
        assert contact.name is None
        assert contact.email is None
    
    def test_createEmptyContact(self):
        """Should create contact with no fields."""
        contact = WhoisContact()
        
        assert contact.name is None
        assert contact.organization is None


# =============================================================================
# WhoisResult Tests
# =============================================================================

class TestWhoisResult:
    """Tests for WhoisResult model."""
    
    def test_createValidWhoisResult(self):
        """Should create valid WHOIS result."""
        result = WhoisResult(
            status=LookupStatus.SUCCESS,
            domain="example.com",
            registrar="MarkMonitor Inc.",
            creationDate=datetime(2015, 1, 1),
        )
        
        assert result.source == DataSource.WHOIS
        assert result.registrar == "MarkMonitor Inc."
    
    def test_calculateDomainAge(self):
        """Should calculate domain age correctly."""
        creationDate = datetime.utcnow() - timedelta(days=100)
        
        result = WhoisResult(
            status=LookupStatus.SUCCESS,
            domain="test.com",
            creationDate=creationDate,
        )
        
        age = result.calculateDomainAge()
        assert age is not None
        assert 99 <= age <= 101  # Allow small variance
    
    def test_calculateDomainAgeNone(self):
        """Should return None when no creation date."""
        result = WhoisResult(
            status=LookupStatus.SUCCESS,
            domain="test.com",
        )
        
        assert result.calculateDomainAge() is None
    
    def test_detectPrivacyProtectionFromOrg(self):
        """Should detect privacy from organization name."""
        result = WhoisResult(
            status=LookupStatus.SUCCESS,
            domain="test.com",
            registrant=WhoisContact(
                organization="Domains By Proxy, LLC"
            ),
        )
        
        assert result.detectPrivacyProtection() is True
    
    def test_detectPrivacyProtectionFromName(self):
        """Should detect privacy from contact name."""
        result = WhoisResult(
            status=LookupStatus.SUCCESS,
            domain="test.com",
            registrant=WhoisContact(
                name="REDACTED FOR PRIVACY"
            ),
        )
        
        assert result.detectPrivacyProtection() is True
    
    def test_noPrivacyProtection(self):
        """Should return False for normal registrant."""
        result = WhoisResult(
            status=LookupStatus.SUCCESS,
            domain="test.com",
            registrant=WhoisContact(
                name="John Doe",
                organization="Example Inc."
            ),
        )
        
        assert result.detectPrivacyProtection() is False
    
    def test_defaultNameServersEmpty(self):
        """nameServers should default to empty list."""
        result = WhoisResult(
            status=LookupStatus.SUCCESS,
            domain="test.com",
        )
        
        assert result.nameServers == []
    
    def test_recentlyRegisteredFlag(self):
        """recentlyRegistered flag should work."""
        result = WhoisResult(
            status=LookupStatus.SUCCESS,
            domain="test.com",
            recentlyRegistered=True,
        )
        
        assert result.recentlyRegistered is True
    
    def test_shortLifespanFlag(self):
        """shortLifespan flag should work."""
        result = WhoisResult(
            status=LookupStatus.SUCCESS,
            domain="test.com",
            shortLifespan=True,
        )
        
        assert result.shortLifespan is True


# =============================================================================
# DnsResult Tests
# =============================================================================

class TestDnsResult:
    """Tests for DnsResult model."""
    
    def test_createValidDnsResult(self):
        """Should create valid DNS result."""
        result = DnsResult(
            status=LookupStatus.SUCCESS,
            domain="example.com",
            aRecords=["93.184.216.34"],
            mxRecords=[
                DnsRecord(
                    recordType=DnsRecordType.MX,
                    value="mail.example.com",
                    priority=10,
                )
            ],
        )
        
        assert result.source == DataSource.DNS
        assert "93.184.216.34" in result.aRecords
    
    def test_ipAddressesProperty(self):
        """ipAddresses should combine A and AAAA records."""
        result = DnsResult(
            status=LookupStatus.SUCCESS,
            domain="example.com",
            aRecords=["192.168.1.1"],
            aaaaRecords=["2001:db8::1"],
        )
        
        assert len(result.ipAddresses) == 2
        assert "192.168.1.1" in result.ipAddresses
        assert "2001:db8::1" in result.ipAddresses
    
    def test_hasIpAddressesTrue(self):
        """hasIpAddresses should return True when IPs exist."""
        result = DnsResult(
            status=LookupStatus.SUCCESS,
            domain="example.com",
            aRecords=["192.168.1.1"],
        )
        
        assert result.hasIpAddresses is True
    
    def test_hasIpAddressesFalse(self):
        """hasIpAddresses should return False when no IPs."""
        result = DnsResult(
            status=LookupStatus.SUCCESS,
            domain="example.com",
        )
        
        assert result.hasIpAddresses is False
    
    def test_defaultListsEmpty(self):
        """Record lists should default to empty."""
        result = DnsResult(
            status=LookupStatus.SUCCESS,
            domain="example.com",
        )
        
        assert result.aRecords == []
        assert result.aaaaRecords == []
        assert result.mxRecords == []
        assert result.nsRecords == []
        assert result.txtRecords == []


# =============================================================================
# ReputationResult Tests
# =============================================================================

class TestReputationResult:
    """Tests for ReputationResult model."""
    
    def test_createValidReputationResult(self):
        """Should create valid reputation result."""
        check = ReputationCheck(
            source=ReputationSource.VIRUSTOTAL,
            isMalicious=True,
            confidence=0.95,
            category="phishing",
        )
        
        result = ReputationResult(
            status=LookupStatus.SUCCESS,
            domain="evil.com",
            checks=[check],
            aggregateScore=0.95,
            knownMalicious=True,
        )
        
        assert result.source == DataSource.REPUTATION
        assert len(result.checks) == 1
        assert result.knownMalicious is True
    
    def test_maliciousCountProperty(self):
        """maliciousCount should count malicious flags."""
        checks = [
            ReputationCheck(source=ReputationSource.VIRUSTOTAL, isMalicious=True),
            ReputationCheck(source=ReputationSource.ABUSEIPDB, isMalicious=True),
            ReputationCheck(source=ReputationSource.PHISHTANK, isMalicious=False),
        ]
        
        result = ReputationResult(
            status=LookupStatus.SUCCESS,
            domain="test.com",
            checks=checks,
        )
        
        assert result.maliciousCount == 2
        assert result.totalChecks == 3
    
    def test_aggregateScoreRange(self):
        """aggregateScore should be between 0 and 1."""
        result = ReputationResult(
            status=LookupStatus.SUCCESS,
            domain="test.com",
            aggregateScore=0.5,
        )
        
        assert 0 <= result.aggregateScore <= 1
    
    def test_aggregateScoreValidation(self):
        """aggregateScore should reject invalid values."""
        with pytest.raises(ValidationError):
            ReputationResult(
                status=LookupStatus.SUCCESS,
                domain="test.com",
                aggregateScore=1.5,  # Invalid
            )


# =============================================================================
# OsintData Aggregation Tests
# =============================================================================

class TestOsintData:
    """Tests for OsintData aggregation model."""
    
    def test_createValidOsintData(self):
        """Should create valid aggregated data."""
        data = OsintData(
            url="https://example.com/login",
            domain="example.com",
        )
        
        assert data.url == "https://example.com/login"
        assert data.domain == "example.com"
    
    def test_hasWhoisProperty(self):
        """hasWhois should check for successful WHOIS."""
        dataWithWhois = OsintData(
            url="https://example.com",
            domain="example.com",
            whois=WhoisResult(
                status=LookupStatus.SUCCESS,
                domain="example.com",
            ),
        )
        
        dataWithoutWhois = OsintData(
            url="https://example.com",
            domain="example.com",
        )
        
        assert dataWithWhois.hasWhois is True
        assert dataWithoutWhois.hasWhois is False
    
    def test_hasWhoisFalseOnError(self):
        """hasWhois should be False when WHOIS failed."""
        data = OsintData(
            url="https://example.com",
            domain="example.com",
            whois=WhoisResult(
                status=LookupStatus.ERROR,
                domain="example.com",
            ),
        )
        
        assert data.hasWhois is False
    
    def test_dataQualityScore(self):
        """dataQualityScore should calculate correctly."""
        # No data collected
        emptyData = OsintData(
            url="https://example.com",
            domain="example.com",
        )
        assert emptyData.dataQualityScore == 0.0
        
        # All data collected
        fullData = OsintData(
            url="https://example.com",
            domain="example.com",
            whois=WhoisResult(status=LookupStatus.SUCCESS, domain="example.com"),
            dns=DnsResult(status=LookupStatus.SUCCESS, domain="example.com"),
            reputation=ReputationResult(status=LookupStatus.SUCCESS, domain="example.com"),
        )
        assert fullData.dataQualityScore == 1.0
        
        # Partial data
        partialData = OsintData(
            url="https://example.com",
            domain="example.com",
            whois=WhoisResult(status=LookupStatus.SUCCESS, domain="example.com"),
        )
        assert partialData.dataQualityScore == pytest.approx(1/3, rel=0.01)
    
    def test_defaultCollectedAt(self):
        """collectedAt should default to current time."""
        data = OsintData(
            url="https://example.com",
            domain="example.com",
        )
        
        assert data.collectedAt is not None
        assert (datetime.utcnow() - data.collectedAt).seconds < 2


# =============================================================================
# Serialization Tests
# =============================================================================

class TestSerialization:
    """Tests for JSON serialization."""
    
    def test_whoisResultToJson(self):
        """WhoisResult should serialize to JSON."""
        result = WhoisResult(
            status=LookupStatus.SUCCESS,
            domain="example.com",
            creationDate=datetime(2020, 1, 1),
        )
        
        jsonData = result.model_dump_json()
        assert "example.com" in jsonData
        assert "success" in jsonData
    
    def test_osintDataToJson(self):
        """OsintData should serialize completely."""
        data = OsintData(
            url="https://example.com",
            domain="example.com",
            whois=WhoisResult(
                status=LookupStatus.SUCCESS,
                domain="example.com",
            ),
        )
        
        jsonData = data.model_dump_json()
        assert "whois" in jsonData
        assert "example.com" in jsonData
