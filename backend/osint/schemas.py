"""
OSINT Module - Data Models and Schemas
======================================

Pydantic models for OSINT data structures with full validation.
These models ensure type safety and data integrity across the system.

Design Principles:
- Immutable data structures (frozen=True where applicable)
- Comprehensive validation with meaningful error messages
- Serialization support for API responses and caching
- Clear separation between input, internal, and output models

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# =============================================================================
# Enumerations
# =============================================================================

class DataSource(str, Enum):
    """OSINT data source enumeration."""
    
    WHOIS = "whois"
    DNS = "dns"
    REPUTATION = "reputation"
    SSL = "ssl"
    HTTP_HEADERS = "http_headers"


class LookupStatus(str, Enum):
    """Status of an OSINT lookup operation."""
    
    SUCCESS = "success"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"


class DnsRecordType(str, Enum):
    """DNS record type enumeration."""
    
    A = "A"
    AAAA = "AAAA"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    CNAME = "CNAME"
    SOA = "SOA"


class RiskLevel(str, Enum):
    """Risk level classification."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# Base Models
# =============================================================================

class OsintResult(BaseModel):
    """
    Base model for all OSINT lookup results.
    
    Provides common fields for tracking lookup status, timing, and errors.
    All specific OSINT results should inherit from this base.
    
    Attributes:
        source: The OSINT data source type
        status: Status of the lookup operation
        domain: The domain that was queried
        queriedAt: Timestamp of when the query was performed
        durationMs: Query duration in milliseconds
        errorMessage: Error message if status is not SUCCESS
        rawData: Optional raw response data for debugging
    """
    
    source: DataSource = Field(
        ...,
        description="OSINT data source type"
    )
    
    status: LookupStatus = Field(
        ...,
        description="Lookup operation status"
    )
    
    domain: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="Queried domain name"
    )
    
    queriedAt: datetime = Field(
        default_factory=datetime.utcnow,
        description="UTC timestamp of query"
    )
    
    durationMs: float = Field(
        default=0.0,
        ge=0,
        description="Query duration in milliseconds"
    )
    
    errorMessage: Optional[str] = Field(
        default=None,
        description="Error message if lookup failed"
    )
    
    rawData: Optional[dict] = Field(
        default=None,
        description="Raw response data for debugging"
    )
    
    @field_validator("domain")
    @classmethod
    def normalizeDomain(cls, v: str) -> str:
        """Normalize domain to lowercase and strip whitespace."""
        return v.lower().strip()
    
    @property
    def isSuccess(self) -> bool:
        """Check if lookup was successful."""
        return self.status == LookupStatus.SUCCESS
    
    @property
    def hasFailed(self) -> bool:
        """Check if lookup failed."""
        return self.status in (
            LookupStatus.ERROR,
            LookupStatus.TIMEOUT,
            LookupStatus.RATE_LIMITED
        )
    
    class Config:
        """Pydantic model configuration."""
        
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


# =============================================================================
# WHOIS Models
# =============================================================================

class WhoisContact(BaseModel):
    """Contact information from WHOIS records."""
    
    name: Optional[str] = Field(default=None, description="Contact name")
    organization: Optional[str] = Field(default=None, description="Organization name")
    email: Optional[str] = Field(default=None, description="Contact email")
    country: Optional[str] = Field(default=None, description="Country code")
    state: Optional[str] = Field(default=None, description="State/Province")
    city: Optional[str] = Field(default=None, description="City")


class WhoisResult(OsintResult):
    """
    WHOIS lookup result with domain registration details.
    
    Contains extracted and normalized WHOIS data for phishing analysis.
    Key indicators: domain age, registrar reputation, privacy protection.
    
    Attributes:
        registrar: Domain registrar name
        creationDate: Domain creation date
        expirationDate: Domain expiration date
        updatedDate: Last update date
        nameServers: List of name servers
        registrant: Registrant contact info
        domainAgeDays: Calculated domain age in days
        isPrivacyProtected: Whether privacy protection is enabled
    """
    
    source: DataSource = Field(
        default=DataSource.WHOIS,
        description="Data source (always WHOIS for this model)"
    )
    
    # Registration Information
    registrar: Optional[str] = Field(
        default=None,
        description="Domain registrar name"
    )
    
    creationDate: Optional[datetime] = Field(
        default=None,
        description="Domain creation/registration date"
    )
    
    expirationDate: Optional[datetime] = Field(
        default=None,
        description="Domain expiration date"
    )
    
    updatedDate: Optional[datetime] = Field(
        default=None,
        description="Last WHOIS record update date"
    )
    
    # DNS Configuration
    nameServers: list[str] = Field(
        default_factory=list,
        description="List of authoritative name servers"
    )
    
    # Contact Information
    registrant: Optional[WhoisContact] = Field(
        default=None,
        description="Registrant contact information"
    )
    
    # Computed Fields (populated during processing)
    domainAgeDays: Optional[int] = Field(
        default=None,
        ge=0,
        description="Domain age in days (computed)"
    )
    
    isPrivacyProtected: bool = Field(
        default=False,
        description="Whether WHOIS privacy protection is enabled"
    )
    
    # Phishing Indicators
    recentlyRegistered: bool = Field(
        default=False,
        description="Domain registered within last 30 days"
    )
    
    shortLifespan: bool = Field(
        default=False,
        description="Domain registered for less than 1 year"
    )
    
    def calculateDomainAge(self) -> Optional[int]:
        """Calculate domain age in days from creation date."""
        if not self.creationDate:
            return None
        
        delta = datetime.utcnow() - self.creationDate
        return max(0, delta.days)
    
    def detectPrivacyProtection(self) -> bool:
        """Detect if WHOIS privacy protection is enabled."""
        privacyIndicators = [
            "privacy",
            "redacted",
            "whoisguard",
            "domains by proxy",
            "contact privacy",
            "private registration",
            "data protected",
            "identity protect"
        ]
        
        if self.registrant and self.registrant.organization:
            orgLower = self.registrant.organization.lower()
            return any(indicator in orgLower for indicator in privacyIndicators)
        
        if self.registrant and self.registrant.name:
            nameLower = self.registrant.name.lower()
            return any(indicator in nameLower for indicator in privacyIndicators)
        
        return False


# =============================================================================
# DNS Models
# =============================================================================

class DnsRecord(BaseModel):
    """Individual DNS record."""
    
    recordType: DnsRecordType = Field(..., description="DNS record type")
    value: str = Field(..., description="Record value")
    ttl: Optional[int] = Field(default=None, ge=0, description="Time to live")
    priority: Optional[int] = Field(default=None, ge=0, description="Priority (for MX records)")


class DnsResult(OsintResult):
    """
    DNS lookup result with all record types.
    
    Attributes:
        aRecords: IPv4 addresses
        aaaaRecords: IPv6 addresses
        mxRecords: Mail exchange records
        nsRecords: Name server records
        txtRecords: TXT records (SPF, DKIM, etc.)
        cnameRecords: CNAME records
        hasValidMx: Whether valid MX records exist
        ipAddresses: All resolved IP addresses
    """
    
    source: DataSource = Field(
        default=DataSource.DNS,
        description="Data source (always DNS for this model)"
    )
    
    aRecords: list[str] = Field(default_factory=list, description="IPv4 addresses")
    aaaaRecords: list[str] = Field(default_factory=list, description="IPv6 addresses")
    mxRecords: list[DnsRecord] = Field(default_factory=list, description="MX records")
    nsRecords: list[str] = Field(default_factory=list, description="Name servers")
    txtRecords: list[str] = Field(default_factory=list, description="TXT records")
    cnameRecords: list[str] = Field(default_factory=list, description="CNAME records")
    
    # Computed analysis fields
    hasValidMx: bool = Field(default=False, description="Has valid mail configuration")
    usesCdn: bool = Field(default=False, description="Uses CDN (Cloudflare, etc.)")
    
    @property
    def ipAddresses(self) -> list[str]:
        """Get all resolved IP addresses (IPv4 and IPv6)."""
        return self.aRecords + self.aaaaRecords
    
    @property
    def hasIpAddresses(self) -> bool:
        """Check if domain resolves to any IP address."""
        return len(self.ipAddresses) > 0


# =============================================================================
# Reputation Models
# =============================================================================

class ReputationSource(str, Enum):
    """External reputation data source."""
    
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    GOOGLE_SAFE_BROWSING = "google_safe_browsing"
    PHISHTANK = "phishtank"
    INTERNAL = "internal"


class ReputationCheck(BaseModel):
    """Individual reputation check result."""
    
    source: ReputationSource = Field(..., description="Reputation data source")
    isMalicious: bool = Field(default=False, description="Flagged as malicious")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence score")
    category: Optional[str] = Field(default=None, description="Threat category")
    lastChecked: datetime = Field(default_factory=datetime.utcnow, description="Check timestamp")


class ReputationResult(OsintResult):
    """
    Aggregated reputation check results.
    
    Combines results from multiple reputation sources.
    
    Attributes:
        checks: List of individual reputation checks
        aggregateScore: Combined reputation score (0-1, higher = more suspicious)
        knownMalicious: Whether URL is in known malicious lists
        categories: List of threat categories from all sources
    """
    
    source: DataSource = Field(
        default=DataSource.REPUTATION,
        description="Data source (always REPUTATION for this model)"
    )
    
    checks: list[ReputationCheck] = Field(
        default_factory=list,
        description="Individual reputation check results"
    )
    
    aggregateScore: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Aggregated suspicion score"
    )
    
    knownMalicious: bool = Field(
        default=False,
        description="URL is in known malicious lists"
    )
    
    categories: list[str] = Field(
        default_factory=list,
        description="Threat categories from all sources"
    )
    
    @property
    def maliciousCount(self) -> int:
        """Count of sources flagging as malicious."""
        return sum(1 for check in self.checks if check.isMalicious)
    
    @property
    def totalChecks(self) -> int:
        """Total number of reputation checks performed."""
        return len(self.checks)


# =============================================================================
# Aggregated OSINT Data
# =============================================================================

class OsintData(BaseModel):
    """
    Aggregated OSINT data from all sources.
    
    This is the main data structure passed to the ML feature extractor
    and analyzer modules. Contains all collected OSINT intelligence.
    
    Attributes:
        url: Original URL being analyzed
        domain: Extracted domain name
        whois: WHOIS lookup result
        dns: DNS lookup result
        reputation: Reputation check result
        collectedAt: Timestamp of data collection
        collectionDurationMs: Total collection time
    """
    
    url: str = Field(..., description="Original URL being analyzed")
    domain: str = Field(..., description="Extracted domain name")
    
    whois: Optional[WhoisResult] = Field(default=None, description="WHOIS data")
    dns: Optional[DnsResult] = Field(default=None, description="DNS data")
    reputation: Optional[ReputationResult] = Field(default=None, description="Reputation data")
    
    collectedAt: datetime = Field(
        default_factory=datetime.utcnow,
        description="Data collection timestamp"
    )
    
    collectionDurationMs: float = Field(
        default=0.0,
        ge=0,
        description="Total collection time in milliseconds"
    )
    
    @property
    def hasWhois(self) -> bool:
        """Check if WHOIS data was collected successfully."""
        return self.whois is not None and self.whois.isSuccess
    
    @property
    def hasDns(self) -> bool:
        """Check if DNS data was collected successfully."""
        return self.dns is not None and self.dns.isSuccess
    
    @property
    def hasReputation(self) -> bool:
        """Check if reputation data was collected."""
        return self.reputation is not None and self.reputation.isSuccess
    
    @property
    def dataQualityScore(self) -> float:
        """
        Calculate data quality score (0-1).
        
        Higher score means more complete OSINT data.
        """
        sources = [self.hasWhois, self.hasDns, self.hasReputation]
        return sum(sources) / len(sources)
