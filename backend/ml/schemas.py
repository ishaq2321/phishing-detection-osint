"""
ML Module - Data Models and Schemas
====================================

Pydantic models for ML feature extraction and scoring.
These models ensure type safety and provide clear interfaces between
the OSINT layer and ML feature extraction/scoring modules.

Design Principles:
- Immutable data structures for predictable behavior
- Comprehensive validation with meaningful error messages
- Serialization support for API responses and debugging
- Clear separation between raw features and processed scores

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from datetime import datetime
from enum import Enum
from typing import Optional

import numpy as np
from pydantic import BaseModel, Field, field_validator


# =============================================================================
# Canonical Feature Names (ORDER MATTERS — must match model input)
# =============================================================================

FEATURE_NAMES: list[str] = [
    # URL structural features (17)
    "urlLength",
    "domainLength",
    "subdomainCount",
    "pathDepth",
    "hasIpAddress",
    "hasAtSymbol",
    "hasDoubleSlash",
    "hasDashInDomain",
    "hasUnderscoreInDomain",
    "isHttps",
    "hasPortNumber",
    "hasSuspiciousTld",
    "hasEncodedChars",
    "hasSuspiciousKeywords",
    "digitRatio",
    "specialCharCount",
    "queryParamCount",
    # OSINT-derived features (12)
    "domainAgeDays",
    "isNewlyRegistered",
    "isYoungDomain",
    "hasPrivacyProtection",
    "hasValidMx",
    "usesCdn",
    "dnsRecordCount",
    "hasValidDns",
    "reputationScore",
    "maliciousSourceCount",
    "isKnownMalicious",
    "hasValidWhois",
]

URL_FEATURE_NAMES: list[str] = FEATURE_NAMES[:17]
OSINT_FEATURE_NAMES: list[str] = FEATURE_NAMES[17:]


# =============================================================================
# Enumerations
# =============================================================================

class RiskLevel(str, Enum):
    """Risk level classification for phishing detection.

    Aligned with the system-wide ThreatLevel thresholds:
    SAFE < 0.3, SUSPICIOUS < 0.5, DANGEROUS < 0.7, CRITICAL >= 0.7
    """

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    CRITICAL = "critical"


class FeatureCategory(str, Enum):
    """Feature category for grouping related features."""
    
    URL_STRUCTURE = "url_structure"
    DOMAIN_ANALYSIS = "domain_analysis"
    OSINT_DERIVED = "osint_derived"
    REPUTATION = "reputation"


# =============================================================================
# URL Feature Models
# =============================================================================

class UrlFeatures(BaseModel):
    """
    Extracted URL structural features.
    
    Contains numerical and boolean features derived from URL analysis
    that serve as inputs to the phishing scoring model.
    
    Attributes:
        urlLength: Total URL length (longer URLs often suspicious)
        domainLength: Domain name length
        subdomainCount: Number of subdomains (e.g., login.fake.example.com = 2)
        pathDepth: URL path depth (number of / in path)
        hasIpAddress: URL uses IP instead of domain name
        hasAtSymbol: Contains @ (URL obfuscation technique)
        hasDoubleSlash: Contains // in path (redirect trick)
        hasDashInDomain: Domain contains hyphens
        hasUnderscoreInDomain: Domain contains underscores
        digitRatio: Ratio of digits to total characters in domain
        specialCharCount: Count of special characters in URL
        isHttps: Uses HTTPS protocol
        hasPortNumber: URL contains explicit port number
        hasSuspiciousTld: Uses suspicious TLD (.tk, .ml, .xyz, etc.)
        queryParamCount: Number of query parameters
        hasEncodedChars: Contains URL-encoded characters
        hasSuspiciousKeywords: Contains keywords like 'login', 'verify', 'secure'
    """
    
    # Length-based features
    urlLength: int = Field(
        default=0,
        ge=0,
        description="Total URL length"
    )
    
    domainLength: int = Field(
        default=0,
        ge=0,
        description="Domain name length"
    )
    
    subdomainCount: int = Field(
        default=0,
        ge=0,
        description="Number of subdomains"
    )
    
    pathDepth: int = Field(
        default=0,
        ge=0,
        description="URL path depth (segments)"
    )
    
    # Binary features
    hasIpAddress: bool = Field(
        default=False,
        description="URL uses IP address instead of domain"
    )
    
    hasAtSymbol: bool = Field(
        default=False,
        description="URL contains @ symbol"
    )
    
    hasDoubleSlash: bool = Field(
        default=False,
        description="URL contains // in path"
    )
    
    hasDashInDomain: bool = Field(
        default=False,
        description="Domain contains hyphen(s)"
    )
    
    hasUnderscoreInDomain: bool = Field(
        default=False,
        description="Domain contains underscore(s)"
    )
    
    isHttps: bool = Field(
        default=False,
        description="Uses HTTPS protocol"
    )
    
    hasPortNumber: bool = Field(
        default=False,
        description="URL contains explicit port number"
    )
    
    hasSuspiciousTld: bool = Field(
        default=False,
        description="Uses suspicious TLD"
    )
    
    hasEncodedChars: bool = Field(
        default=False,
        description="Contains URL-encoded characters"
    )
    
    hasSuspiciousKeywords: bool = Field(
        default=False,
        description="Contains suspicious keywords"
    )
    
    # Ratio/Count features
    digitRatio: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Ratio of digits to total characters in domain"
    )
    
    specialCharCount: int = Field(
        default=0,
        ge=0,
        description="Count of special characters"
    )
    
    queryParamCount: int = Field(
        default=0,
        ge=0,
        description="Number of query parameters"
    )
    
    @property
    def suspiciousFeatureCount(self) -> int:
        """Count of suspicious binary features that are True."""
        binaryFeatures = [
            self.hasIpAddress,
            self.hasAtSymbol,
            self.hasDoubleSlash,
            self.hasUnderscoreInDomain,
            self.hasPortNumber,
            self.hasSuspiciousTld,
            self.hasSuspiciousKeywords,
        ]
        return sum(binaryFeatures)
    
    @property
    def isHighlyStructured(self) -> bool:
        """Check if URL has complex structure (often suspicious)."""
        return (
            self.subdomainCount >= 2
            or self.pathDepth >= 4
            or self.queryParamCount >= 3
        )


# =============================================================================
# OSINT-Derived Feature Models
# =============================================================================

class OsintFeatures(BaseModel):
    """
    Features derived from OSINT data (WHOIS, DNS, Reputation).
    
    These features are extracted from the raw OSINT data and
    normalized for use in the scoring model.
    
    Attributes:
        domainAgeDays: Days since domain registration
        isNewlyRegistered: Domain < 30 days old
        isYoungDomain: Domain < 365 days old
        hasPrivacyProtection: WHOIS privacy enabled
        hasValidMx: Domain has valid mail configuration
        usesCdn: Domain uses CDN
        dnsRecordCount: Total DNS records found
        reputationScore: Aggregated reputation score (0-1)
        maliciousSourceCount: Sources flagging as malicious
        isKnownMalicious: In known malicious lists
        hasValidDns: DNS resolves successfully
        hasValidWhois: WHOIS lookup successful
    """
    
    # WHOIS-derived features
    domainAgeDays: Optional[int] = Field(
        default=None,
        ge=0,
        description="Domain age in days"
    )
    
    isNewlyRegistered: bool = Field(
        default=False,
        description="Domain registered within 30 days"
    )
    
    isYoungDomain: bool = Field(
        default=False,
        description="Domain registered within 365 days"
    )
    
    hasPrivacyProtection: bool = Field(
        default=False,
        description="WHOIS privacy protection enabled"
    )
    
    # DNS-derived features
    hasValidMx: bool = Field(
        default=False,
        description="Has valid mail exchange records"
    )
    
    usesCdn: bool = Field(
        default=False,
        description="Uses content delivery network"
    )
    
    dnsRecordCount: int = Field(
        default=0,
        ge=0,
        description="Total DNS records found"
    )
    
    hasValidDns: bool = Field(
        default=False,
        description="DNS resolution successful"
    )
    
    # Reputation-derived features
    reputationScore: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Aggregated reputation score (0=safe, 1=malicious)"
    )
    
    maliciousSourceCount: int = Field(
        default=0,
        ge=0,
        description="Number of sources flagging as malicious"
    )
    
    isKnownMalicious: bool = Field(
        default=False,
        description="URL is in known malicious lists"
    )
    
    # Data quality indicators
    hasValidWhois: bool = Field(
        default=False,
        description="WHOIS lookup successful"
    )
    
    @property
    def osintRiskIndicators(self) -> int:
        """Count of OSINT-based risk indicators."""
        indicators = [
            self.isNewlyRegistered,
            self.isYoungDomain and not self.isNewlyRegistered,
            self.hasPrivacyProtection,
            self.hasValidDns and not self.hasValidMx,  # Missing MX only counts when DNS is valid
            self.isKnownMalicious,
            self.maliciousSourceCount > 0,
        ]
        return sum(indicators)
    
    @property
    def dataCompleteness(self) -> float:
        """Score indicating completeness of OSINT data (0-1)."""
        checks = [
            self.hasValidWhois,
            self.hasValidDns,
            True,  # Reputation always provides a result
        ]
        return sum(checks) / len(checks)


# =============================================================================
# Combined Feature Set
# =============================================================================

class FeatureSet(BaseModel):
    """
    Complete feature set for phishing analysis.
    
    Combines URL structural features and OSINT-derived features
    into a single model for scoring.
    
    Attributes:
        url: Original URL being analyzed
        domain: Extracted domain name
        urlFeatures: URL structural features
        osintFeatures: OSINT-derived features
        extractedAt: Feature extraction timestamp
        extractionDurationMs: Time taken to extract features
    """
    
    url: str = Field(..., description="Original URL")
    domain: str = Field(..., description="Extracted domain name")
    
    urlFeatures: UrlFeatures = Field(
        default_factory=UrlFeatures,
        description="URL structural features"
    )
    
    osintFeatures: OsintFeatures = Field(
        default_factory=OsintFeatures,
        description="OSINT-derived features"
    )
    
    extractedAt: datetime = Field(
        default_factory=datetime.utcnow,
        description="Feature extraction timestamp"
    )
    
    extractionDurationMs: float = Field(
        default=0.0,
        ge=0,
        description="Extraction duration in milliseconds"
    )
    
    @property
    def totalRiskIndicators(self) -> int:
        """Total count of all risk indicators."""
        return (
            self.urlFeatures.suspiciousFeatureCount
            + self.osintFeatures.osintRiskIndicators
        )
    
    @property
    def hasCompleteData(self) -> bool:
        """Check if all data sources provided valid data."""
        return self.osintFeatures.dataCompleteness == 1.0

    def toVector(self) -> np.ndarray:
        """
        Convert features to a numpy array in canonical order.

        Returns a 1D float64 array of length 29 matching FEATURE_NAMES.
        Boolean features are cast to 0.0/1.0.
        None values (e.g., unknown domainAgeDays) become NaN, which
        XGBoost handles natively as missing values.

        Returns:
            np.ndarray of shape (29,)
        """
        uf = self.urlFeatures
        of = self.osintFeatures

        values: list[float] = [
            # URL structural (17)
            float(uf.urlLength),
            float(uf.domainLength),
            float(uf.subdomainCount),
            float(uf.pathDepth),
            float(uf.hasIpAddress),
            float(uf.hasAtSymbol),
            float(uf.hasDoubleSlash),
            float(uf.hasDashInDomain),
            float(uf.hasUnderscoreInDomain),
            float(uf.isHttps),
            float(uf.hasPortNumber),
            float(uf.hasSuspiciousTld),
            float(uf.hasEncodedChars),
            float(uf.hasSuspiciousKeywords),
            float(uf.digitRatio),
            float(uf.specialCharCount),
            float(uf.queryParamCount),
            # OSINT-derived (12)
            float(of.domainAgeDays) if of.domainAgeDays is not None else float("nan"),
            float(of.isNewlyRegistered),
            float(of.isYoungDomain),
            float(of.hasPrivacyProtection),
            float(of.hasValidMx),
            float(of.usesCdn),
            float(of.dnsRecordCount),
            float(of.hasValidDns),
            float(of.reputationScore),
            float(of.maliciousSourceCount),
            float(of.isKnownMalicious),
            float(of.hasValidWhois),
        ]

        return np.array(values, dtype=np.float64)

    def toUrlVector(self) -> np.ndarray:
        """
        Convert only URL features to numpy array (for ablation study).

        Returns:
            np.ndarray of shape (17,)
        """
        return self.toVector()[:17]

    def toOsintVector(self) -> np.ndarray:
        """
        Convert only OSINT features to numpy array (for ablation study).

        Returns:
            np.ndarray of shape (12,)
        """
        return self.toVector()[17:]

    def toModelVector(self) -> np.ndarray:
        """
        Convert features to the 21-element vector the trained model expects.

        The model was trained on 17 URL features + 4 informative OSINT
        features (hasValidMx, usesCdn, dnsRecordCount, hasValidDns).
        Eight zero-variance OSINT columns were dropped during training.

        Returns:
            np.ndarray of shape (21,)
        """
        uf = self.urlFeatures
        of = self.osintFeatures

        values: list[float] = [
            float(uf.urlLength),
            float(uf.domainLength),
            float(uf.subdomainCount),
            float(uf.pathDepth),
            float(uf.hasIpAddress),
            float(uf.hasAtSymbol),
            float(uf.hasDoubleSlash),
            float(uf.hasDashInDomain),
            float(uf.hasUnderscoreInDomain),
            float(uf.isHttps),
            float(uf.hasPortNumber),
            float(uf.hasSuspiciousTld),
            float(uf.hasEncodedChars),
            float(uf.hasSuspiciousKeywords),
            float(uf.digitRatio),
            float(uf.specialCharCount),
            float(uf.queryParamCount),
            float(of.hasValidMx),
            float(of.usesCdn),
            float(of.dnsRecordCount),
            float(of.hasValidDns),
        ]

        return np.array(values, dtype=np.float64)


# =============================================================================
# Scoring Models
# =============================================================================

class ScoreComponent(BaseModel):
    """
    Individual score component with contribution details.
    
    Tracks each component's contribution to the final score
    for explainability and debugging.
    
    Attributes:
        name: Component name
        rawScore: Unweighted score (0-1)
        weight: Weight applied to this component
        weightedScore: Score after weight applied
        category: Feature category
        factors: List of factors contributing to this score
    """
    
    name: str = Field(..., description="Component name")
    
    rawScore: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Raw unweighted score"
    )
    
    weight: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Weight applied to component"
    )
    
    category: FeatureCategory = Field(
        ...,
        description="Feature category"
    )
    
    factors: list[str] = Field(
        default_factory=list,
        description="Contributing factors"
    )
    
    @property
    def weightedScore(self) -> float:
        """Calculate weighted score."""
        return self.rawScore * self.weight


class RiskScore(BaseModel):
    """
    Final risk score with breakdown.
    
    Provides the final phishing risk assessment with full
    transparency into how the score was calculated.
    
    Attributes:
        url: URL that was scored
        domain: Domain name
        finalScore: Final risk score (0-1)
        riskLevel: Categorical risk level
        confidence: Score confidence (0-1)
        components: Individual score components
        reasons: Human-readable risk reasons
        scoredAt: Scoring timestamp
    """
    
    url: str = Field(..., description="Scored URL")
    domain: str = Field(..., description="Domain name")
    
    finalScore: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Final risk score (0=safe, 1=phishing)"
    )
    
    riskLevel: RiskLevel = Field(
        default=RiskLevel.SAFE,
        description="Categorical risk level"
    )
    
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Score confidence level"
    )
    
    components: list[ScoreComponent] = Field(
        default_factory=list,
        description="Score component breakdown"
    )
    
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable risk factors"
    )
    
    scoredAt: datetime = Field(
        default_factory=datetime.utcnow,
        description="Scoring timestamp"
    )
    
    @field_validator("reasons")
    @classmethod
    def limitReasons(cls, v: list[str]) -> list[str]:
        """Limit reasons to top 10 most important."""
        return v[:10]
    
    @property
    def isPhishing(self) -> bool:
        """Determine if URL is classified as phishing."""
        return self.riskLevel in (RiskLevel.DANGEROUS, RiskLevel.CRITICAL)

    @property
    def isSuspicious(self) -> bool:
        """Determine if URL is suspicious but not confirmed phishing."""
        return self.riskLevel == RiskLevel.SUSPICIOUS
    
    @property
    def componentBreakdown(self) -> dict[str, float]:
        """Get component scores as a dictionary."""
        return {comp.name: comp.weightedScore for comp in self.components}


# =============================================================================
# URL Analysis Models
# =============================================================================

class SuspiciousPattern(BaseModel):
    """
    Detected suspicious URL pattern.
    
    Represents a specific suspicious pattern found in a URL
    with details about why it's considered suspicious.
    
    Attributes:
        patternType: Type of pattern detected
        matchedValue: The actual value that matched
        severity: How suspicious this pattern is (0-1)
        description: Human-readable description
    """
    
    patternType: str = Field(..., description="Type of suspicious pattern")
    matchedValue: str = Field(..., description="Matched value in URL")
    severity: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Pattern severity"
    )
    description: str = Field(..., description="Pattern description")


class UrlAnalysisResult(BaseModel):
    """
    Detailed URL analysis result.
    
    Contains comprehensive analysis of a URL's structure
    including detected patterns and risk factors.
    
    Attributes:
        url: Analyzed URL
        scheme: URL scheme (http/https)
        domain: Domain name
        subdomain: Subdomain if present
        tld: Top-level domain
        path: URL path
        query: Query string
        fragment: URL fragment
        suspiciousPatterns: Detected suspicious patterns
        structuralScore: Score based on URL structure (0-1)
        analysisNotes: Additional analysis notes
    """
    
    url: str = Field(..., description="Original URL")
    
    # URL Components
    scheme: str = Field(default="http", description="URL scheme")
    domain: str = Field(..., description="Domain name")
    subdomain: Optional[str] = Field(default=None, description="Subdomain")
    tld: str = Field(default="", description="Top-level domain")
    path: str = Field(default="", description="URL path")
    query: Optional[str] = Field(default=None, description="Query string")
    fragment: Optional[str] = Field(default=None, description="URL fragment")
    
    # Analysis results
    suspiciousPatterns: list[SuspiciousPattern] = Field(
        default_factory=list,
        description="Detected suspicious patterns"
    )
    
    structuralScore: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Structural risk score"
    )
    
    analysisNotes: list[str] = Field(
        default_factory=list,
        description="Analysis notes"
    )
    
    analyzedAt: datetime = Field(
        default_factory=datetime.utcnow,
        description="Analysis timestamp"
    )
    
    @property
    def patternCount(self) -> int:
        """Count of suspicious patterns detected."""
        return len(self.suspiciousPatterns)
    
    @property
    def maxPatternSeverity(self) -> float:
        """Maximum severity among detected patterns."""
        if not self.suspiciousPatterns:
            return 0.0
        return max(p.severity for p in self.suspiciousPatterns)
    
    @property
    def averagePatternSeverity(self) -> float:
        """Average severity of detected patterns."""
        if not self.suspiciousPatterns:
            return 0.0
        return sum(p.severity for p in self.suspiciousPatterns) / len(self.suspiciousPatterns)
