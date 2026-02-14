"""
API Schemas Module
==================

Pydantic models for API request and response schemas.

This module defines all data models used in the API layer for request
validation, response serialization, and data transfer between layers.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# =============================================================================
# Request Schemas
# =============================================================================

class AnalyzeRequest(BaseModel):
    """
    Request for analyzing content (URL or email).
    
    The content type is auto-detected by default but can be specified.
    
    Attributes:
        content: URL or email content to analyze
        contentType: Type of content (auto, url, email, text)
        
    Example:
        >>> request = AnalyzeRequest(
        ...     content="https://suspicious-paypal.com/login",
        ...     contentType="url"
        ... )
    """
    content: str = Field(
        ...,
        min_length=1,
        description="Content to analyze (URL, email, or text)",
        examples=["https://example.com/verify"]
    )
    contentType: str = Field(
        default="auto",
        pattern="^(auto|url|email|text)$",
        description="Type of content to analyze",
        examples=["auto"]
    )
    
    @field_validator("content")
    @classmethod
    def validateContent(cls, v: str) -> str:
        """Validate content is not empty."""
        if not v or not v.strip():
            raise ValueError("Content cannot be empty")
        return v.strip()


class UrlRequest(BaseModel):
    """
    Request for analyzing a URL.
    
    Attributes:
        url: URL to analyze for phishing
        
    Example:
        >>> request = UrlRequest(url="https://example.com")
    """
    url: str = Field(
        ...,
        min_length=1,
        description="URL to analyze",
        examples=["https://example.com/login"]
    )
    
    @field_validator("url")
    @classmethod
    def validateUrl(cls, v: str) -> str:
        """Validate URL is not empty."""
        if not v or not v.strip():
            raise ValueError("URL cannot be empty")
        return v.strip()


class EmailRequest(BaseModel):
    """
    Request for analyzing email content.
    
    Attributes:
        content: Email body content to analyze
        subject: Optional email subject line
        sender: Optional sender email address
        
    Example:
        >>> request = EmailRequest(
        ...     content="Urgent! Your account has been suspended...",
        ...     subject="Account Security Alert",
        ...     sender="security@example.com"
        ... )
    """
    content: str = Field(
        ...,
        min_length=1,
        description="Email body content",
        examples=["Your account will be suspended unless you verify..."]
    )
    subject: Optional[str] = Field(
        default=None,
        description="Email subject line",
        examples=["Account Security Alert"]
    )
    sender: Optional[str] = Field(
        default=None,
        description="Sender email address",
        examples=["security@paypal.com"]
    )
    
    @field_validator("content")
    @classmethod
    def validateContent(cls, v: str) -> str:
        """Validate content is not empty."""
        if not v or not v.strip():
            raise ValueError("Email content cannot be empty")
        return v.strip()


# =============================================================================
# Response Schemas
# =============================================================================

class VerdictResult(BaseModel):
    """
    Final verdict of the phishing analysis.
    
    Attributes:
        isPhishing: Whether content is classified as phishing
        confidenceScore: Confidence level (0.0-1.0)
        threatLevel: Threat classification
        reasons: List of human-readable reasons
        recommendation: Recommended action for user
        
    Example:
        >>> verdict = VerdictResult(
        ...     isPhishing=True,
        ...     confidenceScore=0.87,
        ...     threatLevel="dangerous",
        ...     reasons=["Uses urgency tactics", "Requests credentials"],
        ...     recommendation="Do not click any links. Report as phishing."
        ... )
    """
    isPhishing: bool = Field(
        ...,
        description="Whether content is classified as phishing"
    )
    confidenceScore: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score (0.0-1.0)"
    )
    threatLevel: str = Field(
        ...,
        pattern="^(safe|suspicious|dangerous|critical)$",
        description="Threat level classification"
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable reasons for the verdict",
        examples=[["Uses urgency tactics", "Suspicious domain age"]]
    )
    recommendation: str = Field(
        ...,
        description="Recommended action for the user",
        examples=["Proceed with caution"]
    )


class OsintSummary(BaseModel):
    """
    Summary of OSINT data collection.
    
    Attributes:
        domain: Domain that was analyzed
        domainAgeDays: Age of domain in days
        registrar: Domain registrar name
        isPrivate: Whether WHOIS privacy is enabled
        hasValidDns: Whether domain has valid DNS records
        reputationScore: Reputation score (0.0-1.0, higher is better)
        inBlacklists: Whether domain is in any blacklists
        
    Example:
        >>> osint = OsintSummary(
        ...     domain="example.com",
        ...     domainAgeDays=30,
        ...     registrar="GoDaddy",
        ...     isPrivate=True,
        ...     hasValidDns=True,
        ...     reputationScore=0.3,
        ...     inBlacklists=False
        ... )
    """
    domain: str = Field(..., description="Analyzed domain")
    domainAgeDays: Optional[int] = Field(
        default=None,
        description="Age of domain in days"
    )
    registrar: Optional[str] = Field(
        default=None,
        description="Domain registrar"
    )
    isPrivate: bool = Field(
        default=False,
        description="WHOIS privacy protection enabled"
    )
    hasValidDns: bool = Field(
        default=False,
        description="Has valid DNS records"
    )
    reputationScore: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Reputation score (higher is better)"
    )
    inBlacklists: bool = Field(
        default=False,
        description="Found in blacklists"
    )


class FeatureSummary(BaseModel):
    """
    Summary of extracted features.
    
    Attributes:
        urlFeatures: Number of URL-based suspicious features
        textFeatures: Number of text-based suspicious features
        osintFeatures: Number of OSINT-based risk indicators
        totalRiskIndicators: Total number of risk indicators
        detectedTactics: List of detected phishing tactics
        
    Example:
        >>> features = FeatureSummary(
        ...     urlFeatures=3,
        ...     textFeatures=5,
        ...     osintFeatures=2,
        ...     totalRiskIndicators=10,
        ...     detectedTactics=["urgency", "credential_request"]
        ... )
    """
    urlFeatures: int = Field(
        default=0,
        ge=0,
        description="Count of URL-based suspicious features"
    )
    textFeatures: int = Field(
        default=0,
        ge=0,
        description="Count of text-based suspicious features"
    )
    osintFeatures: int = Field(
        default=0,
        ge=0,
        description="Count of OSINT-based risk indicators"
    )
    totalRiskIndicators: int = Field(
        default=0,
        ge=0,
        description="Total number of risk indicators"
    )
    detectedTactics: list[str] = Field(
        default_factory=list,
        description="List of detected phishing tactics",
        examples=[["urgency", "brand_impersonation"]]
    )


class AnalysisResponse(BaseModel):
    """
    Complete analysis response.
    
    Attributes:
        success: Whether analysis completed successfully
        verdict: Final verdict result
        osint: OSINT data summary (if available)
        features: Feature extraction summary
        analysisTime: Time taken for analysis (milliseconds)
        analyzedAt: Timestamp of analysis
        error: Error message if analysis failed
        
    Example:
        >>> response = AnalysisResponse(
        ...     success=True,
        ...     verdict=verdict_result,
        ...     osint=osint_summary,
        ...     features=feature_summary,
        ...     analysisTime=1250.5,
        ...     analyzedAt=datetime.now()
        ... )
    """
    success: bool = Field(
        ...,
        description="Whether analysis completed successfully"
    )
    verdict: VerdictResult = Field(
        ...,
        description="Analysis verdict"
    )
    osint: Optional[OsintSummary] = Field(
        default=None,
        description="OSINT data summary"
    )
    features: FeatureSummary = Field(
        ...,
        description="Extracted features summary"
    )
    analysisTime: float = Field(
        ...,
        ge=0.0,
        description="Analysis time in milliseconds"
    )
    analyzedAt: datetime = Field(
        default_factory=datetime.now,
        description="Analysis timestamp"
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message if analysis failed"
    )


class HealthResponse(BaseModel):
    """
    Health check response.
    
    Attributes:
        status: Service status
        version: API version
        timestamp: Current timestamp
        services: Status of dependent services
        
    Example:
        >>> health = HealthResponse(
        ...     status="healthy",
        ...     version="1.0.0",
        ...     timestamp=datetime.now(),
        ...     services={"osint": True, "analyzer": True, "ml": True}
        ... )
    """
    status: str = Field(
        ...,
        pattern="^(healthy|degraded|unhealthy)$",
        description="Service health status"
    )
    version: str = Field(
        ...,
        description="API version"
    )
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="Current timestamp"
    )
    services: dict[str, bool] = Field(
        default_factory=dict,
        description="Status of dependent services"
    )
