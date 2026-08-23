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
from typing import List, Optional

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

class ModelStatusResponse(BaseModel):
    """ML model status metadata."""

    loaded: bool = Field(..., description="Whether the XGBoost model is loaded")
    featureCount: int = Field(default=0, description="Number of input features")
    featureNames: list[str] = Field(default_factory=list, description="Ordered feature names")


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


class ExplanationItem(BaseModel):
    """A single deterministic explanation signal for a verdict.

    Attributes:
        signal: Machine-readable identifier (e.g. ``newlyRegisteredDomain``)
        severity: One of critical / high / medium / low
        detail: Human-readable sentence describing the signal
    """
    signal: str = Field(..., description="Machine-readable signal identifier")
    severity: str = Field(
        ...,
        pattern="^(critical|high|medium|low)$",
        description="Severity band of the signal",
    )
    detail: str = Field(
        ...,
        description="Human-readable explanation sentence",
    )


class ExplanationReport(BaseModel):
    """Deterministic, template-generated verdict explanation.

    Every item is derived from a concrete feature value or OSINT signal —
    no generative model involved — so explanations are reproducible and
    auditable. Items are ordered by severity, then by global SHAP
    importance of the underlying feature.
    """
    summary: str = Field(
        ...,
        description="One-sentence plain-language summary of the verdict",
    )
    items: List[ExplanationItem] = Field(
        default_factory=list,
        description="Explanation signals ordered by severity then importance",
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
    explanation: Optional[ExplanationReport] = Field(
        default=None,
        description="Deterministic explanation report (URL analyses)"
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
        checks: Per-dependency deep-check report (Tier 1.5)
        uptimeSeconds: Seconds since application start (Tier 1.5)
        ready: True when the deep check has completed at least once

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
        description="Service health status",
    )
    version: str = Field(
        ...,
        description="API version",
    )
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="Current timestamp",
    )
    services: dict[str, bool] = Field(
        default_factory=dict,
        description="Status of dependent services",
    )
    # Tier 1.5 deep-check additions -- ALL OPTIONAL to keep the prior
    # shallow response shape backward-compatible.
    checks: Optional[dict[str, dict]] = Field(
        default=None,
        description=(
            "Per-dependency deep-check report.  Each entry has "
            "``status`` ('up'/'down'), ``latencyMs`` (when measured), "
            "and ``detail`` (human-readable note on failure)."
        ),
    )
    uptimeSeconds: Optional[float] = Field(
        default=None,
        description="Seconds since application startup",
    )
    ready: Optional[bool] = Field(
        default=None,
        description=(
            "True when the application has finished initialising and is "
            "ready to serve traffic."
        ),
    )



# =============================================================================
# Tier 3: Batch analysis request / response
# =============================================================================

class BatchItemRequest(BaseModel):
    """Single item inside a batch payload.

    Discriminated by ``type``:

    * ``url``   -> only ``url`` is required; ``subject``/``sender`` must be empty
    * ``email`` -> requires ``content``; ``subject``/``sender`` optional
    * ``auto``  -> server auto-detects via the same heuristic the
                   single-content route uses (URL-shaped -> url,
                   presence of @ or ``from:`` header -> email, else text)
    """

    type: str = Field(
        ...,
        pattern="^(auto|url|email)$",
        description="Discriminator: url, email, or auto-detect",
        examples=["url"],
    )
    url: Optional[str] = Field(
        default=None,
        description="URL to analyse (required when type=url)",
        examples=["https://example.com/login"],
    )
    content: Optional[str] = Field(
        default=None,
        description="Email or free-text body (required when type=email)",
        examples=["Urgent! Verify your account."],
    )
    subject: Optional[str] = Field(
        default=None,
        description="Optional email subject (type=email only)",
    )
    sender: Optional[str] = Field(
        default=None,
        description="Optional email sender (type=email only)",
    )

    @field_validator("type", mode="before")
    @classmethod
    def _normaliseType(cls, v: str) -> str:
        """Lower-case and strip BEFORE the ``pattern`` regex runs,
        so ``"URL"`` and ``" email "`` both pass the discriminator.

        An empty/whitespace ``type`` is rejected (the schema's
        ``pattern`` validator enforces non-empty after normalisation).
        """
        if not isinstance(v, str):
            return v
        stripped = v.strip().lower()
        if not stripped:
            raise ValueError("type must be one of {auto, url, email}")
        return stripped


class BatchAnalyzeRequest(BaseModel):
    """Payload for ``POST /api/analyze/batch``.

    Accepts up to 50 items in a single POST.  The server runs each
    item through the same orchestrator pipeline used by the singles
    routes, with ``asyncio.gather`` for concurrency, and returns a
    per-item result list.  Per-item failures do NOT reject the top-
    level call - the operator sees both succeeded and errored items in
    one round trip.
    """

    items: list[BatchItemRequest] = Field(
        ...,
        min_length=1,
        max_length=50,
        description=(
            "List of items to analyse.  1 <= N <= 50.  Larger payloads "
            "are rejected with HTTP 422 by the framework's length "
            "validator."
        ),
    )

    @field_validator("items")
    @classmethod
    def _noEmptyItemsList(cls, v: list) -> list:
        if not v:
            raise ValueError("items must contain at least one entry")
        return v


class BatchItemResult(BaseModel):
    """Per-item outcome inside a batch response.

    Exactly **one** of ``response`` or ``error`` is non-null.
    """

    index: int = Field(
        ...,
        ge=0,
        description="Index in the original items list (zero-based)",
    )
    status: str = Field(
        ...,
        pattern="^(ok|error)$",
        description="ok if analysis succeeded, error otherwise",
    )
    response: Optional[AnalysisResponse] = Field(
        default=None,
        description="Full analysis response (only when status=ok)",
    )
    error: Optional[str] = Field(
        default=None,
        description=(
            "Human-readable error message (only when status=error). "
            "Mirrors the orchestrator-level exception text."
        ),
    )


class BatchAnalyzeResponse(BaseModel):
    """Top-level batch response.

    Aggregates per-item results into one response payload.  Even when
    every individual item errored, the HTTP status is 200 because the
    BATCH itself processed without incident -- callers must look at
    the per-entry ``status`` field to know each outcome.
    """

    success: bool = Field(
        ...,
        description="Always true at the top level (HTTP 200 was returned)",
    )
    total: int = Field(
        ...,
        ge=0,
        description="Number of items in the original request",
    )
    succeeded: int = Field(
        ...,
        ge=0,
        description="Number of items that produced an analysis response",
    )
    failed: int = Field(
        ...,
        ge=0,
        description="Number of items whose analysis errored",
    )
    analysisTime: float = Field(
        ...,
        ge=0.0,
        description="Wall-clock milliseconds for the entire batch",
    )
    results: list[BatchItemResult] = Field(
        default_factory=list,
        description="Per-item outcome in original-order",
    )


# =============================================================================
# Tier 4 E: RFC 822 / MIME .eml ingestion
# =============================================================================

class EmIngestSummary(BaseModel):
    """Metadata parsed from a raw ``.eml`` payload (Tier 4 E).

    Returned alongside the normal ``AnalysisResponse`` fields so the
    operator sees exactly what the parser extracted -- useful when
    forwarding a suspicious message for triage.
    """

    subject: str = Field(
        default="",
        description="Decoded Subject header (empty when absent)",
    )
    senderName: str = Field(
        default="",
        description="Display name from the From header (empty when absent)",
    )
    senderAddress: str = Field(
        default="",
        description="Email address from the From header (empty when absent)",
    )
    recipients: list[str] = Field(
        default_factory=list,
        description="Addresses from To / Cc headers",
    )
    bodyPreview: str = Field(
        default="",
        description="First 200 chars of the extracted plain-text body",
    )
    hasAttachments: bool = Field(
        default=False,
        description="True when the message carries non-text parts",
    )
    attachmentNames: list[str] = Field(
        default_factory=list,
        description="Filenames of attached parts",
    )
    sizeBytes: int = Field(
        default=0,
        ge=0,
        description="Raw .eml payload size in bytes",
    )


class EmailIngestResponse(AnalysisResponse):
    """Response for ``POST /api/ingest/email``.

    Everything in :class:`AnalysisResponse` (verdict, osint, features)
    plus the ``parsed`` summary of the extracted fields.
    """

    parsed: EmIngestSummary = Field(
        ...,
        description="Metadata parsed from the raw .eml payload",
    )


# Public re-exports so conftest.py and tests pick them up.
__all__ = [
    "AnalyzeRequest",
    "UrlRequest",
    "EmailRequest",
    "ModelStatusResponse",
    "VerdictResult",
    "OsintSummary",
    "FeatureSummary",
    "AnalysisResponse",
    "HealthResponse",
    "BatchItemRequest",
    "BatchAnalyzeRequest",
    "BatchItemResult",
    "BatchAnalyzeResponse",
    "EmIngestSummary",
    "EmailIngestResponse",
]
