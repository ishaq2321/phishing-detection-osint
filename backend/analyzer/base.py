"""
Analyzer Base Module
====================

Abstract base class defining the interface for phishing content analyzers.

This module provides a protocol-based design that allows swapping between
different analyzer implementations (NLP-based, LLM-based, rule-based, etc.)
without changing the API or orchestration logic.

Design Principles:
- Protocol-based for easy testing and mocking
- Async by default for I/O efficiency
- Type-safe with Pydantic models
- Graceful failure handling

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# =============================================================================
# Enumerations
# =============================================================================

class ContentType(str, Enum):
    """Type of content being analyzed."""
    URL = "url"
    EMAIL = "email"
    TEXT = "text"
    AUTO = "auto"  # Auto-detect content type


class ThreatLevel(str, Enum):
    """Classification of threat severity."""
    SAFE = "safe"           # 0.0 - 0.2: No threat detected
    SUSPICIOUS = "suspicious"  # 0.2 - 0.6: Some suspicious indicators
    DANGEROUS = "dangerous"    # 0.6 - 0.9: High probability of phishing
    CRITICAL = "critical"      # 0.9 - 1.0: Confirmed phishing


class PhishingTactic(str, Enum):
    """Common phishing tactics detected."""
    URGENCY = "urgency"
    AUTHORITY_IMPERSONATION = "authority_impersonation"
    BRAND_IMPERSONATION = "brand_impersonation"
    CREDENTIAL_REQUEST = "credential_request"
    THREAT_WARNING = "threat_warning"
    EMOTIONAL_MANIPULATION = "emotional_manipulation"
    MONETARY_REQUEST = "monetary_request"
    ATTACHMENT_MALWARE = "attachment_malware"
    LINK_MANIPULATION = "link_manipulation"
    SOCIAL_PROOF = "social_proof"


# =============================================================================
# Data Models
# =============================================================================

class DetectedIndicator(BaseModel):
    """
    A specific phishing indicator found in the content.
    
    Attributes:
        category: Category of indicator (urgency, threat, etc.)
        description: Human-readable description
        severity: Impact level (0.0 = benign, 1.0 = critical)
        evidence: Text fragment that triggered detection
        position: Optional position in content (char offset or line number)
    """
    
    category: str = Field(
        description="Category of the indicator"
    )
    
    description: str = Field(
        description="Human-readable explanation"
    )
    
    severity: float = Field(
        ge=0.0,
        le=1.0,
        description="Severity score (0-1)"
    )
    
    evidence: Optional[str] = Field(
        default=None,
        description="Text fragment that triggered detection"
    )
    
    position: Optional[int] = Field(
        default=None,
        description="Position in content (char offset)"
    )


class AnalysisResult(BaseModel):
    """
    Complete analysis result from a content analyzer.
    
    Attributes:
        isPhishing: Binary classification result
        confidenceScore: Confidence in the classification (0-1)
        threatLevel: Categorical threat assessment
        reasons: List of human-readable reasons for the verdict
        detectedTactics: List of phishing tactics identified
        indicators: Detailed indicators found
        analysisTime: Time taken for analysis (milliseconds)
        analyzedAt: Timestamp of analysis
    """
    
    isPhishing: bool = Field(
        description="True if content is classified as phishing"
    )
    
    confidenceScore: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence in classification (0-1)"
    )
    
    threatLevel: ThreatLevel = Field(
        description="Threat severity classification"
    )
    
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable reasons for verdict"
    )
    
    detectedTactics: list[PhishingTactic] = Field(
        default_factory=list,
        description="Phishing tactics detected"
    )
    
    indicators: list[DetectedIndicator] = Field(
        default_factory=list,
        description="Detailed indicators found"
    )
    
    analysisTime: float = Field(
        default=0.0,
        ge=0.0,
        description="Analysis duration in milliseconds"
    )
    
    analyzedAt: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp of analysis"
    )
    
    @property
    def topIndicators(self) -> list[DetectedIndicator]:
        """Get top 5 most severe indicators."""
        return sorted(
            self.indicators,
            key=lambda x: x.severity,
            reverse=True
        )[:5]
    
    @property
    def hasHighSeverityIndicators(self) -> bool:
        """Check if any high-severity indicators exist."""
        return any(ind.severity > 0.7 for ind in self.indicators)


# =============================================================================
# Abstract Base Class
# =============================================================================

class BaseAnalyzer(ABC):
    """
    Abstract base class for content analyzers.
    
    All analyzer implementations (NLP, LLM, rule-based, etc.) must
    implement this interface to ensure compatibility with the
    orchestration layer.
    
    Example:
        >>> class MyAnalyzer(BaseAnalyzer):
        ...     async def analyze(self, content: str, contentType: ContentType):
        ...         # Implementation...
        ...         return AnalysisResult(...)
        ...     
        ...     def getCapabilities(self):
        ...         return ["url", "email"]
    """
    
    @abstractmethod
    async def analyze(
        self,
        content: str,
        contentType: ContentType = ContentType.AUTO
    ) -> AnalysisResult:
        """
        Analyze content for phishing indicators.
        
        Args:
            content: The text content to analyze (URL, email body, etc.)
            contentType: Type of content (auto-detected if AUTO)
            
        Returns:
            AnalysisResult: Complete analysis with verdict and details
            
        Raises:
            ValueError: If content is empty or invalid
            RuntimeError: If analysis fails critically
        """
        pass
    
    @abstractmethod
    def getCapabilities(self) -> list[str]:
        """
        Get list of content types this analyzer supports.
        
        Returns:
            List of supported content types (e.g., ["url", "email", "text"])
        """
        pass
    
    @abstractmethod
    def getName(self) -> str:
        """
        Get analyzer name/identifier.
        
        Returns:
            Human-readable analyzer name (e.g., "NLP Analyzer", "LLM Analyzer")
        """
        pass
    
    @abstractmethod
    def getVersion(self) -> str:
        """
        Get analyzer version.
        
        Returns:
            Version string (e.g., "1.0.0")
        """
        pass


# =============================================================================
# Helper Functions
# =============================================================================

def determineThreatLevel(confidenceScore: float) -> ThreatLevel:
    """
    Determine threat level from confidence score.
    
    Args:
        confidenceScore: Phishing probability (0.0 - 1.0)
        
    Returns:
        ThreatLevel: Corresponding threat classification
        
    Example:
        >>> determineThreatLevel(0.15)
        ThreatLevel.SAFE
        >>> determineThreatLevel(0.85)
        ThreatLevel.CRITICAL
    """
    if confidenceScore < 0.4:
        return ThreatLevel.SAFE
    elif confidenceScore < 0.6:
        return ThreatLevel.SUSPICIOUS
    elif confidenceScore < 0.8:
        return ThreatLevel.DANGEROUS
    else:
        return ThreatLevel.CRITICAL


def detectContentType(content: str) -> ContentType:
    """
    Auto-detect content type from the content string.
    
    Args:
        content: The content to analyze
        
    Returns:
        ContentType: Detected content type
        
    Example:
        >>> detectContentType("https://example.com")
        ContentType.URL
        >>> detectContentType("From: sender@example.com\\nSubject: Test")
        ContentType.EMAIL
    """
    content_lower = content.lower().strip()
    
    # Check if it's only a URL
    if content_lower.startswith(("http://", "https://", "www.")) and " " not in content:
        return ContentType.URL
    
    # Check if it's an email address
    import re
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(email_pattern, content.strip()):
        return ContentType.EMAIL
    
    # Check if it's email content (has headers)
    if any(header in content_lower for header in ["from:", "subject:", "to:"]):
        return ContentType.EMAIL
    
    # Default to general text
    return ContentType.TEXT

