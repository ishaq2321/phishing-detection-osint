"""
URL Analyzer Module
===================

Performs deep structural analysis of URLs to detect phishing patterns.

This module goes beyond basic feature extraction to identify specific
suspicious patterns, brand impersonation attempts, and URL obfuscation
techniques commonly used in phishing attacks.

Design Principles:
- Pattern-based detection with configurable rules
- Comprehensive coverage of known phishing URL techniques
- Severity scoring for each detected pattern
- Extensible pattern registry for future updates

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote, urlparse

from .schemas import SuspiciousPattern, UrlAnalysisResult


# =============================================================================
# Pattern Definitions
# =============================================================================

@dataclass(frozen=True)
class PatternDefinition:
    """Definition of a suspicious URL pattern."""
    
    patternType: str
    pattern: re.Pattern
    severity: float
    description: str
    checkDomain: bool = False  # True if pattern should check domain only


# Brand impersonation patterns
BRAND_PATTERNS: list[PatternDefinition] = [
    PatternDefinition(
        patternType="brand_impersonation",
        pattern=re.compile(r"paypal[^a-z]|[^a-z]paypal", re.IGNORECASE),
        severity=0.9,
        description="Potential PayPal impersonation",
        checkDomain=True,
    ),
    PatternDefinition(
        patternType="brand_impersonation",
        pattern=re.compile(r"microsoft[^a-z]|[^a-z]microsoft", re.IGNORECASE),
        severity=0.9,
        description="Potential Microsoft impersonation",
        checkDomain=True,
    ),
    PatternDefinition(
        patternType="brand_impersonation",
        pattern=re.compile(r"apple[^a-z]|[^a-z]apple(?!sauce|pie)", re.IGNORECASE),
        severity=0.85,
        description="Potential Apple impersonation",
        checkDomain=True,
    ),
    PatternDefinition(
        patternType="brand_impersonation",
        pattern=re.compile(r"amazon[^a-z]|[^a-z]amazon", re.IGNORECASE),
        severity=0.9,
        description="Potential Amazon impersonation",
        checkDomain=True,
    ),
    PatternDefinition(
        patternType="brand_impersonation",
        pattern=re.compile(r"netflix[^a-z]|[^a-z]netflix", re.IGNORECASE),
        severity=0.85,
        description="Potential Netflix impersonation",
        checkDomain=True,
    ),
    PatternDefinition(
        patternType="brand_impersonation",
        pattern=re.compile(r"google[^a-z]|[^a-z]google", re.IGNORECASE),
        severity=0.85,
        description="Potential Google impersonation",
        checkDomain=True,
    ),
    PatternDefinition(
        patternType="brand_impersonation",
        pattern=re.compile(r"facebook[^a-z]|[^a-z]facebook", re.IGNORECASE),
        severity=0.85,
        description="Potential Facebook impersonation",
        checkDomain=True,
    ),
    PatternDefinition(
        patternType="brand_impersonation",
        pattern=re.compile(r"instagram[^a-z]|[^a-z]instagram", re.IGNORECASE),
        severity=0.85,
        description="Potential Instagram impersonation",
        checkDomain=True,
    ),
    PatternDefinition(
        patternType="brand_impersonation",
        pattern=re.compile(r"linkedin[^a-z]|[^a-z]linkedin", re.IGNORECASE),
        severity=0.85,
        description="Potential LinkedIn impersonation",
        checkDomain=True,
    ),
    PatternDefinition(
        patternType="brand_impersonation",
        pattern=re.compile(r"dropbox[^a-z]|[^a-z]dropbox", re.IGNORECASE),
        severity=0.85,
        description="Potential Dropbox impersonation",
        checkDomain=True,
    ),
]

# URL obfuscation patterns
OBFUSCATION_PATTERNS: list[PatternDefinition] = [
    PatternDefinition(
        patternType="url_obfuscation",
        pattern=re.compile(r"@"),
        severity=0.95,
        description="URL contains @ symbol (credential injection attack)",
    ),
    PatternDefinition(
        patternType="url_obfuscation",
        pattern=re.compile(r"//[^/]+//"),
        severity=0.8,
        description="Double slash in URL path (redirect confusion)",
    ),
    PatternDefinition(
        patternType="url_obfuscation",
        pattern=re.compile(r"%00|%0d|%0a", re.IGNORECASE),
        severity=0.9,
        description="Null byte or newline injection",
    ),
    PatternDefinition(
        patternType="url_obfuscation",
        pattern=re.compile(r"(?:%[0-9a-f]{2}){4,}", re.IGNORECASE),
        severity=0.7,
        description="Excessive URL encoding",
    ),
    PatternDefinition(
        patternType="url_obfuscation",
        pattern=re.compile(r"0x[0-9a-f]+", re.IGNORECASE),
        severity=0.85,
        description="Hexadecimal IP address encoding",
    ),
    PatternDefinition(
        patternType="url_obfuscation",
        pattern=re.compile(r"\d{10,}"),
        severity=0.8,
        description="Decimal IP address encoding",
    ),
]

# Credential harvesting patterns
CREDENTIAL_PATTERNS: list[PatternDefinition] = [
    PatternDefinition(
        patternType="credential_harvesting",
        pattern=re.compile(r"login|signin|sign-in|logon", re.IGNORECASE),
        severity=0.6,
        description="Login-related keyword in URL",
    ),
    PatternDefinition(
        patternType="credential_harvesting",
        pattern=re.compile(r"password|passwd|pwd", re.IGNORECASE),
        severity=0.75,
        description="Password-related keyword in URL",
    ),
    PatternDefinition(
        patternType="credential_harvesting",
        pattern=re.compile(r"verify|verification|confirm", re.IGNORECASE),
        severity=0.65,
        description="Verification keyword in URL",
    ),
    PatternDefinition(
        patternType="credential_harvesting",
        pattern=re.compile(r"account|banking|wallet", re.IGNORECASE),
        severity=0.6,
        description="Account-related keyword in URL",
    ),
    PatternDefinition(
        patternType="credential_harvesting",
        pattern=re.compile(r"secure|security|auth", re.IGNORECASE),
        severity=0.55,
        description="Security-related keyword in URL",
    ),
    PatternDefinition(
        patternType="credential_harvesting",
        pattern=re.compile(r"update.*(?:payment|card|billing)", re.IGNORECASE),
        severity=0.8,
        description="Payment update request in URL",
    ),
]

# Suspicious structure patterns
STRUCTURE_PATTERNS: list[PatternDefinition] = [
    PatternDefinition(
        patternType="suspicious_structure",
        pattern=re.compile(r"-{2,}"),
        severity=0.5,
        description="Multiple consecutive hyphens in domain",
        checkDomain=True,
    ),
    PatternDefinition(
        patternType="suspicious_structure",
        pattern=re.compile(r"\.{2,}"),
        severity=0.7,
        description="Multiple consecutive dots",
    ),
    PatternDefinition(
        patternType="suspicious_structure",
        pattern=re.compile(r"[a-z0-9]{30,}", re.IGNORECASE),
        severity=0.65,
        description="Extremely long random-looking string",
    ),
    PatternDefinition(
        patternType="suspicious_structure",
        pattern=re.compile(r"[0-9]{4,}[a-z]{4,}|[a-z]{4,}[0-9]{4,}", re.IGNORECASE),
        severity=0.55,
        description="Mixed alphanumeric pattern suggesting randomization",
    ),
]

# Urgency/threat patterns in URL
URGENCY_PATTERNS: list[PatternDefinition] = [
    PatternDefinition(
        patternType="urgency_indicator",
        pattern=re.compile(r"suspend|locked|blocked|disabled", re.IGNORECASE),
        severity=0.75,
        description="Account suspension/blocking language",
    ),
    PatternDefinition(
        patternType="urgency_indicator",
        pattern=re.compile(r"urgent|immediate|expire|limited", re.IGNORECASE),
        severity=0.7,
        description="Urgency language in URL",
    ),
    PatternDefinition(
        patternType="urgency_indicator",
        pattern=re.compile(r"24.?hours?|48.?hours?|action.?required", re.IGNORECASE),
        severity=0.75,
        description="Time pressure language",
    ),
]

# Suspicious TLD patterns
SUSPICIOUS_TLD_PATTERNS: list[PatternDefinition] = [
    PatternDefinition(
        patternType="suspicious_tld",
        pattern=re.compile(r"\.(tk|ml|ga|cf|gq)$", re.IGNORECASE),
        severity=0.8,
        description="Free domain TLD (commonly abused)",
        checkDomain=True,
    ),
    PatternDefinition(
        patternType="suspicious_tld",
        pattern=re.compile(r"\.(xyz|top|work|click|link)$", re.IGNORECASE),
        severity=0.6,
        description="Low-cost TLD (frequently used in phishing)",
        checkDomain=True,
    ),
    PatternDefinition(
        patternType="suspicious_tld",
        pattern=re.compile(r"\.(bid|stream|download|racing)$", re.IGNORECASE),
        severity=0.7,
        description="Spam-associated TLD",
        checkDomain=True,
    ),
]

# Combine all patterns
ALL_PATTERNS: list[PatternDefinition] = (
    BRAND_PATTERNS
    + OBFUSCATION_PATTERNS
    + CREDENTIAL_PATTERNS
    + STRUCTURE_PATTERNS
    + URGENCY_PATTERNS
    + SUSPICIOUS_TLD_PATTERNS
)


# =============================================================================
# Known Legitimate Domains
# =============================================================================

# Domains that should not trigger brand impersonation
LEGITIMATE_BRAND_DOMAINS = frozenset({
    # PayPal
    "paypal.com", "paypal.me",
    # Microsoft
    "microsoft.com", "live.com", "outlook.com", "office.com",
    "azure.com", "windows.com", "xbox.com", "bing.com",
    # Apple
    "apple.com", "icloud.com",
    # Amazon
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr",
    "amazonaws.com", "aws.amazon.com",
    # Netflix
    "netflix.com",
    # Google
    "google.com", "gmail.com", "youtube.com", "googleapis.com",
    "google.co.uk", "google.de", "google.fr",
    # Facebook/Meta
    "facebook.com", "fb.com", "messenger.com", "meta.com",
    # Instagram
    "instagram.com",
    # LinkedIn
    "linkedin.com",
    # Dropbox
    "dropbox.com",
})


# =============================================================================
# URL Analyzer Class
# =============================================================================

class UrlAnalyzer:
    """
    Comprehensive URL analyzer for phishing detection.
    
    Analyzes URL structure, detects suspicious patterns, and
    calculates a structural risk score based on findings.
    
    Example:
        >>> analyzer = UrlAnalyzer()
        >>> result = analyzer.analyze("https://paypal-secure-login.example.tk/verify")
        >>> print(result.structuralScore)
        0.85
        >>> print(len(result.suspiciousPatterns))
        4
    """
    
    def __init__(
        self,
        patterns: Optional[list[PatternDefinition]] = None,
        legitimateDomains: Optional[frozenset[str]] = None,
    ) -> None:
        """
        Initialize the URL analyzer.
        
        Args:
            patterns: Custom pattern definitions (uses defaults if None)
            legitimateDomains: Known legitimate brand domains
        """
        self._patterns = patterns if patterns is not None else ALL_PATTERNS
        self._legitimateDomains = (
            legitimateDomains
            if legitimateDomains is not None
            else LEGITIMATE_BRAND_DOMAINS
        )
    
    def analyze(self, url: str) -> UrlAnalysisResult:
        """
        Perform comprehensive URL analysis.
        
        Args:
            url: URL string to analyze
            
        Returns:
            UrlAnalysisResult: Analysis result with detected patterns
        """
        if not url:
            return UrlAnalysisResult(
                url="",
                domain="",
                analysisNotes=["Empty URL provided"],
            )
        
        # Normalize and parse URL
        normalizedUrl = url.strip()
        if not normalizedUrl.startswith(("http://", "https://")):
            normalizedUrl = "http://" + normalizedUrl
        
        try:
            parsed = urlparse(normalizedUrl)
        except Exception as e:
            return UrlAnalysisResult(
                url=url,
                domain="",
                analysisNotes=[f"URL parsing failed: {str(e)}"],
            )
        
        # Extract components
        scheme = parsed.scheme.lower()
        domain = parsed.netloc.lower()
        domainWithoutPort = domain.split(":")[0]
        
        # Extract subdomain and TLD
        subdomain, baseDomain, tld = self._parseDomainComponents(domainWithoutPort)
        
        path = parsed.path or ""
        query = parsed.query or None
        fragment = parsed.fragment or None
        
        # Check if this is a legitimate brand domain
        isLegitimate = self._isLegitimateDomain(domainWithoutPort)
        
        # Detect suspicious patterns
        suspiciousPatterns = self._detectPatterns(
            normalizedUrl,
            domainWithoutPort,
            isLegitimate,
        )
        
        # Calculate structural score
        structuralScore = self._calculateStructuralScore(
            suspiciousPatterns,
            normalizedUrl,
            scheme,
        )
        
        # Generate analysis notes
        analysisNotes = self._generateNotes(
            suspiciousPatterns,
            isLegitimate,
            scheme,
        )
        
        return UrlAnalysisResult(
            url=url,
            scheme=scheme,
            domain=domainWithoutPort,
            subdomain=subdomain,
            tld=tld,
            path=path,
            query=query,
            fragment=fragment,
            suspiciousPatterns=suspiciousPatterns,
            structuralScore=structuralScore,
            analysisNotes=analysisNotes,
        )
    
    def _parseDomainComponents(
        self,
        domain: str,
    ) -> tuple[Optional[str], str, str]:
        """
        Parse domain into subdomain, base domain, and TLD.
        
        Returns:
            Tuple of (subdomain, baseDomain, tld)
        """
        if not domain:
            return None, "", ""
        
        # Check for IP address
        if self._isIpAddress(domain):
            return None, domain, ""
        
        parts = domain.split(".")
        
        if len(parts) < 2:
            return None, domain, ""
        
        tld = parts[-1]
        
        # Handle two-part TLDs
        twoPartTlds = {"co.uk", "com.au", "org.uk", "net.au", "ac.uk", "gov.uk"}
        if len(parts) >= 3:
            possibleTwoPartTld = f"{parts[-2]}.{parts[-1]}"
            if possibleTwoPartTld in twoPartTlds:
                tld = possibleTwoPartTld
                baseDomain = parts[-3] if len(parts) >= 3 else ""
                subdomain = ".".join(parts[:-3]) if len(parts) > 3 else None
                return subdomain or None, baseDomain, tld
        
        if len(parts) == 2:
            return None, parts[0], tld
        
        baseDomain = parts[-2]
        subdomain = ".".join(parts[:-2])
        
        return subdomain or None, baseDomain, tld
    
    def _isIpAddress(self, domain: str) -> bool:
        """Check if domain is an IP address."""
        # Simple IPv4 check
        parts = domain.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                pass
        return False
    
    def _isLegitimateDomain(self, domain: str) -> bool:
        """Check if domain is a known legitimate brand domain."""
        # Direct match
        if domain in self._legitimateDomains:
            return True
        
        # Check if it's a subdomain of a legitimate domain
        for legitDomain in self._legitimateDomains:
            if domain.endswith("." + legitDomain):
                return True
        
        return False
    
    def _detectPatterns(
        self,
        url: str,
        domain: str,
        isLegitimate: bool,
    ) -> list[SuspiciousPattern]:
        """Detect all suspicious patterns in the URL."""
        patterns: list[SuspiciousPattern] = []
        
        # Keep both original (for encoded patterns) and decoded (for content patterns)
        originalUrl = url
        try:
            decodedUrl = unquote(url)
        except Exception:
            decodedUrl = url
        
        for patternDef in self._patterns:
            # Skip brand impersonation for legitimate domains
            if isLegitimate and patternDef.patternType == "brand_impersonation":
                continue
            
            # Determine what to check
            if patternDef.checkDomain:
                textToCheck = domain
            elif patternDef.patternType == "url_obfuscation":
                # For obfuscation patterns, check original URL (to catch %00, etc.)
                textToCheck = originalUrl
            else:
                textToCheck = decodedUrl
            
            # Search for pattern
            match = patternDef.pattern.search(textToCheck)
            if match:
                patterns.append(
                    SuspiciousPattern(
                        patternType=patternDef.patternType,
                        matchedValue=match.group(),
                        severity=patternDef.severity,
                        description=patternDef.description,
                    )
                )
        
        return patterns
    
    def _calculateStructuralScore(
        self,
        patterns: list[SuspiciousPattern],
        url: str,
        scheme: str,
    ) -> float:
        """
        Calculate overall structural risk score.
        
        Score ranges from 0 (safe) to 1 (highly suspicious).
        """
        if not patterns:
            # Base score for URLs without detected patterns
            baseScore = 0.0
            
            # Slight penalty for HTTP
            if scheme != "https":
                baseScore += 0.1
            
            # Penalty for very long URLs
            if len(url) > 100:
                baseScore += 0.05
            if len(url) > 200:
                baseScore += 0.1
            
            return min(baseScore, 1.0)
        
        # Calculate score based on patterns
        # Use a weighted combination approach
        
        # Maximum severity (most dangerous pattern)
        maxSeverity = max(p.severity for p in patterns)
        
        # Average severity
        avgSeverity = sum(p.severity for p in patterns) / len(patterns)
        
        # Pattern count factor (more patterns = more suspicious)
        countFactor = min(len(patterns) / 5, 1.0)  # Cap at 5 patterns
        
        # Combine factors
        # 50% max severity + 30% average + 20% count factor
        score = (maxSeverity * 0.5) + (avgSeverity * 0.3) + (countFactor * 0.2)
        
        # HTTP penalty
        if scheme != "https":
            score = min(score + 0.1, 1.0)
        
        return min(max(score, 0.0), 1.0)
    
    def _generateNotes(
        self,
        patterns: list[SuspiciousPattern],
        isLegitimate: bool,
        scheme: str,
    ) -> list[str]:
        """Generate human-readable analysis notes."""
        notes: list[str] = []
        
        if isLegitimate:
            notes.append("Domain matches known legitimate brand")
        
        if scheme != "https":
            notes.append("URL does not use HTTPS encryption")
        
        if not patterns:
            notes.append("No suspicious patterns detected")
            return notes
        
        # Group patterns by type
        patternTypes: dict[str, int] = {}
        for pattern in patterns:
            patternTypes[pattern.patternType] = (
                patternTypes.get(pattern.patternType, 0) + 1
            )
        
        for patternType, count in patternTypes.items():
            readableType = patternType.replace("_", " ").title()
            notes.append(f"{count} {readableType} pattern(s) detected")
        
        # Add note for high-severity patterns
        highSeverityPatterns = [p for p in patterns if p.severity >= 0.8]
        if highSeverityPatterns:
            notes.append(
                f"{len(highSeverityPatterns)} high-severity indicator(s) found"
            )
        
        return notes


# =============================================================================
# Convenience Functions
# =============================================================================

def analyzeUrl(url: str) -> UrlAnalysisResult:
    """
    Convenience function for URL analysis.
    
    Creates a UrlAnalyzer and analyzes the URL in one call.
    
    Args:
        url: URL to analyze
        
    Returns:
        UrlAnalysisResult: Analysis result
        
    Example:
        >>> result = analyzeUrl("https://example.com")
        >>> print(result.structuralScore)
        0.0
    """
    analyzer = UrlAnalyzer()
    return analyzer.analyze(url)


def detectBrandImpersonation(url: str) -> list[SuspiciousPattern]:
    """
    Detect potential brand impersonation in a URL.
    
    Args:
        url: URL to check
        
    Returns:
        List of brand impersonation patterns detected
        
    Example:
        >>> patterns = detectBrandImpersonation("https://paypal-secure.example.tk")
        >>> len(patterns)
        1
    """
    result = analyzeUrl(url)
    return [
        p for p in result.suspiciousPatterns
        if p.patternType == "brand_impersonation"
    ]


def detectUrlObfuscation(url: str) -> list[SuspiciousPattern]:
    """
    Detect URL obfuscation techniques.
    
    Args:
        url: URL to check
        
    Returns:
        List of obfuscation patterns detected
        
    Example:
        >>> patterns = detectUrlObfuscation("https://example.com@evil.tk")
        >>> len(patterns)
        1
    """
    result = analyzeUrl(url)
    return [
        p for p in result.suspiciousPatterns
        if p.patternType == "url_obfuscation"
    ]


def getUrlRiskLevel(url: str) -> str:
    """
    Get a simple risk level for a URL.
    
    Args:
        url: URL to check
        
    Returns:
        Risk level: "safe", "low", "medium", "high", or "critical"
        
    Example:
        >>> getUrlRiskLevel("https://google.com")
        "safe"
        >>> getUrlRiskLevel("https://paypal-verify.example.tk")
        "high"
    """
    result = analyzeUrl(url)
    score = result.structuralScore
    
    if score < 0.2:
        return "safe"
    elif score < 0.4:
        return "low"
    elif score < 0.6:
        return "medium"
    elif score < 0.8:
        return "high"
    else:
        return "critical"
