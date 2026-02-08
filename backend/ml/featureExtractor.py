"""
Feature Extractor Module
========================

Extracts numerical and boolean features from URLs and OSINT data
for use in the phishing scoring model.

This module transforms raw URL strings and OSINT results into
structured feature sets that can be used for machine learning
classification or rule-based scoring.

Design Principles:
- Pure functions where possible for testability
- Protocol-based dependency injection for OSINT data
- Comprehensive feature extraction covering all known phishing indicators
- Graceful handling of missing or incomplete data

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import re
import time
from typing import Optional, Protocol
from urllib.parse import parse_qs, unquote, urlparse

from .schemas import FeatureSet, OsintFeatures, UrlFeatures


# =============================================================================
# Constants
# =============================================================================

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = frozenset({
    "tk", "ml", "ga", "cf", "gq",  # Freenom free domains
    "xyz", "top", "work", "click", "link",
    "info", "online", "site", "website",
    "buzz", "club", "live", "icu", "cam",
    "bid", "stream", "download", "racing",
})

# Keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = frozenset({
    "login", "signin", "sign-in", "logon",
    "verify", "verification", "confirm", "confirmation",
    "secure", "security", "update", "upgrade",
    "account", "banking", "bank", "wallet",
    "paypal", "netflix", "amazon", "apple", "microsoft",
    "password", "credential", "authenticate",
    "suspend", "suspended", "locked", "unlock",
    "urgent", "immediately", "action", "required",
})

# Regex patterns
IP_ADDRESS_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# IPv6 pattern (covers full, compressed, and loopback forms)
IPV6_PATTERN = re.compile(
    r"^\[?"  # Optional opening bracket
    r"(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"  # Full form
    r"(?:[0-9a-fA-F]{1,4}:)*:(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{0,4}|"  # Compressed
    r"::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{0,4}|"  # Leading ::
    r"(?:[0-9a-fA-F]{1,4}:)+:|"  # Trailing ::
    r"::"  # Just :: (loopback shorthand)
    r")"
    r"\]?$"  # Optional closing bracket
)

# URL-encoded character pattern
ENCODED_CHAR_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")

# Port number in URL pattern
PORT_PATTERN = re.compile(r":(\d+)(?:/|$)")


# =============================================================================
# Protocol Definitions
# =============================================================================

class OsintDataProtocol(Protocol):
    """Protocol for OSINT data access."""
    
    @property
    def hasWhois(self) -> bool:
        """Check if WHOIS data is available."""
        ...
    
    @property
    def hasDns(self) -> bool:
        """Check if DNS data is available."""
        ...
    
    @property
    def hasReputation(self) -> bool:
        """Check if reputation data is available."""
        ...


# =============================================================================
# URL Feature Extraction
# =============================================================================

def extractUrlFeatures(url: str) -> UrlFeatures:
    """
    Extract structural features from a URL.
    
    Analyzes the URL string to extract features that are commonly
    associated with phishing URLs, such as length, special characters,
    suspicious patterns, etc.
    
    Args:
        url: The URL string to analyze
        
    Returns:
        UrlFeatures: Extracted URL features
        
    Example:
        >>> features = extractUrlFeatures("https://login-secure.example.com/verify")
        >>> features.hasSuspiciousKeywords
        True
        >>> features.hasHttps
        True
    """
    if not url:
        return UrlFeatures()
    
    # Normalize and parse URL
    normalizedUrl = url.strip()
    if not normalizedUrl.startswith(("http://", "https://")):
        normalizedUrl = "http://" + normalizedUrl
    
    try:
        parsed = urlparse(normalizedUrl)
    except Exception:
        # Return minimal features if URL parsing fails
        return UrlFeatures(urlLength=len(url))
    
    # Extract domain and related components
    domain = parsed.netloc.lower()
    
    # Handle IPv6 addresses (bracketed) - remove port carefully
    if domain.startswith("["):
        # IPv6 format: [::1] or [::1]:8080
        closingBracket = domain.find("]")
        if closingBracket != -1:
            domainWithoutPort = domain[:closingBracket + 1]
        else:
            domainWithoutPort = domain
    else:
        # IPv4 or hostname - split by last colon for port
        domainWithoutPort = domain.rsplit(":", 1)[0]
    
    # Check for IP address in domain
    hasIpAddress = _isIpAddress(domainWithoutPort)
    
    # Calculate subdomain count
    subdomainCount = _countSubdomains(domainWithoutPort)
    
    # Extract TLD
    tld = _extractTld(domainWithoutPort)
    
    # Calculate path depth
    path = parsed.path or ""
    pathDepth = _calculatePathDepth(path)
    
    # Count query parameters
    queryParamCount = len(parse_qs(parsed.query)) if parsed.query else 0
    
    # Calculate digit ratio in domain
    digitRatio = _calculateDigitRatio(domainWithoutPort)
    
    # Count special characters
    specialCharCount = _countSpecialChars(normalizedUrl)
    
    # Check for suspicious features
    hasSuspiciousTld = tld in SUSPICIOUS_TLDS
    hasSuspiciousKeywords = _hasSuspiciousKeywords(normalizedUrl)
    hasEncodedChars = bool(ENCODED_CHAR_PATTERN.search(normalizedUrl))
    hasPortNumber = _hasExplicitPort(domain)
    
    return UrlFeatures(
        urlLength=len(normalizedUrl),
        domainLength=len(domainWithoutPort),
        subdomainCount=subdomainCount,
        pathDepth=pathDepth,
        hasIpAddress=hasIpAddress,
        hasAtSymbol="@" in normalizedUrl,
        hasDoubleSlash="//" in path,
        hasDashInDomain="-" in domainWithoutPort,
        hasUnderscoreInDomain="_" in domainWithoutPort,
        isHttps=parsed.scheme.lower() == "https",
        hasPortNumber=hasPortNumber,
        hasSuspiciousTld=hasSuspiciousTld,
        hasEncodedChars=hasEncodedChars,
        hasSuspiciousKeywords=hasSuspiciousKeywords,
        digitRatio=digitRatio,
        specialCharCount=specialCharCount,
        queryParamCount=queryParamCount,
    )


def _isIpAddress(domain: str) -> bool:
    """Check if domain is an IP address (IPv4 or IPv6)."""
    # Remove brackets for IPv6
    cleanDomain = domain.strip("[]")
    return bool(
        IP_ADDRESS_PATTERN.match(cleanDomain)
        or IPV6_PATTERN.match(domain)
    )


def _countSubdomains(domain: str) -> int:
    """
    Count the number of subdomains in a domain.
    
    Example:
        'www.mail.example.com' -> 2 (www and mail)
        'example.com' -> 0
    """
    if _isIpAddress(domain):
        return 0
    
    parts = domain.split(".")
    
    # Handle special cases
    if len(parts) <= 2:
        return 0
    
    # Check for two-part TLDs (e.g., .co.uk, .com.au)
    twoPartTlds = {"co.uk", "com.au", "org.uk", "net.au", "ac.uk", "gov.uk"}
    if len(parts) >= 3:
        possibleTwoPartTld = f"{parts[-2]}.{parts[-1]}"
        if possibleTwoPartTld in twoPartTlds:
            return max(0, len(parts) - 3)
    
    return len(parts) - 2


def _extractTld(domain: str) -> str:
    """Extract top-level domain from domain name."""
    if _isIpAddress(domain):
        return ""
    
    parts = domain.split(".")
    if len(parts) >= 1:
        return parts[-1].lower()
    return ""


def _calculatePathDepth(path: str) -> int:
    """Calculate URL path depth (number of path segments)."""
    if not path or path == "/":
        return 0
    
    # Remove leading/trailing slashes and split
    cleanPath = path.strip("/")
    if not cleanPath:
        return 0
    
    segments = cleanPath.split("/")
    return len(segments)


def _calculateDigitRatio(domain: str) -> float:
    """Calculate ratio of digits to total characters in domain."""
    if not domain:
        return 0.0
    
    digitCount = sum(1 for c in domain if c.isdigit())
    return digitCount / len(domain)


def _countSpecialChars(url: str) -> int:
    """Count special characters in URL (excluding allowed ones)."""
    # Characters that are normal in URLs
    allowedChars = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=")
    
    count = 0
    for char in url.lower():
        if char not in allowedChars:
            count += 1
    return count


def _hasSuspiciousKeywords(url: str) -> bool:
    """Check if URL contains suspicious phishing-related keywords."""
    urlLower = url.lower()
    
    # Decode URL-encoded characters for better matching
    try:
        decodedUrl = unquote(urlLower)
    except Exception:
        decodedUrl = urlLower
    
    return any(keyword in decodedUrl for keyword in SUSPICIOUS_KEYWORDS)


def _hasExplicitPort(domain: str) -> bool:
    """Check if domain includes explicit port number."""
    if ":" not in domain:
        return False
    
    # IPv6 addresses contain colons but may not have ports
    if domain.startswith("["):
        # IPv6 with port: [::1]:8080
        return "]:" in domain
    
    # Standard port check
    match = PORT_PATTERN.search(domain)
    if match:
        port = int(match.group(1))
        # Standard ports (80, 443) are not suspicious
        return port not in (80, 443)
    
    return False


# =============================================================================
# OSINT Feature Extraction
# =============================================================================

def extractOsintFeatures(
    whoisResult: Optional[object] = None,
    dnsResult: Optional[object] = None,
    reputationResult: Optional[object] = None,
) -> OsintFeatures:
    """
    Extract features from OSINT data.
    
    Transforms raw OSINT results into normalized features
    suitable for scoring.
    
    Args:
        whoisResult: WHOIS lookup result (optional)
        dnsResult: DNS lookup result (optional)
        reputationResult: Reputation check result (optional)
        
    Returns:
        OsintFeatures: Extracted OSINT features
        
    Example:
        >>> features = extractOsintFeatures(whoisResult=whois, dnsResult=dns)
        >>> features.isNewlyRegistered
        False
    """
    features = OsintFeatures()
    
    # Extract WHOIS features
    if whoisResult is not None:
        features = _extractWhoisFeatures(whoisResult, features)
    
    # Extract DNS features
    if dnsResult is not None:
        features = _extractDnsFeatures(dnsResult, features)
    
    # Extract reputation features
    if reputationResult is not None:
        features = _extractReputationFeatures(reputationResult, features)
    
    return features


def _extractWhoisFeatures(
    whoisResult: object,
    features: OsintFeatures,
) -> OsintFeatures:
    """Extract features from WHOIS result."""
    # Check if WHOIS was successful
    isSuccess = getattr(whoisResult, "isSuccess", False)
    if not isSuccess:
        return features
    
    # Domain age
    domainAgeDays = getattr(whoisResult, "domainAgeDays", None)
    
    # Recently registered check
    recentlyRegistered = getattr(whoisResult, "recentlyRegistered", False)
    
    # Privacy protection
    isPrivacyProtected = getattr(whoisResult, "isPrivacyProtected", False)
    
    # Create updated features
    return OsintFeatures(
        domainAgeDays=domainAgeDays,
        isNewlyRegistered=recentlyRegistered,
        isYoungDomain=domainAgeDays is not None and domainAgeDays < 365,
        hasPrivacyProtection=isPrivacyProtected,
        hasValidMx=features.hasValidMx,
        usesCdn=features.usesCdn,
        dnsRecordCount=features.dnsRecordCount,
        hasValidDns=features.hasValidDns,
        reputationScore=features.reputationScore,
        maliciousSourceCount=features.maliciousSourceCount,
        isKnownMalicious=features.isKnownMalicious,
        hasValidWhois=True,
    )


def _extractDnsFeatures(
    dnsResult: object,
    features: OsintFeatures,
) -> OsintFeatures:
    """Extract features from DNS result."""
    # Check if DNS was successful
    isSuccess = getattr(dnsResult, "isSuccess", False)
    if not isSuccess:
        return features
    
    # MX validation
    hasValidMx = getattr(dnsResult, "hasValidMx", False)
    
    # CDN detection
    usesCdn = getattr(dnsResult, "usesCdn", False)
    
    # Count DNS records
    aRecords = getattr(dnsResult, "aRecords", [])
    aaaaRecords = getattr(dnsResult, "aaaaRecords", [])
    mxRecords = getattr(dnsResult, "mxRecords", [])
    nsRecords = getattr(dnsResult, "nsRecords", [])
    txtRecords = getattr(dnsResult, "txtRecords", [])
    
    dnsRecordCount = (
        len(aRecords)
        + len(aaaaRecords)
        + len(mxRecords)
        + len(nsRecords)
        + len(txtRecords)
    )
    
    return OsintFeatures(
        domainAgeDays=features.domainAgeDays,
        isNewlyRegistered=features.isNewlyRegistered,
        isYoungDomain=features.isYoungDomain,
        hasPrivacyProtection=features.hasPrivacyProtection,
        hasValidMx=hasValidMx,
        usesCdn=usesCdn,
        dnsRecordCount=dnsRecordCount,
        hasValidDns=True,
        reputationScore=features.reputationScore,
        maliciousSourceCount=features.maliciousSourceCount,
        isKnownMalicious=features.isKnownMalicious,
        hasValidWhois=features.hasValidWhois,
    )


def _extractReputationFeatures(
    reputationResult: object,
    features: OsintFeatures,
) -> OsintFeatures:
    """Extract features from reputation result."""
    # Check if reputation lookup was successful
    isSuccess = getattr(reputationResult, "isSuccess", False)
    if not isSuccess:
        return features
    
    # Aggregate score
    aggregateScore = getattr(reputationResult, "aggregateScore", 0.0)
    
    # Malicious flags
    knownMalicious = getattr(reputationResult, "knownMalicious", False)
    maliciousCount = getattr(reputationResult, "maliciousCount", 0)
    
    return OsintFeatures(
        domainAgeDays=features.domainAgeDays,
        isNewlyRegistered=features.isNewlyRegistered,
        isYoungDomain=features.isYoungDomain,
        hasPrivacyProtection=features.hasPrivacyProtection,
        hasValidMx=features.hasValidMx,
        usesCdn=features.usesCdn,
        dnsRecordCount=features.dnsRecordCount,
        hasValidDns=features.hasValidDns,
        reputationScore=aggregateScore,
        maliciousSourceCount=maliciousCount,
        isKnownMalicious=knownMalicious,
        hasValidWhois=features.hasValidWhois,
    )


# =============================================================================
# Combined Feature Extraction
# =============================================================================

class FeatureExtractor:
    """
    Main feature extraction orchestrator.
    
    Combines URL and OSINT feature extraction into a single
    unified interface for the scoring module.
    
    Example:
        >>> extractor = FeatureExtractor()
        >>> features = extractor.extract("https://example.com", osintData)
        >>> print(features.urlFeatures.isHttps)
        True
    """
    
    def __init__(self) -> None:
        """Initialize the feature extractor."""
        pass
    
    def extract(
        self,
        url: str,
        osintData: Optional[object] = None,
    ) -> FeatureSet:
        """
        Extract all features from URL and OSINT data.
        
        Args:
            url: URL to analyze
            osintData: Optional OSINT data (OsintData model)
            
        Returns:
            FeatureSet: Complete feature set
        """
        startTime = time.perf_counter()
        
        # Extract URL features
        urlFeatures = extractUrlFeatures(url)
        
        # Extract domain from URL
        domain = self._extractDomain(url)
        
        # Extract OSINT features if available
        if osintData is not None:
            whoisResult = getattr(osintData, "whois", None)
            dnsResult = getattr(osintData, "dns", None)
            reputationResult = getattr(osintData, "reputation", None)
            
            osintFeatures = extractOsintFeatures(
                whoisResult=whoisResult,
                dnsResult=dnsResult,
                reputationResult=reputationResult,
            )
        else:
            osintFeatures = OsintFeatures()
        
        durationMs = (time.perf_counter() - startTime) * 1000
        
        return FeatureSet(
            url=url,
            domain=domain,
            urlFeatures=urlFeatures,
            osintFeatures=osintFeatures,
            extractionDurationMs=durationMs,
        )
    
    def extractUrlFeaturesOnly(self, url: str) -> UrlFeatures:
        """
        Extract only URL structural features.
        
        Useful when OSINT data is not available or not needed.
        
        Args:
            url: URL to analyze
            
        Returns:
            UrlFeatures: URL structural features
        """
        return extractUrlFeatures(url)
    
    def extractOsintFeaturesOnly(
        self,
        whoisResult: Optional[object] = None,
        dnsResult: Optional[object] = None,
        reputationResult: Optional[object] = None,
    ) -> OsintFeatures:
        """
        Extract only OSINT-derived features.
        
        Useful when URL analysis is done separately.
        
        Args:
            whoisResult: WHOIS lookup result
            dnsResult: DNS lookup result
            reputationResult: Reputation check result
            
        Returns:
            OsintFeatures: OSINT-derived features
        """
        return extractOsintFeatures(
            whoisResult=whoisResult,
            dnsResult=dnsResult,
            reputationResult=reputationResult,
        )
    
    def _extractDomain(self, url: str) -> str:
        """Extract domain from URL."""
        if not url:
            return ""
        
        normalizedUrl = url.strip()
        if not normalizedUrl.startswith(("http://", "https://")):
            normalizedUrl = "http://" + normalizedUrl
        
        try:
            parsed = urlparse(normalizedUrl)
            domain = parsed.netloc.lower()
            # Remove port
            return domain.split(":")[0]
        except Exception:
            return ""


# =============================================================================
# Convenience Functions
# =============================================================================

def extractFeatures(
    url: str,
    osintData: Optional[object] = None,
) -> FeatureSet:
    """
    Convenience function for feature extraction.
    
    Creates a FeatureExtractor and extracts features in one call.
    
    Args:
        url: URL to analyze
        osintData: Optional OSINT data
        
    Returns:
        FeatureSet: Complete feature set
        
    Example:
        >>> features = extractFeatures("https://example.com")
        >>> print(features.urlFeatures.isHttps)
        True
    """
    extractor = FeatureExtractor()
    return extractor.extract(url, osintData)
