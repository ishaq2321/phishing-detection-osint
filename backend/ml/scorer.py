"""
Phishing Risk Scorer Module
============================

Combines features from URL analysis and OSINT data to produce
a final phishing risk score with full explainability.

The scorer uses a weighted combination approach based on research
into phishing detection, with configurable weights for each component.

Scoring Model:
- URL Structural Score: 25% (from urlAnalyzer)
- OSINT Score: 35% (domain age, reputation, DNS)
- Feature-based Score: 40% (extracted features)

Design Principles:
- Explainable scoring with detailed component breakdown
- Configurable weights for different use cases
- Graceful degradation when data is incomplete
- Clear risk level classification

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from dataclasses import dataclass
from typing import Optional

from .featureExtractor import FeatureExtractor
from .schemas import (
    FeatureCategory,
    FeatureSet,
    OsintFeatures,
    RiskLevel,
    RiskScore,
    ScoreComponent,
    UrlAnalysisResult,
    UrlFeatures,
)
from .urlAnalyzer import UrlAnalyzer


# =============================================================================
# Scoring Configuration
# =============================================================================

@dataclass(frozen=True)
class ScoringWeights:
    """
    Weights for combining score components.
    
    Weights should sum to 1.0 for proper normalization.
    """
    
    urlStructure: float = 0.25
    osintDerived: float = 0.35
    featureBased: float = 0.40
    
    def __post_init__(self) -> None:
        """Validate weights sum to 1.0."""
        total = self.urlStructure + self.osintDerived + self.featureBased
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"Weights must sum to 1.0, got {total}")


# Risk level thresholds
RISK_THRESHOLDS = {
    RiskLevel.SAFE: 0.2,
    RiskLevel.LOW: 0.4,
    RiskLevel.MEDIUM: 0.6,
    RiskLevel.HIGH: 0.8,
    # CRITICAL is anything above HIGH
}


# =============================================================================
# Score Component Calculators
# =============================================================================

def calculateUrlStructureScore(
    urlFeatures: UrlFeatures,
    urlAnalysis: Optional[UrlAnalysisResult] = None,
) -> tuple[float, list[str]]:
    """
    Calculate score based on URL structural features.
    
    Args:
        urlFeatures: Extracted URL features
        urlAnalysis: Optional URL analysis result
        
    Returns:
        Tuple of (score, list of contributing factors)
    """
    score = 0.0
    factors: list[str] = []
    
    # URL length penalty (phishing URLs tend to be longer)
    if urlFeatures.urlLength > 75:
        penalty = min((urlFeatures.urlLength - 75) / 100, 0.3)
        score += penalty
        factors.append(f"Long URL ({urlFeatures.urlLength} chars)")
    
    # IP address instead of domain (very suspicious)
    if urlFeatures.hasIpAddress:
        score += 0.4
        factors.append("Uses IP address instead of domain name")
    
    # @ symbol (redirect attack)
    if urlFeatures.hasAtSymbol:
        score += 0.35
        factors.append("Contains @ symbol (potential redirect attack)")
    
    # Double slash in path
    if urlFeatures.hasDoubleSlash:
        score += 0.25
        factors.append("Contains double slash in path")
    
    # Underscore in domain (unusual)
    if urlFeatures.hasUnderscoreInDomain:
        score += 0.2
        factors.append("Domain contains underscore")
    
    # Suspicious TLD
    if urlFeatures.hasSuspiciousTld:
        score += 0.25
        factors.append("Uses suspicious top-level domain")
    
    # No HTTPS
    if not urlFeatures.isHttps:
        score += 0.15
        factors.append("Does not use HTTPS")
    
    # Suspicious keywords
    if urlFeatures.hasSuspiciousKeywords:
        score += 0.2
        factors.append("Contains suspicious keywords")
    
    # Explicit port number
    if urlFeatures.hasPortNumber:
        score += 0.2
        factors.append("Uses explicit port number")
    
    # URL encoding
    if urlFeatures.hasEncodedChars:
        score += 0.15
        factors.append("Contains URL-encoded characters")
    
    # High digit ratio in domain
    if urlFeatures.digitRatio > 0.3:
        score += 0.15
        factors.append("High ratio of digits in domain")
    
    # Deep path
    if urlFeatures.pathDepth > 4:
        score += 0.1
        factors.append(f"Deep URL path ({urlFeatures.pathDepth} levels)")
    
    # Multiple subdomains
    if urlFeatures.subdomainCount > 2:
        score += 0.15
        factors.append(f"Multiple subdomains ({urlFeatures.subdomainCount})")
    
    # Many query parameters
    if urlFeatures.queryParamCount > 4:
        score += 0.1
        factors.append(f"Many query parameters ({urlFeatures.queryParamCount})")
    
    # Include URL analysis score if available
    if urlAnalysis is not None and urlAnalysis.suspiciousPatterns:
        # Add weight based on pattern severity
        patternScore = urlAnalysis.structuralScore * 0.3
        score += patternScore
        factors.append(
            f"{len(urlAnalysis.suspiciousPatterns)} suspicious pattern(s) detected"
        )
    
    return min(score, 1.0), factors


def calculateOsintScore(osintFeatures: OsintFeatures) -> tuple[float, list[str]]:
    """
    Calculate score based on OSINT-derived features.
    
    Args:
        osintFeatures: OSINT-derived features
        
    Returns:
        Tuple of (score, list of contributing factors)
    """
    score = 0.0
    factors: list[str] = []
    
    # Known malicious (high score, but continue collecting factors)
    if osintFeatures.isKnownMalicious:
        score += 0.8
        factors.append("URL is in known malicious lists")
    
    # Malicious source count
    if osintFeatures.maliciousSourceCount > 0:
        penalty = min(osintFeatures.maliciousSourceCount * 0.25, 0.5)
        score += penalty
        factors.append(
            f"{osintFeatures.maliciousSourceCount} reputation source(s) flagged malicious"
        )
    
    # Reputation score (already 0-1 where 1 is suspicious)
    if osintFeatures.reputationScore > 0.3:
        score += osintFeatures.reputationScore * 0.4
        factors.append(f"Poor reputation score ({osintFeatures.reputationScore:.2f})")
    
    # Newly registered domain (high risk)
    if osintFeatures.isNewlyRegistered:
        score += 0.35
        factors.append("Domain registered within last 30 days")
    elif osintFeatures.isYoungDomain:
        score += 0.2
        factors.append("Domain less than 1 year old")
    
    # Very young domain (< 7 days)
    if (
        osintFeatures.domainAgeDays is not None
        and osintFeatures.domainAgeDays < 7
    ):
        score += 0.15  # Additional penalty
        factors.append("Domain registered within last 7 days")
    
    # Privacy protection (can be legitimate but often used by phishers)
    if osintFeatures.hasPrivacyProtection:
        score += 0.1
        factors.append("WHOIS privacy protection enabled")
    
    # No valid MX records
    if osintFeatures.hasValidDns and not osintFeatures.hasValidMx:
        score += 0.15
        factors.append("No valid mail server configuration")
    
    # Very few DNS records (sparse configuration)
    if osintFeatures.hasValidDns and osintFeatures.dnsRecordCount < 3:
        score += 0.1
        factors.append("Minimal DNS configuration")
    
    # Data quality penalties (missing data is slightly suspicious)
    if not osintFeatures.hasValidWhois:
        score += 0.1
        factors.append("WHOIS data unavailable")
    
    if not osintFeatures.hasValidDns:
        score += 0.1
        factors.append("DNS resolution failed")
    
    return min(score, 1.0), factors


def calculateFeatureScore(features: FeatureSet) -> tuple[float, list[str]]:
    """
    Calculate score based on combined feature analysis.
    
    This provides a holistic view combining URL and OSINT features
    for patterns that emerge from the combination.
    
    Args:
        features: Complete feature set
        
    Returns:
        Tuple of (score, list of contributing factors)
    """
    score = 0.0
    factors: list[str] = []
    
    urlFeatures = features.urlFeatures
    osintFeatures = features.osintFeatures
    
    # Combined risk indicators
    totalIndicators = features.totalRiskIndicators
    if totalIndicators >= 5:
        score += 0.4
        factors.append(f"High number of risk indicators ({totalIndicators})")
    elif totalIndicators >= 3:
        score += 0.2
        factors.append(f"Multiple risk indicators ({totalIndicators})")
    
    # Suspicious combination: new domain + suspicious keywords
    if osintFeatures.isNewlyRegistered and urlFeatures.hasSuspiciousKeywords:
        score += 0.3
        factors.append("New domain with phishing keywords")
    
    # Suspicious combination: IP address + no HTTPS
    if urlFeatures.hasIpAddress and not urlFeatures.isHttps:
        score += 0.25
        factors.append("IP address without HTTPS")
    
    # Suspicious combination: long URL + suspicious TLD + keywords
    if (
        urlFeatures.urlLength > 100
        and urlFeatures.hasSuspiciousTld
        and urlFeatures.hasSuspiciousKeywords
    ):
        score += 0.25
        factors.append("Long URL with suspicious TLD and keywords")
    
    # Complex structure on new domain
    if osintFeatures.isYoungDomain and urlFeatures.isHighlyStructured:
        score += 0.2
        factors.append("Complex URL structure on young domain")
    
    # Poor data completeness with other suspicious signs
    if (
        osintFeatures.dataCompleteness < 0.7
        and urlFeatures.suspiciousFeatureCount >= 2
    ):
        score += 0.15
        factors.append("Incomplete OSINT data with suspicious URL features")
    
    # CDN hiding + suspicious features
    # (CDN itself is not suspicious, but combined with other factors)
    if osintFeatures.usesCdn and urlFeatures.hasSuspiciousKeywords:
        score += 0.1
        factors.append("CDN used with suspicious keywords")
    
    # High digit ratio + suspicious TLD
    if urlFeatures.digitRatio > 0.2 and urlFeatures.hasSuspiciousTld:
        score += 0.15
        factors.append("High digit ratio with suspicious TLD")
    
    return min(score, 1.0), factors


# =============================================================================
# Risk Level Determination
# =============================================================================

def determineRiskLevel(score: float) -> RiskLevel:
    """
    Determine categorical risk level from numerical score.
    
    Args:
        score: Risk score (0-1)
        
    Returns:
        RiskLevel: Categorical risk level
    """
    if score < RISK_THRESHOLDS[RiskLevel.SAFE]:
        return RiskLevel.SAFE
    elif score < RISK_THRESHOLDS[RiskLevel.LOW]:
        return RiskLevel.LOW
    elif score < RISK_THRESHOLDS[RiskLevel.MEDIUM]:
        return RiskLevel.MEDIUM
    elif score < RISK_THRESHOLDS[RiskLevel.HIGH]:
        return RiskLevel.HIGH
    else:
        return RiskLevel.CRITICAL


def calculateConfidence(
    features: FeatureSet,
    urlAnalysis: Optional[UrlAnalysisResult],
) -> float:
    """
    Calculate confidence level for the score.
    
    Confidence is based on data completeness and quality.
    
    Args:
        features: Complete feature set
        urlAnalysis: URL analysis result
        
    Returns:
        Confidence score (0-1)
    """
    confidence = 0.0
    
    # URL analysis always contributes (basic feature always available)
    confidence += 0.3
    
    # OSINT data quality
    osintCompleteness = features.osintFeatures.dataCompleteness
    confidence += osintCompleteness * 0.5
    
    # URL analysis quality
    if urlAnalysis is not None:
        # More patterns = more data = higher confidence
        if urlAnalysis.patternCount > 0:
            confidence += 0.1
        confidence += 0.1  # URL analysis was successful
    
    return min(confidence, 1.0)


# =============================================================================
# Main Scorer Class
# =============================================================================

class PhishingScorer:
    """
    Main phishing risk scorer.
    
    Combines URL structural analysis, OSINT features, and pattern
    detection to produce a comprehensive risk assessment.
    
    Example:
        >>> scorer = PhishingScorer()
        >>> result = scorer.score("https://example.com", osintData)
        >>> print(result.finalScore)
        0.15
        >>> print(result.riskLevel)
        RiskLevel.SAFE
    """
    
    def __init__(
        self,
        weights: Optional[ScoringWeights] = None,
        featureExtractor: Optional[FeatureExtractor] = None,
        urlAnalyzer: Optional[UrlAnalyzer] = None,
    ) -> None:
        """
        Initialize the phishing scorer.
        
        Args:
            weights: Scoring weights (uses defaults if None)
            featureExtractor: Feature extractor instance
            urlAnalyzer: URL analyzer instance
        """
        self._weights = weights if weights is not None else ScoringWeights()
        self._featureExtractor = (
            featureExtractor
            if featureExtractor is not None
            else FeatureExtractor()
        )
        self._urlAnalyzer = (
            urlAnalyzer if urlAnalyzer is not None else UrlAnalyzer()
        )
    
    def score(
        self,
        url: str,
        osintData: Optional[object] = None,
    ) -> RiskScore:
        """
        Calculate phishing risk score for a URL.
        
        Args:
            url: URL to score
            osintData: Optional OSINT data (OsintData model)
            
        Returns:
            RiskScore: Complete risk assessment
        """
        if not url:
            return RiskScore(
                url="",
                domain="",
                finalScore=0.0,
                riskLevel=RiskLevel.SAFE,
                confidence=0.0,
                reasons=["Empty URL provided"],
            )
        
        # Extract features and analyze URL
        features = self._featureExtractor.extract(url, osintData)
        urlAnalysis = self._urlAnalyzer.analyze(url)
        
        return self._calculateScore(features, urlAnalysis)
    
    def scoreWithFeatures(
        self,
        features: FeatureSet,
        urlAnalysis: Optional[UrlAnalysisResult] = None,
    ) -> RiskScore:
        """
        Calculate score from pre-extracted features.
        
        Useful when features have already been extracted elsewhere.
        
        Args:
            features: Pre-extracted feature set
            urlAnalysis: Optional pre-computed URL analysis
            
        Returns:
            RiskScore: Complete risk assessment
        """
        if urlAnalysis is None:
            urlAnalysis = self._urlAnalyzer.analyze(features.url)
        
        return self._calculateScore(features, urlAnalysis)
    
    def _calculateScore(
        self,
        features: FeatureSet,
        urlAnalysis: UrlAnalysisResult,
    ) -> RiskScore:
        """
        Core scoring logic shared by score() and scoreWithFeatures().
        
        Combines URL structure, OSINT, and feature-based scores
        into a final weighted risk assessment.
        
        Args:
            features: Extracted feature set
            urlAnalysis: URL structural analysis result
            
        Returns:
            RiskScore: Complete risk assessment with component breakdown
        """
        # Calculate component scores
        urlScore, urlFactors = calculateUrlStructureScore(
            features.urlFeatures,
            urlAnalysis,
        )
        
        osintScore, osintFactors = calculateOsintScore(features.osintFeatures)
        
        featureScore, featureFactors = calculateFeatureScore(features)
        
        # Create score components
        components = [
            ScoreComponent(
                name="URL Structure",
                rawScore=urlScore,
                weight=self._weights.urlStructure,
                category=FeatureCategory.URL_STRUCTURE,
                factors=urlFactors,
            ),
            ScoreComponent(
                name="OSINT Analysis",
                rawScore=osintScore,
                weight=self._weights.osintDerived,
                category=FeatureCategory.OSINT_DERIVED,
                factors=osintFactors,
            ),
            ScoreComponent(
                name="Feature Analysis",
                rawScore=featureScore,
                weight=self._weights.featureBased,
                category=FeatureCategory.DOMAIN_ANALYSIS,
                factors=featureFactors,
            ),
        ]
        
        # Calculate weighted final score
        finalScore = sum(comp.weightedScore for comp in components)
        finalScore = min(max(finalScore, 0.0), 1.0)
        
        # Determine risk level
        riskLevel = determineRiskLevel(finalScore)
        
        # Calculate confidence
        confidence = calculateConfidence(features, urlAnalysis)
        
        # Compile all reasons (sorted by severity)
        allFactors = urlFactors + osintFactors + featureFactors
        reasons = self._prioritizeReasons(allFactors, riskLevel)
        
        return RiskScore(
            url=features.url,
            domain=features.domain,
            finalScore=finalScore,
            riskLevel=riskLevel,
            confidence=confidence,
            components=components,
            reasons=reasons,
        )
    
    def _prioritizeReasons(
        self,
        factors: list[str],
        riskLevel: RiskLevel,
    ) -> list[str]:
        """
        Prioritize and deduplicate reasons for the score.
        
        High-priority keywords are moved to the top.
        """
        if not factors:
            if riskLevel == RiskLevel.SAFE:
                return ["No significant risk indicators detected"]
            return ["Unable to determine specific risk factors"]
        
        # Define priority keywords
        highPriority = {
            "malicious", "phishing", "attack", "ip address",
            "newly registered", "7 days",
        }
        
        mediumPriority = {
            "suspicious", "keyword", "pattern", "young domain",
            "no https", "no valid mail",
        }
        
        # Deduplicate
        uniqueFactors = list(dict.fromkeys(factors))
        
        # Sort by priority
        def priorityKey(factor: str) -> int:
            factorLower = factor.lower()
            if any(kw in factorLower for kw in highPriority):
                return 0
            if any(kw in factorLower for kw in mediumPriority):
                return 1
            return 2
        
        sortedFactors = sorted(uniqueFactors, key=priorityKey)
        
        # Limit to top 10
        return sortedFactors[:10]


# =============================================================================
# Convenience Functions
# =============================================================================

def scoreUrl(
    url: str,
    osintData: Optional[object] = None,
) -> RiskScore:
    """
    Convenience function for URL scoring.
    
    Creates a PhishingScorer and scores the URL in one call.
    
    Args:
        url: URL to score
        osintData: Optional OSINT data
        
    Returns:
        RiskScore: Complete risk assessment
        
    Example:
        >>> result = scoreUrl("https://example.com")
        >>> print(result.riskLevel)
        RiskLevel.SAFE
    """
    scorer = PhishingScorer()
    return scorer.score(url, osintData)


def quickScore(url: str) -> float:
    """
    Get a quick numerical score without full analysis.
    
    Useful for batch processing where only the score is needed.
    
    Args:
        url: URL to score
        
    Returns:
        Risk score (0-1)
        
    Example:
        >>> quickScore("https://google.com")
        0.05
    """
    result = scoreUrl(url)
    return result.finalScore


def isPhishing(
    url: str,
    threshold: float = 0.6,
    osintData: Optional[object] = None,
) -> bool:
    """
    Quick check if a URL is likely phishing.
    
    Args:
        url: URL to check
        threshold: Score threshold for phishing classification
        osintData: Optional OSINT data
        
    Returns:
        True if URL is classified as phishing
        
    Example:
        >>> isPhishing("https://paypal-verify.example.tk")
        True
    """
    result = scoreUrl(url, osintData)
    return result.finalScore >= threshold


def getRiskLevel(
    url: str,
    osintData: Optional[object] = None,
) -> RiskLevel:
    """
    Get the risk level for a URL.
    
    Args:
        url: URL to check
        osintData: Optional OSINT data
        
    Returns:
        RiskLevel enum value
        
    Example:
        >>> getRiskLevel("https://google.com")
        RiskLevel.SAFE
    """
    result = scoreUrl(url, osintData)
    return result.riskLevel
