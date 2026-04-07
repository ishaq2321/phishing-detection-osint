"""
Analysis Orchestrator Module
============================

Coordinates OSINT, ML, and Analyzer modules for comprehensive analysis.

This orchestrator acts as the central coordinator that combines results from
multiple analysis modules to provide a unified phishing detection verdict.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import asyncio
import re
import time
from typing import Optional
from urllib.parse import urlparse

from backend.analyzer import AnalysisResult, ContentType, NlpAnalyzer
from backend.ml import FeatureSet, PhishingPredictor, RiskScore, extractFeatures, scoreUrl
from backend.osint import OsintData, lookupDns, lookupReputation, lookupWhois

from .schemas import (
    AnalysisResponse,
    FeatureSummary,
    OsintSummary,
    VerdictResult,
)


# =============================================================================
# Scoring Constants
# =============================================================================

ML_PRIMARY_WEIGHT = 0.85
TEXT_SUPPLEMENT_WEIGHT = 0.15
TEXT_PRIMARY_WEIGHT = 0.55
URL_SECONDARY_WEIGHT = 0.25
OSINT_SECONDARY_WEIGHT = 0.20
PHISHING_THRESHOLD = 0.5
THREAT_SAFE_UPPER = 0.3
THREAT_SUSPICIOUS_UPPER = 0.5
THREAT_DANGEROUS_UPPER = 0.7
RECENT_DOMAIN_AGE_DAYS = 30


# =============================================================================
# Orchestrator Class
# =============================================================================

class AnalysisOrchestrator:
    """
    Coordinates all analysis modules for comprehensive phishing detection.
    
    This class orchestrates the analysis workflow by:
    1. Extracting the domain from content
    2. Collecting OSINT data (WHOIS, DNS, Reputation)
    3. Extracting ML features
    4. Running NLP/LLM analysis on text content
    5. Combining all results into a final verdict
    
    Example:
        >>> orchestrator = AnalysisOrchestrator()
        >>> response = await orchestrator.analyze(
        ...     content="https://suspicious-site.com",
        ...     contentType="url"
        ... )
        >>> print(response.verdict.isPhishing)
        True
    """
    
    def __init__(self) -> None:
        """Initialize the orchestrator with analyzer."""
        self.analyzer = NlpAnalyzer()
    
    async def analyze(
        self,
        content: str,
        contentType: str = "auto"
    ) -> AnalysisResponse:
        """
        Perform comprehensive phishing analysis.
        
        Args:
            content: Content to analyze (URL, email, or text)
            contentType: Type of content (auto, url, email, text)
            
        Returns:
            AnalysisResponse: Complete analysis results
            
        Example:
            >>> response = await orchestrator.analyze(
            ...     "https://example.com/verify",
            ...     "url"
            ... )
        """
        startTime = time.time()
        
        try:
            # Determine content type
            if contentType == "auto":
                contentType = self._detectContentType(content)
            
            # Extract domain for OSINT (if applicable)
            domain = self._extractDomain(content)
            
            # Collect OSINT data (if domain available)
            osintData: Optional[OsintData] = None
            if domain:
                osintData = await self._collectOsintData(domain, url=content)
            
            # Extract ML features
            featureSet: FeatureSet = extractFeatures(content, osintData)
            
            # Calculate URL-based score
            urlScore: Optional[RiskScore] = None
            if contentType == "url":
                urlScore = scoreUrl(content, osintData)
            
            # Run NLP/LLM analysis on content
            textAnalysis: AnalysisResult = await self.analyzer.analyze(
                content,
                ContentType[contentType.upper()]
            )
            
            # Combine all analyses into final verdict
            verdict = self._combineVerdict(
                textAnalysis,
                urlScore,
                osintData,
                featureSet
            )
            
            # Build response
            analysisTime = (time.time() - startTime) * 1000  # milliseconds
            
            return AnalysisResponse(
                success=True,
                verdict=verdict,
                osint=self._buildOsintSummary(osintData, domain) if osintData else None,
                features=self._buildFeatureSummary(featureSet, textAnalysis),
                analysisTime=analysisTime,
            )
            
        except Exception as e:
            # Handle errors gracefully
            analysisTime = (time.time() - startTime) * 1000
            return AnalysisResponse(
                success=False,
                verdict=VerdictResult(
                    isPhishing=False,
                    confidenceScore=0.0,
                    threatLevel="safe",
                    reasons=["Analysis error"],
                    recommendation="Unable to analyze content. Please try again."
                ),
                features=FeatureSummary(),
                analysisTime=analysisTime,
                error=str(e)
            )
    
    def _detectContentType(self, content: str) -> str:
        """Auto-detect content type from content."""
        contentLower = content.lower().strip()
        
        # Check if it's a URL (with protocol or www prefix)
        if contentLower.startswith(("http://", "https://", "www.")):
            return "url"
        
        # Check if it looks like a bare domain (e.g., "google.com", "example.co.uk")
        # Pattern: alphanumeric with optional hyphens, followed by a TLD
        bareDomainPattern = r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}(/.*)?$'
        if re.match(bareDomainPattern, contentLower):
            return "url"
        
        # Check if it has email headers
        if any(header in contentLower for header in ["from:", "subject:", "to:"]):
            return "email"
        
        # Default to text
        return "text"
    
    def _extractDomain(self, content: str) -> Optional[str]:
        """Extract domain from URL or email content."""
        try:
            contentStripped = content.strip()
            
            # Try parsing as URL (with protocol or www prefix)
            if contentStripped.startswith(("http://", "https://", "www.")):
                parsed = urlparse(contentStripped if "://" in contentStripped else f"http://{contentStripped}")
                return parsed.netloc.lower().replace("www.", "")
            
            # Check if it looks like a bare domain (e.g., "google.com")
            bareDomainPattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(/.*)?$'
            if re.match(bareDomainPattern, contentStripped):
                # Extract just the domain part (before any path)
                domain = contentStripped.split("/")[0].lower()
                return domain
            
            # Try extracting from email content
            # Look for URLs in content
            urlPattern = r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'
            urls = re.findall(urlPattern, content)
            if urls:
                parsed = urlparse(urls[0])
                return parsed.netloc.lower().replace("www.", "")
            
            # Look for email addresses
            emailPattern = r'@([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)'
            emails = re.findall(emailPattern, content)
            if emails:
                return emails[0].lower()
            
            return None
            
        except Exception:
            return None
    
    async def _collectOsintData(self, domain: str, url: str = "") -> Optional[OsintData]:
        """Collect OSINT data for domain using parallel execution.
        
        Args:
            domain: Domain name to collect OSINT data for
            url: Original URL being analyzed
        """
        try:
            # Collect data from all OSINT sources in parallel with global timeout
            # This ensures we don't hang indefinitely on non-existent domains
            whoisResult, dnsResult, reputationResult = await asyncio.wait_for(
                asyncio.gather(
                    lookupWhois(domain),
                    lookupDns(domain),
                    lookupReputation(domain),
                    return_exceptions=True,  # Don't fail if one lookup fails
                ),
                timeout=15.0,  # Global timeout for all OSINT lookups
            )
            
            # Handle exceptions returned by gather (when return_exceptions=True)
            if isinstance(whoisResult, Exception):
                whoisResult = None
            if isinstance(dnsResult, Exception):
                dnsResult = None
            if isinstance(reputationResult, Exception):
                reputationResult = None
            
            # Build OsintData object
            return OsintData(
                url=url or f"https://{domain}",
                domain=domain,
                whois=whoisResult if whoisResult and not isinstance(whoisResult, BaseException) and whoisResult.status == "success" else None,
                dns=dnsResult if dnsResult and not isinstance(dnsResult, BaseException) and dnsResult.status == "success" else None,
                reputation=reputationResult if reputationResult and not isinstance(reputationResult, BaseException) and reputationResult.status == "success" else None,
            )
            
        except asyncio.TimeoutError:
            # OSINT collection timed out - return empty data
            return OsintData(
                url=url or f"https://{domain}",
                domain=domain,
                whois=None,
                dns=None,
                reputation=None,
            )
        except Exception:
            # Return None if OSINT collection fails
            return None
    
    def _combineVerdict(
        self,
        textAnalysis: AnalysisResult,
        urlScore: Optional[RiskScore],
        osintData: Optional[OsintData],
        featureSet: FeatureSet
    ) -> VerdictResult:
        """
        Combine all analysis results into final verdict.
        
        For URL content the XGBoost model (via urlScore.finalScore) is
        the primary signal (85 %) since it already encodes both URL
        structure and OSINT features.  Text analysis contributes a
        supplementary 15 %.
        
        For email / text content, NLP analysis is primary (55 %) while
        URL and OSINT scores are secondary (25 % + 20 %).
        """
        if urlScore is not None:
            # URL analysis: ML model is the primary signal.  OSINT
            # features are already embedded in the model's prediction,
            # so adding OSINT a second time would double-count.
            combinedScore = (
                urlScore.finalScore * ML_PRIMARY_WEIGHT
                + textAnalysis.confidenceScore * TEXT_SUPPLEMENT_WEIGHT
            )
        else:
            # Email / text analysis: NLP is primary, URL features
            # and OSINT are supplementary.
            featureScore = min(featureSet.totalRiskIndicators / 10, 1.0)
            osintScore = 0.0
            if osintData and osintData.reputation:
                osintScore = osintData.reputation.aggregateScore
            elif osintData and osintData.whois:
                if osintData.whois.domainAgeDays and osintData.whois.domainAgeDays < RECENT_DOMAIN_AGE_DAYS:
                    osintScore += 0.3
                if osintData.whois.isPrivacyProtected:
                    osintScore += 0.2
            combinedScore = (
                textAnalysis.confidenceScore * TEXT_PRIMARY_WEIGHT
                + featureScore * URL_SECONDARY_WEIGHT
                + osintScore * OSINT_SECONDARY_WEIGHT
            )
        
        combinedScore = min(max(combinedScore, 0.0), 1.0)
        
        # Determine if phishing
        isPhishing = combinedScore >= PHISHING_THRESHOLD
        
        # Determine threat level
        if combinedScore < THREAT_SAFE_UPPER:
            threatLevel = "safe"
        elif combinedScore < THREAT_SUSPICIOUS_UPPER:
            threatLevel = "suspicious"
        elif combinedScore < THREAT_DANGEROUS_UPPER:
            threatLevel = "dangerous"
        else:
            threatLevel = "critical"
        
        # Combine reasons from all sources
        reasons: list[str] = []
        reasons.extend(textAnalysis.reasons[:5])
        
        if urlScore:
            reasons.extend(urlScore.reasons[:3])
        
        if osintData:
            if osintData.whois and osintData.whois.domainAgeDays and osintData.whois.domainAgeDays < RECENT_DOMAIN_AGE_DAYS:
                reasons.append(f"Domain registered recently ({osintData.whois.domainAgeDays} days ago)")
            if osintData.whois and osintData.whois.isPrivacyProtected:
                reasons.append("WHOIS privacy protection enabled")
            if osintData.reputation and osintData.reputation.maliciousCount > 0:
                reasons.append(f"Found in {osintData.reputation.maliciousCount} blacklists")
        
        # ML model confidence
        predictor = PhishingPredictor()
        mlDetails = (
            f"ML model confidence: {urlScore.finalScore:.1%}"
            if urlScore and predictor.isLoaded
            else None
        )
        if mlDetails:
            reasons.insert(0, mlDetails)
        
        recommendation = self._generateRecommendation(threatLevel)
        
        return VerdictResult(
            isPhishing=isPhishing,
            confidenceScore=round(combinedScore, 3),
            threatLevel=threatLevel,
            reasons=reasons[:10],
            recommendation=recommendation
        )
    
    def _generateRecommendation(self, threatLevel: str) -> str:
        """Generate user recommendation based on threat level."""
        recommendations = {
            "safe": "This content appears safe. Proceed with normal caution.",
            "suspicious": "This content shows some suspicious characteristics. Verify the source before interacting.",
            "dangerous": "This content has multiple phishing indicators. Do not click links or provide information.",
            "critical": "This content is highly likely to be phishing. Do not interact. Report as phishing immediately."
        }
        return recommendations.get(threatLevel, "Unable to assess. Proceed with caution.")
    
    def _buildOsintSummary(
        self,
        osintData: OsintData,
        domain: Optional[str]
    ) -> OsintSummary:
        """Build OSINT summary from OSINT data."""
        return OsintSummary(
            domain=domain or osintData.domain,
            domainAgeDays=osintData.whois.domainAgeDays if osintData.whois else None,
            registrar=osintData.whois.registrar if osintData.whois else None,
            isPrivate=osintData.whois.isPrivacyProtected if osintData.whois else False,
            hasValidDns=bool(osintData.dns and osintData.dns.hasIpAddresses) if osintData.dns else False,
            reputationScore=osintData.reputation.aggregateScore if osintData.reputation else 0.5,
            inBlacklists=osintData.reputation.maliciousCount > 0 if osintData.reputation else False
        )
    
    def _buildFeatureSummary(
        self,
        featureSet: FeatureSet,
        textAnalysis: AnalysisResult
    ) -> FeatureSummary:
        """Build feature summary from feature set and text analysis."""
        return FeatureSummary(
            urlFeatures=featureSet.urlFeatures.suspiciousFeatureCount,
            textFeatures=len(textAnalysis.indicators),
            osintFeatures=featureSet.osintFeatures.osintRiskIndicators,
            totalRiskIndicators=featureSet.totalRiskIndicators + len(textAnalysis.indicators),
            detectedTactics=[tactic.value for tactic in textAnalysis.detectedTactics]
        )
