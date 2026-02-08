"""
Analysis Orchestrator Module
============================

Coordinates OSINT, ML, and Analyzer modules for comprehensive analysis.

This orchestrator acts as the central coordinator that combines results from
multiple analysis modules to provide a unified phishing detection verdict.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import time
from typing import Optional
from urllib.parse import urlparse

from backend.analyzer import AnalysisResult, ContentType, NlpAnalyzer
from backend.ml import FeatureSet, RiskScore, extractFeatures, scoreUrl
from backend.osint import OsintData, lookupDns, lookupReputation, lookupWhois

from .schemas import (
    AnalysisResponse,
    FeatureSummary,
    OsintSummary,
    VerdictResult,
)


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
                osintData = await self._collectOsintData(domain)
            
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
        content_lower = content.lower().strip()
        
        # Check if it's a URL
        if content_lower.startswith(("http://", "https://", "www.")):
            return "url"
        
        # Check if it has email headers
        if any(header in content_lower for header in ["from:", "subject:", "to:"]):
            return "email"
        
        # Default to text
        return "text"
    
    def _extractDomain(self, content: str) -> Optional[str]:
        """Extract domain from URL or email content."""
        try:
            # Try parsing as URL
            if content.startswith(("http://", "https://", "www.")):
                parsed = urlparse(content if "://" in content else f"http://{content}")
                return parsed.netloc.lower().replace("www.", "")
            
            # Try extracting from email content
            import re
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
    
    async def _collectOsintData(self, domain: str) -> Optional[OsintData]:
        """Collect OSINT data for domain."""
        try:
            # Collect data from all OSINT sources
            whoisResult = await lookupWhois(domain)
            dnsResult = await lookupDns(domain)
            reputationResult = await lookupReputation(domain)
            
            # Build OsintData object
            return OsintData(
                domain=domain,
                whois=whoisResult if whoisResult.status == "success" else None,
                dns=dnsResult if dnsResult.status == "success" else None,
                reputation=reputationResult if reputationResult.status == "success" else None,
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
        
        Scoring weights:
        - Text analysis: 40%
        - URL score: 25%
        - OSINT data: 35%
        """
        # Start with text analysis score
        combinedScore = textAnalysis.confidenceScore * 0.4
        
        # Add URL score if available
        if urlScore:
            combinedScore += urlScore.overallScore * 0.25
        else:
            # Use feature set indicators if no URL score
            featureScore = min(featureSet.totalRiskIndicators / 10, 1.0)
            combinedScore += featureScore * 0.25
        
        # Add OSINT score if available
        if osintData and osintData.reputation:
            # Reputation score is 0-1 where 1 is good, so we invert it
            osintScore = 1.0 - osintData.reputation.aggregateScore
            combinedScore += osintScore * 0.35
        else:
            # Use domain age and privacy as fallback
            if osintData and osintData.whois:
                osintScore = 0.0
                if osintData.whois.domainAgeDays and osintData.whois.domainAgeDays < 30:
                    osintScore += 0.3
                if osintData.whois.isPrivate:
                    osintScore += 0.2
                combinedScore += osintScore
        
        # Determine if phishing
        isPhishing = combinedScore >= 0.6
        
        # Determine threat level
        if combinedScore < 0.4:
            threatLevel = "safe"
        elif combinedScore < 0.6:
            threatLevel = "suspicious"
        elif combinedScore < 0.8:
            threatLevel = "dangerous"
        else:
            threatLevel = "critical"
        
        # Combine reasons from all sources
        reasons: list[str] = []
        reasons.extend(textAnalysis.reasons[:5])  # Top 5 from text analysis
        
        if urlScore:
            reasons.extend(urlScore.reasons[:3])  # Top 3 from URL
        
        if osintData:
            if osintData.whois and osintData.whois.domainAgeDays and osintData.whois.domainAgeDays < 30:
                reasons.append(f"Domain registered recently ({osintData.whois.domainAgeDays} days ago)")
            if osintData.whois and osintData.whois.isPrivate:
                reasons.append("WHOIS privacy protection enabled")
            if osintData.reputation and osintData.reputation.maliciousCount > 0:
                reasons.append(f"Found in {osintData.reputation.maliciousCount} blacklists")
        
        # Generate recommendation
        recommendation = self._generateRecommendation(threatLevel)
        
        return VerdictResult(
            isPhishing=isPhishing,
            confidenceScore=round(combinedScore, 3),
            threatLevel=threatLevel,
            reasons=reasons[:10],  # Limit to 10 reasons
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
            isPrivate=osintData.whois.isPrivate if osintData.whois else False,
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
