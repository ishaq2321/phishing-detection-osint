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
from typing import Any, Optional
from urllib.parse import urlparse

from backend.analyzer import AnalysisResult, ContentType, NlpAnalyzer
from backend.config import settings
from backend.ml import FeatureSet, PhishingPredictor, RiskScore, extractFeatures, scoreUrl
from backend.osint import OsintData, lookupDns, lookupReputationCached, lookupWhois

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
# Maximum number of batch items analysed simultaneously. Each item spawns
# up to three OSINT lookups; an unbounded gather on a 50-item batch means
# ~150 concurrent outbound requests, which overwhelms free-tier instances
# and trips provider rate limits.
BATCH_CONCURRENCY = 5


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
    4. Running NLP analysis on text content
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

            response = AnalysisResponse(
                success=True,
                verdict=verdict,
                osint=self._buildOsintSummary(osintData, domain) if osintData else None,
                features=self._buildFeatureSummary(featureSet, textAnalysis),
                analysisTime=analysisTime,
            )

            # Template-based explanation (URL analyses only).  Deterministic
            # and fire-and-forget: explanation failures never fail analysis.
            if contentType == "url":
                try:
                    from backend.ml.explainer import getExplainer
                    from .schemas import ExplanationItem, ExplanationReport
                    raw = getExplainer().explain(featureSet, osintData)
                    response.explanation = ExplanationReport(
                        summary=raw["summary"],
                        items=[ExplanationItem(**item) for item in raw["items"]],
                    )
                except Exception:  # noqa: BLE001
                    pass

            # Tier 4 D: observability hook -- every analysis path (single,
            # batch, ingest) funnels through here.  Metrics must never be
            # able to break analysis, so this is fire-and-forget.
            try:
                from backend.metrics import ANALYSIS_TOTAL
                ANALYSIS_TOTAL.inc(
                    content_type=contentType,
                    threat_level=response.verdict.threatLevel,
                )
            except Exception:  # noqa: BLE001
                pass

            # Drift monitoring: log the raw model-input vector for URL
            # analyses so the drift monitor can measure distribution shift.
            # Fire-and-forget -- monitoring failures never fail analysis.
            if contentType == "url":
                try:
                    from backend.ml.drift import getMonitor, vectorFromFeatureSet
                    getMonitor().record(vectorFromFeatureSet(featureSet))
                except Exception:  # noqa: BLE001
                    pass

            return response
            
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
            # Collect data from all OSINT sources in parallel under a global
            # budget. On deadline, sources that FINISHED are kept and only
            # the still-running ones are cancelled — a slow DNS lookup must
            # not discard an already-completed WHOIS result (the original
            # wait_for cancelled everything, which is how established
            # domains like github.com lost all OSINT data).
            tasks = {
                "whois": asyncio.create_task(lookupWhois(domain)),
                "dns": asyncio.create_task(lookupDns(domain)),
                "reputation": asyncio.create_task(lookupReputationCached(domain)),
            }
            done, pending = await asyncio.wait(
                tasks.values(),
                timeout=float(settings.osintTimeout),
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

            def result_of(name: str):
                task = tasks[name]
                if task in done and not task.cancelled():
                    exc = task.exception()
                    if exc is None:
                        return task.result()
                return None

            whoisResult = result_of("whois")
            dnsResult = result_of("dns")
            reputationResult = result_of("reputation")

            # Build OsintData object
            return OsintData(
                url=url or f"https://{domain}",
                domain=domain,
                whois=whoisResult if whoisResult and whoisResult.status == "success" else None,
                dns=dnsResult if dnsResult and dnsResult.status == "success" else None,
                reputation=reputationResult if reputationResult and reputationResult.status == "success" else None,
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
            mlWeighted = urlScore.finalScore * ML_PRIMARY_WEIGHT
            nlpWeighted = textAnalysis.confidenceScore * TEXT_SUPPLEMENT_WEIGHT
            combinedScore = mlWeighted + nlpWeighted
            componentScores = {"ml": round(mlWeighted, 3), "nlp": round(nlpWeighted, 3)}
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
            nlpWeighted = textAnalysis.confidenceScore * TEXT_PRIMARY_WEIGHT
            featWeighted = featureScore * URL_SECONDARY_WEIGHT
            osintWeighted = min(osintScore, 1.0) * OSINT_SECONDARY_WEIGHT
            combinedScore = nlpWeighted + featWeighted + osintWeighted
            componentScores = {
                "nlp": round(nlpWeighted, 3),
                "urlFeatures": round(featWeighted, 3),
                "osint": round(osintWeighted, 3),
            }
        
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
            recommendation=recommendation,
            componentScores=componentScores
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
        # Count sources that produced usable data (skip skipped/failed
        # checks) so the UI can tell "checked and clean" apart from
        # "no source ran".
        sourcesChecked = 0
        if osintData.reputation:
            sourcesChecked = sum(
                1
                for c in osintData.reputation.checks
                if getattr(c, "category", None) not in (
                    "api_key_missing",
                    "check_failed",
                    "not_found",
                )
            )
        return OsintSummary(
            domain=domain or osintData.domain,
            domainAgeDays=osintData.whois.domainAgeDays if osintData.whois else None,
            registrar=osintData.whois.registrar if osintData.whois else None,
            isPrivate=osintData.whois.isPrivacyProtected if osintData.whois else False,
            hasValidDns=bool(osintData.dns and osintData.dns.hasIpAddresses) if osintData.dns else False,
            reputationScore=osintData.reputation.aggregateScore if osintData.reputation else 0.0,
            reputationSourcesChecked=sourcesChecked,
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


    # ------------------------------------------------------------------
    # Tier 3: batch analysis
    # ------------------------------------------------------------------
    async def analyzeBatch(
        self,
        items: "list[object]",
    ) -> tuple[list[Any], int, int]:
        """Run a batch of analyses concurrently.

        Each item is a small ``SimpleNamespace`` produced by the
        router layer to keep the orchestrator decoupled from the
        Pydantic schema: ``item.type``, ``item.url``, ``item.content``,
        ``item.subject``, ``item.sender``.

        Returns ``(perItemResultList, succeededCount, failedCount)``.

        The per-item list mirrors the input order.  Each element is a
        tuple ``(outcome, response_or_None, error_or_None)`` where
        ``outcome`` is one of:

        * ``"ok"``    -> ``response_or_None`` is an ``AnalysisResponse``
        * ``"error"`` -> ``error_or_None`` carries the exception text

        Concurrency is bounded only by ``asyncio.gather``; the OSINT
        layer of each individual pipeline does its own retry / timeout
        so a slow upstream can never block the whole batch.
        """
        import asyncio
        from types import SimpleNamespace

        async def _runOne(item: SimpleNamespace) -> AnalysisResponse:
            t = (item.type or "auto").lower()
            if t == "url":
                if not item.url:
                    raise ValueError("type=url but url field is empty")
                return await self.analyze(content=item.url, contentType="url")
            if t == "email":
                if not item.content:
                    raise ValueError("type=email but content field is empty")
                # Mirror the single-content route's body assembly.
                full = item.content
                if item.subject:
                    full = f"Subject: {item.subject}\n\n{full}"
                if item.sender:
                    full = f"From: {item.sender}\n{full}"
                return await self.analyze(content=full, contentType="email")
            # ``auto`` and any unknown type -> let the orchestrator detect.
            if not item.content and not item.url:
                raise ValueError(
                    "auto-detect requires url or content (both empty)"
                )
            return await self.analyze(
                content=item.url or item.content,
                contentType="auto",
            )

        semaphore = asyncio.Semaphore(BATCH_CONCURRENCY)

        async def _runner(item: object):
            """Run with exception captured into the result tuple."""
            async with semaphore:
                try:
                    resp = await _runOne(item)
                    return ("ok", resp, None)
                except Exception as exc:  # noqa: BLE001 - we deliberately
                    # catch *everything*; per-item failures must not
                    # cancel sibling tasks.
                    return ("error", None, str(exc) or type(exc).__name__)

        tasks = [asyncio.create_task(_runner(it)) for it in items]
        results = await asyncio.gather(*tasks)
        succeeded = sum(1 for r in results if r[0] == "ok")
        failed = len(results) - succeeded
        return list(results), succeeded, failed
