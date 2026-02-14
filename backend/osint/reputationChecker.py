"""
Reputation Checker Module for OSINT Data Collection.

This module provides async reputation lookup capabilities using external
threat intelligence APIs. It supports VirusTotal, AbuseIPDB, and can be
extended for additional sources.

Features:
    - Async API requests with timeout and retry
    - Multiple reputation source support
    - Aggregated risk scoring
    - Rate limiting awareness
    - Protocol-based design for testability

Supported Sources:
    - VirusTotal: Domain/URL reputation
    - AbuseIPDB: IP address reputation
    - Internal: Placeholder for custom blocklists

Example:
    >>> import asyncio
    >>> from osint import lookupReputation
    >>> 
    >>> async def check():
    ...     result = await lookupReputation("example.com")
    ...     print(f"Malicious: {result.knownMalicious}")
    ...     print(f"Score: {result.aggregateScore}")
    >>> 
    >>> asyncio.run(check())

Author: Ishaq Muhammad
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional, Protocol, runtime_checkable

import httpx

from .schemas import (
    ReputationResult,
    ReputationCheck,
    ReputationSource,
    LookupStatus,
)

# =============================================================================
# Module Configuration
# =============================================================================

logger = logging.getLogger(__name__)

# API endpoints
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2"

# Default timeouts
DEFAULT_API_TIMEOUT = 10.0
DEFAULT_MAX_RETRIES = 2


# =============================================================================
# Exceptions
# =============================================================================

class ReputationError(Exception):
    """Base exception for reputation operations."""
    
    def __init__(self, message: str, source: Optional[str] = None) -> None:
        self.source = source
        super().__init__(message)


class ReputationTimeoutError(ReputationError):
    """API request timed out."""
    pass


class ReputationApiError(ReputationError):
    """API returned an error response."""
    
    def __init__(
        self,
        message: str,
        source: Optional[str] = None,
        statusCode: Optional[int] = None
    ) -> None:
        self.statusCode = statusCode
        super().__init__(message, source)


class ReputationRateLimitError(ReputationApiError):
    """API rate limit exceeded."""
    pass


# =============================================================================
# Protocol for Dependency Injection
# =============================================================================

@runtime_checkable
class ReputationClientProtocol(Protocol):
    """
    Protocol for reputation API client operations.
    
    Enables dependency injection for testing without real API calls.
    """
    
    async def checkDomain(
        self,
        domain: str,
        source: ReputationSource
    ) -> ReputationCheck:
        """
        Check domain reputation with a specific source.
        
        Args:
            domain: Domain name to check
            source: Reputation source to query
        
        Returns:
            ReputationCheck with results
        
        Raises:
            ReputationError: On API errors
        """
        ...
    
    async def checkIp(
        self,
        ip: str,
        source: ReputationSource
    ) -> ReputationCheck:
        """
        Check IP address reputation.
        
        Args:
            ip: IP address to check
            source: Reputation source to query
        
        Returns:
            ReputationCheck with results
        """
        ...


# =============================================================================
# Default Reputation Client Implementation
# =============================================================================

class DefaultReputationClient:
    """
    Default reputation client using real APIs.
    
    Supports VirusTotal and AbuseIPDB with proper authentication
    and rate limit handling.
    """
    
    def __init__(
        self,
        virusTotalApiKey: Optional[str] = None,
        abuseIpDbApiKey: Optional[str] = None,
        timeout: float = DEFAULT_API_TIMEOUT
    ) -> None:
        """
        Initialize the reputation client.
        
        Args:
            virusTotalApiKey: VirusTotal API key (optional)
            abuseIpDbApiKey: AbuseIPDB API key (optional)
            timeout: Request timeout in seconds
        """
        self._virusTotalApiKey = virusTotalApiKey
        self._abuseIpDbApiKey = abuseIpDbApiKey
        self._timeout = timeout
        self._httpClient: Optional[httpx.AsyncClient] = None
    
    async def _getClient(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._httpClient is None or self._httpClient.is_closed:
            self._httpClient = httpx.AsyncClient(timeout=self._timeout)
        return self._httpClient
    
    async def close(self) -> None:
        """Close the HTTP client."""
        if self._httpClient and not self._httpClient.is_closed:
            await self._httpClient.aclose()
            self._httpClient = None
    
    async def checkDomain(
        self,
        domain: str,
        source: ReputationSource
    ) -> ReputationCheck:
        """
        Check domain reputation with specified source.
        
        Args:
            domain: Domain to check
            source: Reputation source
        
        Returns:
            ReputationCheck with findings
        """
        if source == ReputationSource.VIRUSTOTAL:
            return await self._checkVirusTotal(domain)
        elif source == ReputationSource.INTERNAL:
            return await self._checkInternal(domain)
        else:
            # Source not supported for domains
            return ReputationCheck(
                source=source,
                isMalicious=False,
                confidence=0.0,
                category=None
            )
    
    async def checkIp(
        self,
        ip: str,
        source: ReputationSource
    ) -> ReputationCheck:
        """
        Check IP address reputation.
        
        Args:
            ip: IP address to check
            source: Reputation source
        
        Returns:
            ReputationCheck with findings
        """
        if source == ReputationSource.ABUSEIPDB:
            return await self._checkAbuseIpDb(ip)
        elif source == ReputationSource.VIRUSTOTAL:
            return await self._checkVirusTotalIp(ip)
        else:
            return ReputationCheck(
                source=source,
                isMalicious=False,
                confidence=0.0
            )
    
    async def _checkVirusTotal(self, domain: str) -> ReputationCheck:
        """
        Query VirusTotal API for domain reputation.
        
        Args:
            domain: Domain to check
        
        Returns:
            ReputationCheck from VirusTotal
        """
        if not self._virusTotalApiKey:
            logger.debug("VirusTotal API key not configured, skipping")
            return ReputationCheck(
                source=ReputationSource.VIRUSTOTAL,
                isMalicious=False,
                confidence=0.0,
                category="api_key_missing"
            )
        
        try:
            client = await self._getClient()
            url = f"{VIRUSTOTAL_API_URL}/domains/{domain}"
            
            response = await client.get(
                url,
                headers={"x-apikey": self._virusTotalApiKey}
            )
            
            if response.status_code == 429:
                raise ReputationRateLimitError(
                    "VirusTotal rate limit exceeded",
                    source="virustotal",
                    statusCode=429
                )
            
            if response.status_code == 404:
                # Domain not in VT database
                return ReputationCheck(
                    source=ReputationSource.VIRUSTOTAL,
                    isMalicious=False,
                    confidence=0.0,
                    category="not_found"
                )
            
            if response.status_code != 200:
                raise ReputationApiError(
                    f"VirusTotal API error: {response.status_code}",
                    source="virustotal",
                    statusCode=response.status_code
                )
            
            data = response.json()
            return self._parseVirusTotalResponse(data)
        
        except httpx.TimeoutException:
            raise ReputationTimeoutError(
                "VirusTotal request timeout",
                source="virustotal"
            )
        
        except httpx.HTTPError as e:
            raise ReputationError(
                f"VirusTotal HTTP error: {str(e)}",
                source="virustotal"
            )
    
    async def _checkVirusTotalIp(self, ip: str) -> ReputationCheck:
        """Query VirusTotal for IP reputation."""
        if not self._virusTotalApiKey:
            return ReputationCheck(
                source=ReputationSource.VIRUSTOTAL,
                isMalicious=False,
                confidence=0.0,
                category="api_key_missing"
            )
        
        try:
            client = await self._getClient()
            url = f"{VIRUSTOTAL_API_URL}/ip_addresses/{ip}"
            
            response = await client.get(
                url,
                headers={"x-apikey": self._virusTotalApiKey}
            )
            
            if response.status_code == 429:
                raise ReputationRateLimitError(
                    "VirusTotal rate limit exceeded",
                    source="virustotal",
                    statusCode=429
                )
            
            if response.status_code != 200:
                return ReputationCheck(
                    source=ReputationSource.VIRUSTOTAL,
                    isMalicious=False,
                    confidence=0.0
                )
            
            data = response.json()
            return self._parseVirusTotalResponse(data)
        
        except httpx.TimeoutException:
            raise ReputationTimeoutError(
                "VirusTotal request timeout",
                source="virustotal"
            )
        
        except httpx.HTTPError as e:
            raise ReputationError(
                f"VirusTotal HTTP error: {str(e)}",
                source="virustotal"
            )
    
    def _parseVirusTotalResponse(self, data: dict) -> ReputationCheck:
        """
        Parse VirusTotal API response.
        
        Args:
            data: Raw API response
        
        Returns:
            Parsed ReputationCheck
        """
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 1
        
        isMalicious = (malicious + suspicious) > 0
        confidence = min((malicious + suspicious) / max(total, 1), 1.0)
        
        # Get primary category
        categories = attributes.get("categories", {})
        category = None
        if categories:
            # Get first category value
            category = next(iter(categories.values()), None)
        
        return ReputationCheck(
            source=ReputationSource.VIRUSTOTAL,
            isMalicious=isMalicious,
            confidence=confidence,
            category=category
        )
    
    async def _checkAbuseIpDb(self, ip: str) -> ReputationCheck:
        """
        Query AbuseIPDB for IP reputation.
        
        Args:
            ip: IP address to check
        
        Returns:
            ReputationCheck from AbuseIPDB
        """
        if not self._abuseIpDbApiKey:
            logger.debug("AbuseIPDB API key not configured, skipping")
            return ReputationCheck(
                source=ReputationSource.ABUSEIPDB,
                isMalicious=False,
                confidence=0.0,
                category="api_key_missing"
            )
        
        try:
            client = await self._getClient()
            url = f"{ABUSEIPDB_API_URL}/check"
            
            response = await client.get(
                url,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={
                    "Key": self._abuseIpDbApiKey,
                    "Accept": "application/json"
                }
            )
            
            if response.status_code == 429:
                raise ReputationRateLimitError(
                    "AbuseIPDB rate limit exceeded",
                    source="abuseipdb",
                    statusCode=429
                )
            
            if response.status_code != 200:
                raise ReputationApiError(
                    f"AbuseIPDB API error: {response.status_code}",
                    source="abuseipdb",
                    statusCode=response.status_code
                )
            
            data = response.json()
            return self._parseAbuseIpDbResponse(data)
        
        except httpx.TimeoutException:
            raise ReputationTimeoutError(
                "AbuseIPDB request timeout",
                source="abuseipdb"
            )
        
        except httpx.HTTPError as e:
            raise ReputationError(
                f"AbuseIPDB HTTP error: {str(e)}",
                source="abuseipdb"
            )
    
    def _parseAbuseIpDbResponse(self, data: dict) -> ReputationCheck:
        """
        Parse AbuseIPDB API response.
        
        Args:
            data: Raw API response
        
        Returns:
            Parsed ReputationCheck
        """
        ipData = data.get("data", {})
        
        abuseScore = ipData.get("abuseConfidenceScore", 0)
        totalReports = ipData.get("totalReports", 0)
        
        # Consider malicious if abuse score > 50 or has recent reports
        isMalicious = abuseScore > 50 or totalReports > 5
        confidence = abuseScore / 100.0
        
        # Get usage type as category
        category = ipData.get("usageType", None)
        
        return ReputationCheck(
            source=ReputationSource.ABUSEIPDB,
            isMalicious=isMalicious,
            confidence=confidence,
            category=category
        )
    
    async def _checkInternal(self, domain: str) -> ReputationCheck:
        """
        Check against internal blocklist (placeholder).
        
        This can be extended to check against custom blocklists,
        previously detected phishing domains, etc.
        
        Args:
            domain: Domain to check
        
        Returns:
            ReputationCheck (currently always clean)
        """
        # Placeholder for internal blocklist check
        # In production, this would query a database of known bad domains
        return ReputationCheck(
            source=ReputationSource.INTERNAL,
            isMalicious=False,
            confidence=0.0,
            category=None
        )


# =============================================================================
# Reputation Checker Class
# =============================================================================

class ReputationChecker:
    """
    Async reputation checker for phishing detection.
    
    Queries multiple reputation sources and aggregates results
    into a unified risk score.
    
    Attributes:
        timeout: API request timeout in seconds
        maxRetries: Maximum retry attempts for failed requests
        sources: List of reputation sources to query
    
    Example:
        >>> checker = ReputationChecker()
        >>> result = await checker.lookup("example.com")
        >>> print(f"Score: {result.aggregateScore}")
    """
    
    def __init__(
        self,
        timeout: Optional[float] = None,
        maxRetries: int = DEFAULT_MAX_RETRIES,
        client: Optional[ReputationClientProtocol] = None,
        sources: Optional[list[ReputationSource]] = None
    ) -> None:
        """
        Initialize the reputation checker.
        
        Args:
            timeout: API request timeout (defaults to config)
            maxRetries: Max retries for transient failures
            client: Custom client for dependency injection
            sources: Sources to query (defaults to all configured)
        """
        from backend.config import getSettings
        settings = getSettings()
        
        self._timeout = timeout or settings.reputationTimeout
        self._maxRetries = max(0, min(maxRetries, 5))
        
        if client:
            self._client = client
        else:
            self._client = DefaultReputationClient(
                virusTotalApiKey=settings.virusTotalApiKey,
                abuseIpDbApiKey=settings.abuseIpDbApiKey,
                timeout=self._timeout
            )
        
        # Default sources based on available API keys
        if sources:
            self._sources = sources
        else:
            self._sources = [ReputationSource.INTERNAL]
            if settings.hasVirusTotalKey:
                self._sources.append(ReputationSource.VIRUSTOTAL)
            if settings.hasAbuseIpDbKey:
                self._sources.append(ReputationSource.ABUSEIPDB)
    
    async def lookup(
        self,
        domain: str,
        ipAddresses: Optional[list[str]] = None
    ) -> ReputationResult:
        """
        Perform reputation lookup for a domain.
        
        Queries all configured sources and aggregates results.
        
        Args:
            domain: Domain name to check
            ipAddresses: Optional list of IPs to also check
        
        Returns:
            ReputationResult with aggregated findings
        
        Note:
            This method never raises exceptions. Errors are captured
            in the result's status and errorMessage fields.
        """
        startTime = time.perf_counter()
        
        # Validate domain
        normalizedDomain = self._normalizeDomain(domain)
        
        if not normalizedDomain:
            return ReputationResult(
                domain="unknown",
                status=LookupStatus.ERROR,
                errorMessage="Empty or invalid domain",
                durationMs=self._calculateDuration(startTime)
            )
        
        try:
            # Collect all checks
            checks: list[ReputationCheck] = []
            
            # Check domain with each source
            domainChecks = await self._checkDomain(normalizedDomain)
            checks.extend(domainChecks)
            
            # Check IPs if provided
            if ipAddresses:
                ipChecks = await self._checkIps(ipAddresses)
                checks.extend(ipChecks)
            
            # Build result
            return self._buildResult(
                domain=normalizedDomain,
                checks=checks,
                durationMs=self._calculateDuration(startTime)
            )
        
        except Exception as e:
            logger.error(f"Reputation check error for {normalizedDomain}: {e}")
            return ReputationResult(
                domain=normalizedDomain,
                status=LookupStatus.ERROR,
                errorMessage=str(e),
                durationMs=self._calculateDuration(startTime)
            )
    
    async def _checkDomain(self, domain: str) -> list[ReputationCheck]:
        """
        Check domain against all sources.
        
        Args:
            domain: Normalized domain
        
        Returns:
            List of reputation checks
        """
        tasks = [
            self._checkWithRetry(domain, source, "domain")
            for source in self._sources
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        checks = []
        for result in results:
            if isinstance(result, ReputationCheck):
                checks.append(result)
            elif isinstance(result, Exception):
                logger.warning(f"Reputation check failed: {result}")
        
        return checks
    
    async def _checkIps(self, ipAddresses: list[str]) -> list[ReputationCheck]:
        """
        Check IP addresses against relevant sources.
        
        Args:
            ipAddresses: List of IPs to check
        
        Returns:
            List of reputation checks
        """
        # Only check IPs with sources that support IP lookup
        ipSources = [
            s for s in self._sources
            if s in (ReputationSource.VIRUSTOTAL, ReputationSource.ABUSEIPDB)
        ]
        
        if not ipSources:
            return []
        
        tasks = []
        for ip in ipAddresses[:5]:  # Limit to first 5 IPs
            for source in ipSources:
                tasks.append(self._checkWithRetry(ip, source, "ip"))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [r for r in results if isinstance(r, ReputationCheck)]
    
    async def _checkWithRetry(
        self,
        target: str,
        source: ReputationSource,
        targetType: str
    ) -> ReputationCheck:
        """
        Perform check with retry logic.
        
        Args:
            target: Domain or IP to check
            source: Reputation source
            targetType: "domain" or "ip"
        
        Returns:
            ReputationCheck from source
        """
        lastError: Optional[Exception] = None
        
        for attempt in range(self._maxRetries + 1):
            try:
                if targetType == "domain":
                    return await self._client.checkDomain(target, source)
                else:
                    return await self._client.checkIp(target, source)
            
            except ReputationRateLimitError:
                # Don't retry rate limits
                raise
            
            except (ReputationTimeoutError, ReputationError) as e:
                lastError = e
                
                if attempt < self._maxRetries:
                    logger.debug(
                        f"Reputation retry {attempt + 1}/{self._maxRetries} "
                        f"for {target} ({source.value})"
                    )
                    await asyncio.sleep(0.5)
        
        # Return empty check on failure
        if lastError:
            logger.warning(f"Reputation check failed after retries: {lastError}")
        
        return ReputationCheck(
            source=source,
            isMalicious=False,
            confidence=0.0,
            category="check_failed"
        )
    
    def _buildResult(
        self,
        domain: str,
        checks: list[ReputationCheck],
        durationMs: float
    ) -> ReputationResult:
        """
        Build ReputationResult from individual checks.
        
        Args:
            domain: Domain name
            checks: List of reputation checks
            durationMs: Total lookup duration
        
        Returns:
            Aggregated ReputationResult
        """
        # Calculate aggregate score
        aggregateScore = self._calculateAggregateScore(checks)
        
        # Determine if known malicious
        knownMalicious = any(
            check.isMalicious and check.confidence > 0.5
            for check in checks
        )
        
        # Collect all categories
        categories = [
            check.category
            for check in checks
            if check.category and check.category not in (
                "api_key_missing", "check_failed", "not_found"
            )
        ]
        
        return ReputationResult(
            domain=domain,
            status=LookupStatus.SUCCESS,
            durationMs=durationMs,
            checks=checks,
            aggregateScore=aggregateScore,
            knownMalicious=knownMalicious,
            categories=categories
        )
    
    def _calculateAggregateScore(self, checks: list[ReputationCheck]) -> float:
        """
        Calculate aggregate reputation score.
        
        Higher score = more suspicious (0.0 - 1.0)
        
        Args:
            checks: List of reputation checks
        
        Returns:
            Aggregate score between 0 and 1
        """
        if not checks:
            return 0.0
        
        # Weight malicious findings higher
        totalWeight = 0.0
        weightedSum = 0.0
        
        for check in checks:
            # Skip failed checks
            if check.category in ("api_key_missing", "check_failed"):
                continue
            
            weight = 1.0
            if check.source == ReputationSource.VIRUSTOTAL:
                weight = 2.0  # VT is highly trusted
            
            totalWeight += weight
            
            if check.isMalicious:
                weightedSum += check.confidence * weight
        
        if totalWeight == 0:
            return 0.0
        
        return min(weightedSum / totalWeight, 1.0)
    
    def _normalizeDomain(self, domain: str) -> str:
        """Normalize domain name."""
        if not domain:
            return ""
        
        normalized = domain.strip().lower()
        
        # Remove protocol
        for prefix in ("https://", "http://", "//"):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
        
        # Remove www
        if normalized.startswith("www."):
            normalized = normalized[4:]
        
        # Remove path and query
        for char in ("/", "?", "#", ":"):
            if char in normalized:
                normalized = normalized.split(char)[0]
        
        return normalized.strip(".")
    
    def _calculateDuration(self, startTime: float) -> float:
        """Calculate duration in milliseconds."""
        return (time.perf_counter() - startTime) * 1000
    
    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if hasattr(self._client, "close"):
            await self._client.close()
    
    async def __aenter__(self) -> "ReputationChecker":
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, *args) -> None:
        """Async context manager exit."""
        await self.close()


# =============================================================================
# Convenience Function
# =============================================================================

async def lookupReputation(
    domain: str,
    ipAddresses: Optional[list[str]] = None,
    timeout: Optional[float] = None
) -> ReputationResult:
    """
    Convenience function for reputation lookup.
    
    Creates a ReputationChecker instance and performs lookup.
    For multiple lookups, use ReputationChecker directly.
    
    Args:
        domain: Domain to check
        ipAddresses: Optional IPs to also check
        timeout: Optional custom timeout
    
    Returns:
        ReputationResult with findings
    
    Example:
        >>> result = await lookupReputation("example.com")
        >>> print(f"Malicious: {result.knownMalicious}")
    """
    async with ReputationChecker(timeout=timeout) as checker:
        return await checker.lookup(domain, ipAddresses)
