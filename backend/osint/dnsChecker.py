"""
DNS Checker Module for OSINT Data Collection.

This module provides async DNS resolution capabilities for phishing detection.
It collects A, AAAA, MX, NS, TXT, and CNAME records and analyzes them for
suspicious patterns.

Features:
    - Async DNS resolution with timeout and retry
    - Multiple record type support (A, AAAA, MX, NS, TXT, CNAME)
    - CDN detection (Cloudflare, Akamai, etc.)
    - Mail configuration validation
    - Protocol-based design for testability

Example:
    >>> import asyncio
    >>> from osint import lookupDns
    >>> 
    >>> async def check():
    ...     result = await lookupDns("example.com")
    ...     print(f"IPs: {result.ipAddresses}")
    ...     print(f"Has MX: {result.hasValidMx}")
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

import dns.resolver
import dns.exception
import dns.rdatatype

from .schemas import (
    DnsResult,
    DnsRecord,
    DnsRecordType,
    LookupStatus,
)

# =============================================================================
# Module Configuration
# =============================================================================

logger = logging.getLogger(__name__)

# CDN providers to detect (domain patterns in CNAME or NS records)
CDN_PATTERNS: frozenset[str] = frozenset({
    "cloudflare",
    "cloudfront",
    "akamai",
    "fastly",
    "edgecast",
    "sucuri",
    "incapsula",
    "stackpath",
    "imperva",
    "cdn77",
    "keycdn",
    "bunny",
    "azure",
    "googleapis",
    "googleusercontent",
})

# Common free email providers (suspicious for business domains)
FREE_EMAIL_PROVIDERS: frozenset[str] = frozenset({
    "gmail",
    "yahoo",
    "hotmail",
    "outlook",
    "protonmail",
    "zoho",
    "mail.ru",
    "yandex",
})


# =============================================================================
# Exceptions
# =============================================================================

class DnsError(Exception):
    """Base exception for DNS operations."""
    
    def __init__(self, message: str, domain: str = "") -> None:
        self.domain = domain
        super().__init__(message)


class DnsTimeoutError(DnsError):
    """DNS lookup timed out."""
    pass


class DnsNotFoundError(DnsError):
    """Domain not found in DNS (NXDOMAIN)."""
    pass


# =============================================================================
# Protocol for Dependency Injection
# =============================================================================

@runtime_checkable
class DnsResolverProtocol(Protocol):
    """
    Protocol for DNS resolver operations.
    
    Enables dependency injection for testing without real DNS queries.
    """
    
    def resolve(
        self,
        domain: str,
        recordType: str
    ) -> list[dict]:
        """
        Resolve DNS records for a domain.
        
        Args:
            domain: Domain name to resolve
            recordType: DNS record type (A, AAAA, MX, etc.)
        
        Returns:
            List of record dictionaries with 'value', 'ttl', and optional 'priority'
        
        Raises:
            DnsNotFoundError: If domain doesn't exist
            DnsTimeoutError: If resolution times out
            DnsError: For other DNS errors
        """
        ...


# =============================================================================
# Default DNS Resolver Implementation
# =============================================================================

class DefaultDnsResolver:
    """
    Default DNS resolver using dnspython library.
    
    Provides synchronous DNS resolution wrapped for async use.
    """
    
    def __init__(self, timeout: float = 5.0, nameservers: Optional[list[str]] = None) -> None:
        """
        Initialize the DNS resolver.
        
        Args:
            timeout: Query timeout in seconds
            nameservers: Optional custom nameservers (defaults to system)
        """
        self._timeout = timeout
        self._nameservers = nameservers
    
    def resolve(self, domain: str, recordType: str) -> list[dict]:
        """
        Resolve DNS records synchronously.
        
        Args:
            domain: Domain name to resolve
            recordType: DNS record type
        
        Returns:
            List of record dictionaries
        
        Raises:
            DnsNotFoundError: Domain doesn't exist
            DnsTimeoutError: Resolution timed out
            DnsError: Other DNS errors
        """
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self._timeout
            resolver.lifetime = self._timeout
            
            if self._nameservers:
                resolver.nameservers = self._nameservers
            
            rdtype = dns.rdatatype.from_text(recordType)
            answer = resolver.resolve(domain, rdtype)
            
            records = []
            for rdata in answer:
                record = {
                    "value": self._extractValue(rdata, recordType),
                    "ttl": answer.ttl,
                }
                
                # Add priority for MX records
                if recordType == "MX":
                    record["priority"] = rdata.preference
                
                records.append(record)
            
            return records
        
        except dns.resolver.NXDOMAIN:
            raise DnsNotFoundError(f"Domain not found: {domain}", domain)
        
        except dns.resolver.NoAnswer:
            # Domain exists but no records of this type
            return []
        
        except dns.resolver.NoNameservers:
            raise DnsError(f"No nameservers available for {domain}", domain)
        
        except dns.exception.Timeout:
            raise DnsTimeoutError(f"DNS timeout for {domain}", domain)
        
        except Exception as e:
            raise DnsError(f"DNS error for {domain}: {str(e)}", domain)
    
    def _extractValue(self, rdata, recordType: str) -> str:
        """Extract string value from DNS record data."""
        if recordType == "MX":
            return str(rdata.exchange).rstrip(".")
        elif recordType == "TXT":
            # TXT records may have multiple strings
            return "".join(s.decode() if isinstance(s, bytes) else s 
                         for s in rdata.strings)
        elif recordType in ("CNAME", "NS"):
            return str(rdata.target).rstrip(".")
        else:
            return str(rdata).rstrip(".")


# =============================================================================
# DNS Lookup Class
# =============================================================================

class DnsChecker:
    """
    Async DNS checker for phishing detection.
    
    Performs comprehensive DNS lookups and analyzes records for
    suspicious patterns commonly associated with phishing sites.
    
    Attributes:
        timeout: DNS query timeout in seconds
        maxRetries: Maximum retry attempts for failed queries
        retryDelay: Delay between retries in seconds
    
    Example:
        >>> checker = DnsChecker(timeout=5.0)
        >>> result = await checker.lookup("example.com")
        >>> print(result.ipAddresses)
    """
    
    def __init__(
        self,
        timeout: Optional[float] = None,
        maxRetries: int = 2,
        retryDelay: float = 0.5,
        resolver: Optional[DnsResolverProtocol] = None
    ) -> None:
        """
        Initialize the DNS checker.
        
        Args:
            timeout: Query timeout (defaults to config value)
            maxRetries: Max retry attempts for transient failures
            retryDelay: Delay between retry attempts
            resolver: Custom resolver for dependency injection
        """
        from config import getSettings
        settings = getSettings()
        
        self._timeout = timeout or settings.dnsTimeout
        self._maxRetries = max(0, min(maxRetries, 5))
        self._retryDelay = retryDelay
        self._resolver = resolver or DefaultDnsResolver(timeout=self._timeout)
    
    async def lookup(self, domain: str) -> DnsResult:
        """
        Perform comprehensive DNS lookup for a domain.
        
        Resolves multiple record types and analyzes them for
        suspicious patterns.
        
        Args:
            domain: Domain name to lookup (will be normalized)
        
        Returns:
            DnsResult with all resolved records and analysis
        
        Note:
            This method never raises exceptions. Errors are captured
            in the result's status and errorMessage fields.
        """
        startTime = time.perf_counter()
        
        # Validate and normalize domain
        normalizedDomain = self._normalizeDomain(domain)
        
        if not normalizedDomain:
            return DnsResult(
                domain="unknown",
                status=LookupStatus.ERROR,
                errorMessage="Empty or invalid domain",
                durationMs=self._calculateDuration(startTime)
            )
        
        try:
            # Perform lookups for all record types in parallel
            results, criticalError = await self._resolveAllRecords(normalizedDomain)
            
            # Check for critical errors (timeout, general errors)
            if criticalError is not None:
                if isinstance(criticalError, DnsTimeoutError):
                    return DnsResult(
                        domain=normalizedDomain,
                        status=LookupStatus.TIMEOUT,
                        errorMessage=str(criticalError),
                        durationMs=self._calculateDuration(startTime)
                    )
                else:
                    return DnsResult(
                        domain=normalizedDomain,
                        status=LookupStatus.ERROR,
                        errorMessage=str(criticalError),
                        durationMs=self._calculateDuration(startTime)
                    )
            
            # Check if domain exists at all
            if self._isDomainNotFound(results):
                return DnsResult(
                    domain=normalizedDomain,
                    status=LookupStatus.NOT_FOUND,
                    errorMessage="Domain not found (NXDOMAIN)",
                    durationMs=self._calculateDuration(startTime)
                )
            
            # Build successful result
            return self._buildResult(
                domain=normalizedDomain,
                results=results,
                durationMs=self._calculateDuration(startTime)
            )
        
        except DnsTimeoutError as e:
            logger.warning(f"DNS timeout for {normalizedDomain}: {e}")
            return DnsResult(
                domain=normalizedDomain,
                status=LookupStatus.TIMEOUT,
                errorMessage=str(e),
                durationMs=self._calculateDuration(startTime)
            )
        
        except Exception as e:
            logger.error(f"DNS error for {normalizedDomain}: {e}")
            return DnsResult(
                domain=normalizedDomain,
                status=LookupStatus.ERROR,
                errorMessage=str(e),
                durationMs=self._calculateDuration(startTime)
            )
    
    async def _resolveAllRecords(self, domain: str) -> tuple[dict[str, list[dict]], Optional[Exception]]:
        """
        Resolve all DNS record types in parallel.
        
        Args:
            domain: Normalized domain name
        
        Returns:
            Tuple of (results dict, critical exception if any)
        """
        recordTypes = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
        
        # Create tasks for parallel resolution
        tasks = [
            self._resolveWithRetry(domain, recordType)
            for recordType in recordTypes
        ]
        
        # Run all lookups in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Separate results from exceptions
        recordResults = {}
        criticalException: Optional[Exception] = None
        allNxdomain = True
        
        for recordType, result in zip(recordTypes, results):
            if isinstance(result, DnsNotFoundError):
                # NXDOMAIN is expected for some record types
                recordResults[recordType] = []
            elif isinstance(result, (DnsTimeoutError, DnsError)):
                # Track critical exceptions
                recordResults[recordType] = []
                if criticalException is None:
                    criticalException = result
                allNxdomain = False
            elif isinstance(result, Exception):
                # Other unexpected exceptions
                recordResults[recordType] = []
                if criticalException is None:
                    criticalException = DnsError(str(result), domain)
                allNxdomain = False
            else:
                # Successful result
                recordResults[recordType] = result
                allNxdomain = False
        
        # Only return critical exception if ALL record types failed with errors
        # (not just NXDOMAIN)
        if allNxdomain:
            # True NXDOMAIN - domain doesn't exist
            return recordResults, None
        elif criticalException and all(len(r) == 0 for r in recordResults.values()):
            # All failed with errors, propagate the first one
            return recordResults, criticalException
        
        return recordResults, None
    
    async def _resolveWithRetry(
        self,
        domain: str,
        recordType: str
    ) -> list[dict]:
        """
        Resolve DNS record with retry logic.
        
        Args:
            domain: Domain to resolve
            recordType: DNS record type
        
        Returns:
            List of record dictionaries
        
        Raises:
            DnsNotFoundError: If domain doesn't exist (no retry)
            DnsTimeoutError: If all retries fail with timeout
            DnsError: If all retries fail with errors
        """
        lastError: Optional[Exception] = None
        
        for attempt in range(self._maxRetries + 1):
            try:
                # Run blocking resolver in thread pool
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None,
                    self._resolver.resolve,
                    domain,
                    recordType
                )
            
            except DnsNotFoundError:
                # Don't retry for NXDOMAIN
                raise
            
            except (DnsTimeoutError, DnsError) as e:
                lastError = e
                
                if attempt < self._maxRetries:
                    logger.debug(
                        f"DNS retry {attempt + 1}/{self._maxRetries} "
                        f"for {domain} ({recordType}): {e}"
                    )
                    await asyncio.sleep(self._retryDelay)
        
        # All retries exhausted
        if lastError:
            raise lastError
        
        return []
    
    def _buildResult(
        self,
        domain: str,
        results: dict[str, list[dict]],
        durationMs: float
    ) -> DnsResult:
        """
        Build DnsResult from raw lookup results.
        
        Args:
            domain: Domain name
            results: Raw lookup results by record type
            durationMs: Total lookup duration
        
        Returns:
            Fully populated DnsResult
        """
        # Extract simple record values
        aRecords = [r["value"] for r in results.get("A", [])]
        aaaaRecords = [r["value"] for r in results.get("AAAA", [])]
        nsRecords = [r["value"] for r in results.get("NS", [])]
        txtRecords = [r["value"] for r in results.get("TXT", [])]
        cnameRecords = [r["value"] for r in results.get("CNAME", [])]
        
        # Build MX records with priority
        mxRecords = [
            DnsRecord(
                recordType=DnsRecordType.MX,
                value=r["value"],
                ttl=r.get("ttl"),
                priority=r.get("priority", 0)
            )
            for r in results.get("MX", [])
        ]
        
        # Analyze records
        hasValidMx = self._hasValidMailConfig(mxRecords, txtRecords)
        usesCdn = self._detectCdn(cnameRecords, nsRecords, aRecords)
        
        return DnsResult(
            domain=domain,
            status=LookupStatus.SUCCESS,
            durationMs=durationMs,
            aRecords=aRecords,
            aaaaRecords=aaaaRecords,
            mxRecords=mxRecords,
            nsRecords=nsRecords,
            txtRecords=txtRecords,
            cnameRecords=cnameRecords,
            hasValidMx=hasValidMx,
            usesCdn=usesCdn
        )
    
    def _hasValidMailConfig(
        self,
        mxRecords: list[DnsRecord],
        txtRecords: list[str]
    ) -> bool:
        """
        Check if domain has valid mail configuration.
        
        A domain has valid mail config if it has:
        - At least one MX record with a non-empty value, OR
        - SPF record in TXT records
        
        Args:
            mxRecords: List of MX records
            txtRecords: List of TXT record values
        
        Returns:
            True if valid mail config exists
        """
        # Check for MX records
        if mxRecords and any(mx.value for mx in mxRecords):
            return True
        
        # Check for SPF record
        for txt in txtRecords:
            if txt.lower().startswith("v=spf1"):
                return True
        
        return False
    
    def _detectCdn(
        self,
        cnameRecords: list[str],
        nsRecords: list[str],
        aRecords: list[str]
    ) -> bool:
        """
        Detect if domain uses a CDN.
        
        Checks CNAME and NS records for known CDN patterns.
        
        Args:
            cnameRecords: CNAME record values
            nsRecords: NS record values
            aRecords: A record values (IP addresses)
        
        Returns:
            True if CDN is detected
        """
        allRecords = cnameRecords + nsRecords
        
        for record in allRecords:
            recordLower = record.lower()
            if any(cdn in recordLower for cdn in CDN_PATTERNS):
                return True
        
        return False
    
    def _isDomainNotFound(self, results: dict[str, list[dict]]) -> bool:
        """
        Check if domain doesn't exist (all lookups returned empty).
        
        Note: A domain can exist without A records (e.g., only MX),
        so we check if ALL record types returned empty.
        
        Args:
            results: Lookup results by record type
        
        Returns:
            True if domain appears to not exist
        """
        return all(len(records) == 0 for records in results.values())
    
    def _normalizeDomain(self, domain: str) -> str:
        """
        Normalize domain name for DNS lookup.
        
        Removes protocol, path, and other URL components.
        
        Args:
            domain: Raw domain or URL input
        
        Returns:
            Normalized domain name
        """
        if not domain:
            return ""
        
        normalized = domain.strip().lower()
        
        # Remove protocol
        for prefix in ("https://", "http://", "//"):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
        
        # Remove www prefix
        if normalized.startswith("www."):
            normalized = normalized[4:]
        
        # Remove path, query string, port
        for char in ("/", "?", "#", ":"):
            if char in normalized:
                normalized = normalized.split(char)[0]
        
        return normalized.strip(".")
    
    def _calculateDuration(self, startTime: float) -> float:
        """Calculate duration in milliseconds."""
        return (time.perf_counter() - startTime) * 1000
    
    async def __aenter__(self) -> "DnsChecker":
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, *args) -> None:
        """Async context manager exit."""
        pass


# =============================================================================
# Convenience Function
# =============================================================================

async def lookupDns(
    domain: str,
    timeout: Optional[float] = None
) -> DnsResult:
    """
    Convenience function for DNS lookup.
    
    Creates a DnsChecker instance and performs lookup.
    For multiple lookups, use DnsChecker directly for efficiency.
    
    Args:
        domain: Domain to lookup
        timeout: Optional custom timeout
    
    Returns:
        DnsResult with DNS data
    
    Example:
        >>> result = await lookupDns("google.com")
        >>> print(result.ipAddresses)
    """
    async with DnsChecker(timeout=timeout) as checker:
        return await checker.lookup(domain)
