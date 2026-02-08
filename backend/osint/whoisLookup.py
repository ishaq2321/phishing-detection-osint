"""
WHOIS Lookup Module
===================

Async WHOIS lookup implementation with robust error handling,
retry logic, and comprehensive data extraction.

Design Principles:
- Async by default for I/O efficiency
- Protocol-based abstraction for testability
- Comprehensive error handling with typed exceptions
- Clean separation between lookup, parsing, and business logic

Architecture:
    WhoisLookup (public interface)
        └── WhoisParser (data extraction)
            └── WhoisResult (Pydantic model)

Usage:
    from osint.whoisLookup import WhoisLookup
    
    async with WhoisLookup() as lookup:
        result = await lookup.lookup("example.com")
        if result.isSuccess:
            print(f"Domain age: {result.domainAgeDays} days")

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import Any, Optional, Protocol

import whois

from config import settings
from osint.schemas import (
    DataSource,
    LookupStatus,
    WhoisContact,
    WhoisResult,
)


# =============================================================================
# Logging Configuration
# =============================================================================

logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================

class WhoisError(Exception):
    """Base exception for WHOIS lookup errors."""
    
    def __init__(self, domain: str, message: str):
        self.domain = domain
        self.message = message
        super().__init__(f"WHOIS error for {domain}: {message}")


class WhoisTimeoutError(WhoisError):
    """Raised when WHOIS lookup times out."""
    pass


class WhoisNotFoundError(WhoisError):
    """Raised when domain is not found in WHOIS."""
    pass


class WhoisParseError(WhoisError):
    """Raised when WHOIS response cannot be parsed."""
    pass


# =============================================================================
# Protocols (for dependency injection and testing)
# =============================================================================

class WhoisClientProtocol(Protocol):
    """Protocol for WHOIS client implementations."""
    
    def query(self, domain: str) -> dict[str, Any]:
        """
        Query WHOIS for a domain.
        
        Args:
            domain: Domain name to query
            
        Returns:
            Dictionary with WHOIS data
            
        Raises:
            Exception: On lookup failure
        """
        ...


class WhoisParserProtocol(Protocol):
    """Protocol for WHOIS response parsers."""
    
    def parse(self, domain: str, rawData: dict[str, Any]) -> WhoisResult:
        """
        Parse raw WHOIS data into structured result.
        
        Args:
            domain: Domain name that was queried
            rawData: Raw WHOIS response data
            
        Returns:
            Structured WhoisResult
        """
        ...


# =============================================================================
# WHOIS Parser Implementation
# =============================================================================

class WhoisParser:
    """
    Parser for raw WHOIS data.
    
    Extracts and normalizes WHOIS fields into structured format.
    Handles inconsistencies across different registrars and TLDs.
    """
    
    # Known privacy protection services
    PRIVACY_INDICATORS = frozenset([
        "privacy",
        "redacted",
        "whoisguard",
        "domains by proxy",
        "contact privacy",
        "private registration",
        "data protected",
        "identity protect",
        "withheld for privacy",
        "redacted for privacy",
        "not disclosed",
    ])
    
    def parse(self, domain: str, rawData: dict[str, Any]) -> WhoisResult:
        """
        Parse raw WHOIS data into WhoisResult model.
        
        Args:
            domain: Domain name queried
            rawData: Raw WHOIS response dictionary
            
        Returns:
            Structured WhoisResult with all extracted fields
        """
        # Extract dates
        creationDate = self._extractDate(rawData.get("creation_date"))
        expirationDate = self._extractDate(rawData.get("expiration_date"))
        updatedDate = self._extractDate(rawData.get("updated_date"))
        
        # Extract name servers
        nameServers = self._extractList(rawData.get("name_servers"))
        
        # Extract registrant contact
        registrant = self._extractContact(rawData)
        
        # Detect privacy protection
        isPrivacyProtected = self._detectPrivacy(rawData, registrant)
        
        # Calculate domain age
        domainAgeDays = self._calculateAgeDays(creationDate)
        
        # Detect phishing indicators
        recentlyRegistered = domainAgeDays is not None and domainAgeDays < 30
        shortLifespan = self._detectShortLifespan(creationDate, expirationDate)
        
        return WhoisResult(
            source=DataSource.WHOIS,
            status=LookupStatus.SUCCESS,
            domain=domain,
            registrar=self._extractString(rawData.get("registrar")),
            creationDate=creationDate,
            expirationDate=expirationDate,
            updatedDate=updatedDate,
            nameServers=nameServers,
            registrant=registrant,
            domainAgeDays=domainAgeDays,
            isPrivacyProtected=isPrivacyProtected,
            recentlyRegistered=recentlyRegistered,
            shortLifespan=shortLifespan,
            rawData=self._sanitizeRawData(rawData),
        )
    
    def _extractDate(self, value: Any) -> Optional[datetime]:
        """Extract datetime from WHOIS response (handles lists and various formats)."""
        if value is None:
            return None
        
        # Handle list of dates (take first)
        if isinstance(value, list):
            value = value[0] if value else None
        
        if isinstance(value, datetime):
            return value
        
        if isinstance(value, str):
            return self._parseDate(value)
        
        return None
    
    def _parseDate(self, dateStr: str) -> Optional[datetime]:
        """Parse date string in various formats."""
        formats = [
            "%Y-%m-%d",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%d-%b-%Y",
            "%Y/%m/%d",
            "%d/%m/%Y",
            "%Y.%m.%d",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(dateStr.strip(), fmt)
            except ValueError:
                continue
        
        logger.debug(f"Failed to parse date: {dateStr}")
        return None
    
    def _extractList(self, value: Any) -> list[str]:
        """Extract list of strings from WHOIS response."""
        if value is None:
            return []
        
        if isinstance(value, str):
            return [value.lower().strip()]
        
        if isinstance(value, (list, tuple, set)):
            return [str(v).lower().strip() for v in value if v]
        
        return []
    
    def _extractString(self, value: Any) -> Optional[str]:
        """Extract string from WHOIS response (handles lists)."""
        if value is None:
            return None
        
        if isinstance(value, list):
            value = value[0] if value else None
        
        if isinstance(value, str):
            return value.strip() if value.strip() else None
        
        return str(value) if value else None
    
    def _extractContact(self, rawData: dict[str, Any]) -> Optional[WhoisContact]:
        """Extract registrant contact information."""
        name = self._extractString(rawData.get("name"))
        org = self._extractString(rawData.get("org"))
        email = self._extractString(rawData.get("emails"))
        country = self._extractString(rawData.get("country"))
        state = self._extractString(rawData.get("state"))
        city = self._extractString(rawData.get("city"))
        
        # Only return contact if we have some data
        if any([name, org, email, country]):
            return WhoisContact(
                name=name,
                organization=org,
                email=email,
                country=country,
                state=state,
                city=city,
            )
        
        return None
    
    def _detectPrivacy(
        self,
        rawData: dict[str, Any],
        registrant: Optional[WhoisContact]
    ) -> bool:
        """Detect if WHOIS privacy protection is enabled."""
        # Check registrant organization
        if registrant and registrant.organization:
            orgLower = registrant.organization.lower()
            if any(indicator in orgLower for indicator in self.PRIVACY_INDICATORS):
                return True
        
        # Check registrant name
        if registrant and registrant.name:
            nameLower = registrant.name.lower()
            if any(indicator in nameLower for indicator in self.PRIVACY_INDICATORS):
                return True
        
        # Check raw text fields
        for key in ["name", "org", "registrant_name", "registrant_organization"]:
            value = self._extractString(rawData.get(key))
            if value:
                valueLower = value.lower()
                if any(indicator in valueLower for indicator in self.PRIVACY_INDICATORS):
                    return True
        
        return False
    
    def _calculateAgeDays(self, creationDate: Optional[datetime]) -> Optional[int]:
        """Calculate domain age in days."""
        if not creationDate:
            return None
        
        delta = datetime.utcnow() - creationDate
        return max(0, delta.days)
    
    def _detectShortLifespan(
        self,
        creationDate: Optional[datetime],
        expirationDate: Optional[datetime]
    ) -> bool:
        """Detect if domain was registered for less than 1 year."""
        if not creationDate or not expirationDate:
            return False
        
        lifespan = expirationDate - creationDate
        return lifespan.days < 365
    
    def _sanitizeRawData(self, rawData: dict[str, Any]) -> dict[str, Any]:
        """Sanitize raw data for storage (convert non-serializable types)."""
        sanitized = {}
        
        for key, value in rawData.items():
            if isinstance(value, datetime):
                sanitized[key] = value.isoformat()
            elif isinstance(value, (list, tuple, set)):
                sanitized[key] = [
                    v.isoformat() if isinstance(v, datetime) else str(v)
                    for v in value
                ]
            elif value is not None:
                try:
                    sanitized[key] = str(value)
                except Exception:
                    sanitized[key] = "<non-serializable>"
        
        return sanitized


# =============================================================================
# Default WHOIS Client (wrapper around python-whois)
# =============================================================================

class DefaultWhoisClient:
    """
    Default WHOIS client using python-whois library.
    
    This is a thin wrapper that can be replaced with a mock for testing.
    """
    
    def query(self, domain: str) -> dict[str, Any]:
        """
        Query WHOIS for a domain.
        
        Args:
            domain: Domain name to query
            
        Returns:
            Dictionary with WHOIS data
            
        Raises:
            Exception: On lookup failure
        """
        result = whois.whois(domain)
        
        # Convert whois result to dictionary
        if hasattr(result, "__dict__"):
            return dict(result)
        
        return dict(result) if result else {}


# =============================================================================
# Main WHOIS Lookup Class
# =============================================================================

class WhoisLookup:
    """
    Async WHOIS lookup with retry logic and error handling.
    
    Provides a clean async interface for WHOIS lookups with:
    - Configurable timeouts
    - Automatic retry with exponential backoff
    - Comprehensive error handling
    - Structured result objects
    
    Usage:
        async with WhoisLookup() as lookup:
            result = await lookup.lookup("example.com")
        
        # Or without context manager:
        lookup = WhoisLookup()
        result = await lookup.lookup("example.com")
    
    Attributes:
        timeout: Lookup timeout in seconds
        maxRetries: Maximum retry attempts
        retryDelay: Base delay between retries
        client: WHOIS client implementation
        parser: WHOIS response parser
    """
    
    def __init__(
        self,
        timeout: Optional[int] = None,
        maxRetries: Optional[int] = None,
        retryDelay: Optional[float] = None,
        client: Optional[WhoisClientProtocol] = None,
        parser: Optional[WhoisParserProtocol] = None,
    ):
        """
        Initialize WHOIS lookup service.
        
        Args:
            timeout: Lookup timeout in seconds (default from settings)
            maxRetries: Max retry attempts (default from settings)
            retryDelay: Delay between retries (default from settings)
            client: Custom WHOIS client (for testing)
            parser: Custom response parser (for testing)
        """
        self.timeout = timeout or settings.whoisTimeout
        self.maxRetries = maxRetries if maxRetries is not None else settings.maxRetries
        self.retryDelay = retryDelay or settings.retryDelaySeconds
        
        self.client = client or DefaultWhoisClient()
        self.parser = parser or WhoisParser()
    
    async def __aenter__(self) -> "WhoisLookup":
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, excType, excVal, excTb) -> None:
        """Async context manager exit."""
        pass
    
    async def lookup(self, domain: str) -> WhoisResult:
        """
        Perform async WHOIS lookup for a domain.
        
        Args:
            domain: Domain name to query (e.g., "example.com")
            
        Returns:
            WhoisResult with lookup data and status
            
        Note:
            This method never raises exceptions. Errors are captured
            in the result's status and errorMessage fields.
        """
        startTime = time.perf_counter()
        domain = self._normalizeDomain(domain)
        
        # Validate domain is not empty
        if not domain:
            return self._createErrorResult(
                domain or "unknown",
                LookupStatus.ERROR,
                "Domain cannot be empty",
                startTime
            )
        
        logger.info(f"Starting WHOIS lookup for: {domain}")
        
        for attempt in range(self.maxRetries + 1):
            try:
                result = await self._lookupWithTimeout(domain)
                result.durationMs = (time.perf_counter() - startTime) * 1000
                
                logger.info(
                    f"WHOIS lookup successful for {domain} "
                    f"(attempt {attempt + 1}, {result.durationMs:.0f}ms)"
                )
                return result
                
            except WhoisTimeoutError as e:
                logger.warning(f"WHOIS timeout for {domain} (attempt {attempt + 1})")
                if attempt < self.maxRetries:
                    await self._sleepWithBackoff(attempt)
                else:
                    return self._createErrorResult(
                        domain, LookupStatus.TIMEOUT, str(e), startTime
                    )
                    
            except WhoisNotFoundError as e:
                logger.info(f"Domain not found in WHOIS: {domain}")
                return self._createErrorResult(
                    domain, LookupStatus.NOT_FOUND, str(e), startTime
                )
                
            except Exception as e:
                logger.error(f"WHOIS error for {domain}: {e}")
                if attempt < self.maxRetries:
                    await self._sleepWithBackoff(attempt)
                else:
                    return self._createErrorResult(
                        domain, LookupStatus.ERROR, str(e), startTime
                    )
        
        # Should not reach here, but just in case
        return self._createErrorResult(
            domain, LookupStatus.ERROR, "Max retries exceeded", startTime
        )
    
    async def _lookupWithTimeout(self, domain: str) -> WhoisResult:
        """
        Execute WHOIS lookup with timeout.
        
        Args:
            domain: Domain to query
            
        Returns:
            WhoisResult on success
            
        Raises:
            WhoisTimeoutError: On timeout
            WhoisNotFoundError: If domain not found
            WhoisParseError: If response cannot be parsed
        """
        try:
            # Run synchronous whois query in thread pool
            rawData = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None,
                    self.client.query,
                    domain
                ),
                timeout=self.timeout
            )
            
            # Check if domain was found
            if not rawData or (
                not rawData.get("domain_name") and 
                not rawData.get("creation_date")
            ):
                raise WhoisNotFoundError(domain, "Domain not found in WHOIS database")
            
            # Parse the response
            return self.parser.parse(domain, rawData)
            
        except asyncio.TimeoutError:
            raise WhoisTimeoutError(domain, f"Timeout after {self.timeout}s")
    
    async def _sleepWithBackoff(self, attempt: int) -> None:
        """Sleep with exponential backoff."""
        delay = self.retryDelay * (2 ** attempt)
        logger.debug(f"Retrying in {delay:.1f}s...")
        await asyncio.sleep(delay)
    
    def _normalizeDomain(self, domain: str) -> str:
        """
        Normalize domain name for WHOIS lookup.
        
        Removes protocol, path, and converts to lowercase.
        
        Args:
            domain: Input domain or URL
            
        Returns:
            Normalized domain name
        """
        domain = domain.lower().strip()
        
        # Remove protocol
        for prefix in ["https://", "http://", "www."]:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        
        # Remove path and query string
        domain = domain.split("/")[0]
        domain = domain.split("?")[0]
        domain = domain.split("#")[0]
        
        # Remove port
        domain = domain.split(":")[0]
        
        return domain
    
    def _createErrorResult(
        self,
        domain: str,
        status: LookupStatus,
        errorMessage: str,
        startTime: float
    ) -> WhoisResult:
        """Create error result with timing information."""
        durationMs = (time.perf_counter() - startTime) * 1000
        
        # Use placeholder for empty domain to satisfy validation
        safeDomain = domain if domain else "unknown"
        
        return WhoisResult(
            source=DataSource.WHOIS,
            status=status,
            domain=safeDomain,
            durationMs=durationMs,
            errorMessage=errorMessage,
        )


# =============================================================================
# Convenience Function
# =============================================================================

async def lookupWhois(domain: str) -> WhoisResult:
    """
    Convenience function for one-off WHOIS lookups.
    
    Args:
        domain: Domain name to query
        
    Returns:
        WhoisResult with lookup data
    
    Example:
        result = await lookupWhois("example.com")
        print(f"Domain age: {result.domainAgeDays} days")
    """
    async with WhoisLookup() as lookup:
        return await lookup.lookup(domain)
