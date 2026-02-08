"""
OSINT Module
============

Open Source Intelligence data collection for phishing detection.

This module provides async interfaces for gathering OSINT data:
- WHOIS lookup (domain registration info)
- DNS resolution (A, AAAA, MX, NS, TXT records)
- Reputation checking (VirusTotal, AbuseIPDB, etc.)

Architecture:
    osint/
    ├── __init__.py      # Public exports
    ├── schemas.py       # Pydantic data models
    ├── whoisLookup.py   # WHOIS lookup service
    ├── dnsChecker.py    # DNS resolution service
    └── reputationChecker.py  # Reputation API integrations

Usage:
    from osint import WhoisLookup, lookupWhois
    from osint.schemas import WhoisResult, OsintData
    
    result = await lookupWhois("example.com")

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from .schemas import (
    DataSource,
    DnsRecord,
    DnsRecordType,
    DnsResult,
    LookupStatus,
    OsintData,
    OsintResult,
    ReputationCheck,
    ReputationResult,
    ReputationSource,
    RiskLevel,
    WhoisContact,
    WhoisResult,
)
from .whoisLookup import (
    DefaultWhoisClient,
    WhoisClientProtocol,
    WhoisError,
    WhoisLookup,
    WhoisNotFoundError,
    WhoisParser,
    WhoisParserProtocol,
    WhoisParseError,
    WhoisTimeoutError,
    lookupWhois,
)
from .dnsChecker import (
    DefaultDnsResolver,
    DnsChecker,
    DnsError,
    DnsNotFoundError,
    DnsResolverProtocol,
    DnsTimeoutError,
    lookupDns,
)
from .reputationChecker import (
    DefaultReputationClient,
    ReputationChecker,
    ReputationClientProtocol,
    ReputationError,
    ReputationApiError,
    ReputationRateLimitError,
    ReputationTimeoutError,
    lookupReputation,
)

__all__ = [
    # Schemas
    "DataSource",
    "DnsRecord",
    "DnsRecordType",
    "DnsResult",
    "LookupStatus",
    "OsintData",
    "OsintResult",
    "ReputationCheck",
    "ReputationResult",
    "ReputationSource",
    "RiskLevel",
    "WhoisContact",
    "WhoisResult",
    # WHOIS
    "DefaultWhoisClient",
    "WhoisClientProtocol",
    "WhoisError",
    "WhoisLookup",
    "WhoisNotFoundError",
    "WhoisParser",
    "WhoisParserProtocol",
    "WhoisParseError",
    "WhoisTimeoutError",
    "lookupWhois",
    # DNS
    "DefaultDnsResolver",
    "DnsChecker",
    "DnsError",
    "DnsNotFoundError",
    "DnsResolverProtocol",
    "DnsTimeoutError",
    "lookupDns",
    # Reputation
    "DefaultReputationClient",
    "ReputationChecker",
    "ReputationClientProtocol",
    "ReputationError",
    "ReputationApiError",
    "ReputationRateLimitError",
    "ReputationTimeoutError",
    "lookupReputation",
]

