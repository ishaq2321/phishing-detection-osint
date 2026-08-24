"""
Unit Tests for OSINT collection semantics
==========================================

Regression tests for the OSINT data-loss incident (2026-08):

The original implementation wrapped the three parallel lookups in
``asyncio.wait_for(gather(...), 15)``. When ONE source exceeded the
budget, the whole gather was cancelled and *already-finished* sibling
results were discarded — even github.com lost all OSINT data because a
flaky DNS record type stretched past 15 s while WHOIS had finished in
<1 s.

The fix keeps sources that finish within the global budget and cancels
only the stragglers, with a configurable budget (OSINT_TIMEOUT).
"""

import asyncio
import time
from unittest.mock import patch

import pytest

from backend.api.orchestrator import AnalysisOrchestrator
from backend.config import settings
from backend.osint import (
    DataSource,
    DnsChecker,
    DnsRecordType,
    DnsResult,
    LookupStatus,
    ReputationResult,
    WhoisResult,
)


# =============================================================================
# Fixtures
# =============================================================================

def makeWhoisResult(status=LookupStatus.SUCCESS):
    return WhoisResult(
        source=DataSource.WHOIS,
        status=status,
        domain="github.com",
        durationMs=100.0,
        registrar="MarkMonitor, Inc.",
        domainAgeDays=6893,
    )


def makeDnsResult(status=LookupStatus.SUCCESS):
    return DnsResult(
        source=DataSource.DNS,
        status=status,
        domain="github.com",
        durationMs=50.0,
        ipAddresses=["140.82.121.4"],
    )


def makeReputationResult(status=LookupStatus.SUCCESS):
    return ReputationResult(
        source=DataSource.REPUTATION,
        status=status,
        domain="github.com",
        durationMs=30.0,
        checks=[],
        aggregateScore=0.1,
        knownMalicious=False,
        categories=[],
    )


@pytest.fixture
def orchestrator():
    return AnalysisOrchestrator()


# =============================================================================
# Collection semantics — the data-loss regressions
# =============================================================================

class TestCollectOsintDataSemantics:
    """A slow source must not discard finished sibling results."""

    @pytest.mark.asyncio
    async def test_slow_dns_keeps_finished_whois_and_reputation(
        self, orchestrator, monkeypatch
    ):
        """THE regression: github.com lost all OSINT data because slow DNS
        tripped the global cancel. WHOIS (0.9s) and reputation (0.03s) were
        already complete and must survive."""
        async def slowDns(domain):
            await asyncio.sleep(30)
            return makeDnsResult()

        async def fastWhois(domain):
            await asyncio.sleep(0.05)
            return makeWhoisResult()

        async def fastReputation(domain):
            await asyncio.sleep(0.05)
            return makeReputationResult()

        monkeypatch.setattr(settings, "osintTimeout", 1)
        with patch(
            "backend.api.orchestrator.lookupWhois", side_effect=fastWhois
        ), patch(
            "backend.api.orchestrator.lookupDns", side_effect=slowDns
        ), patch(
            "backend.api.orchestrator.lookupReputationCached",
            side_effect=fastReputation,
        ):
            t0 = time.perf_counter()
            data = await orchestrator._collectOsintData("github.com", "https://github.com")
            elapsed = time.perf_counter() - t0

        assert data is not None
        assert data.whois is not None, "finished WHOIS was discarded"
        assert data.reputation is not None, "finished reputation was discarded"
        assert data.dns is None, "slow DNS should be the only casualty"
        assert elapsed < 5, f"collection took {elapsed:.1f}s — budget not enforced"

    @pytest.mark.asyncio
    async def test_all_sources_slow_returns_empty_within_budget(
        self, orchestrator, monkeypatch
    ):
        """When nothing finishes in time the result is empty but the call
        is bounded by the budget (not hung forever)."""
        async def hang(domain):
            await asyncio.sleep(60)

        monkeypatch.setattr(settings, "osintTimeout", 1)
        with patch(
            "backend.api.orchestrator.lookupWhois", side_effect=hang
        ), patch(
            "backend.api.orchestrator.lookupDns", side_effect=hang
        ), patch(
            "backend.api.orchestrator.lookupReputationCached", side_effect=hang
        ):
            t0 = time.perf_counter()
            data = await orchestrator._collectOsintData("slow.example", "https://slow.example")
            elapsed = time.perf_counter() - t0

        assert data is not None
        assert data.whois is None and data.dns is None and data.reputation is None
        assert elapsed < 5

    @pytest.mark.asyncio
    async def test_raising_source_does_not_poison_siblings(
        self, orchestrator, monkeypatch
    ):
        """An exception in one lookup must not affect the others."""
        async def boom(domain):
            raise RuntimeError("whois server exploded")

        async def fastDns(domain):
            return makeDnsResult()

        async def fastReputation(domain):
            return makeReputationResult()

        monkeypatch.setattr(settings, "osintTimeout", 5)
        with patch(
            "backend.api.orchestrator.lookupWhois", side_effect=boom
        ), patch(
            "backend.api.orchestrator.lookupDns", side_effect=fastDns
        ), patch(
            "backend.api.orchestrator.lookupReputationCached",
            side_effect=fastReputation,
        ):
            data = await orchestrator._collectOsintData("example.com", "https://example.com")

        assert data is not None
        assert data.whois is None
        assert data.dns is not None
        assert data.reputation is not None

    @pytest.mark.asyncio
    async def test_non_success_status_is_dropped(self, orchestrator, monkeypatch):
        """A source that finishes but reports NOT_FOUND yields None for
        that field only."""
        async def notFoundWhois(domain):
            return makeWhoisResult(status=LookupStatus.NOT_FOUND)

        async def fastDns(domain):
            return makeDnsResult()

        async def fastReputation(domain):
            return makeReputationResult()

        monkeypatch.setattr(settings, "osintTimeout", 5)
        with patch(
            "backend.api.orchestrator.lookupWhois", side_effect=notFoundWhois
        ), patch(
            "backend.api.orchestrator.lookupDns", side_effect=fastDns
        ), patch(
            "backend.api.orchestrator.lookupReputationCached",
            side_effect=fastReputation,
        ):
            data = await orchestrator._collectOsintData("example.com", "https://example.com")

        assert data.whois is None
        assert data.dns is not None


# =============================================================================
# DNS per-record-type deadline
# =============================================================================

class TestDnsPerTypeDeadline:
    """One flaky record type (resolvers often drop TXT/MX) must not
    stretch the whole DNS lookup — the second layer of the incident."""

    @pytest.mark.asyncio
    async def test_hanging_record_type_is_abandoned(self):
        class HangingForTxtResolver:
            """Resolver that hangs forever on TXT, instant otherwise."""

            def __init__(self):
                self.timeout = 0.5
                self.lifetime = 0.5

            def resolve(self, domain, recordType):
                if recordType == DnsRecordType.TXT or recordType == "TXT":
                    time.sleep(30)
                return [{"value": "93.184.216.34", "ttl": 300}]

        checker = DnsChecker(
            timeout=0.5,
            resolver=HangingForTxtResolver(),
            maxRetries=3,
            retryDelay=0.05,
        )

        t0 = time.perf_counter()
        result = await checker.lookup("example.com")
        elapsed = time.perf_counter() - t0

        # 6 record types, worst one capped at 2x timeout = 1s (retries
        # happen inside the same deadline), so the lookup must finish
        # well under the old unbounded behaviour (~23s for 4 TXT attempts).
        assert elapsed < 6, f"DNS lookup took {elapsed:.1f}s — per-type deadline not enforced"
        assert result.status == LookupStatus.SUCCESS
        assert result.ipAddresses, "A records should still resolve"
