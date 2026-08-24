"""
Unit Tests for batch concurrency bound and reputation result cache
===================================================================

Regression tests for the deep-review findings (2026-08):

- The batch orchestrator used an unbounded ``asyncio.gather``: a 50-item
  batch meant ~150 concurrent outbound OSINT requests on a free-tier
  instance.
- Reputation lookups had no cache: VirusTotal's free tier allows ~4
  requests/minute, so repeated analyses of the same domain burned the
  quota and silently lost the source.
"""

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from backend.api.orchestrator import (
    AnalysisOrchestrator,
    BATCH_CONCURRENCY,
)
from backend.osint import reputationChecker as rc
from backend.osint.schemas import DataSource
from backend.osint.reputationChecker import lookupReputationCached


# =============================================================================
# Batch concurrency
# =============================================================================

class TestBatchConcurrencyBound:
    """Batch items must not all run at once."""

    @pytest.mark.asyncio
    async def test_concurrency_never_exceeds_limit(self):
        orchestrator = AnalysisOrchestrator()
        inFlight = 0
        peak = 0

        async def fakeAnalyze(content, contentType):
            nonlocal inFlight, peak
            inFlight += 1
            peak = max(peak, inFlight)
            await asyncio.sleep(0.05)
            inFlight -= 1
            # Minimal AnalysisResponse-shaped object; the batch runner
            # only passes it through.
            return object()

        items = [
            SimpleNamespace(type="text", url=None, content=f"item {i}",
                            subject=None, sender=None)
            for i in range(BATCH_CONCURRENCY * 3)
        ]

        with patch.object(orchestrator, "analyze", side_effect=fakeAnalyze):
            _, succeeded, failed = await orchestrator.analyzeBatch(items)

        assert peak <= BATCH_CONCURRENCY, (
            f"peak concurrency {peak} exceeded the bound {BATCH_CONCURRENCY}"
        )
        assert succeeded == len(items)
        assert failed == 0


# =============================================================================
# Reputation cache
# =============================================================================

class TestReputationCache:
    """Repeated lookups within the TTL must not re-hit the provider."""

    @pytest.mark.asyncio
    async def test_second_lookup_served_from_cache(self):
        calls = {"n": 0}

        def makeResult(status):
            return rc.ReputationResult(
                source=DataSource.REPUTATION,
                status=status,
                domain="example.com",
                durationMs=1.0,
                checks=[],
                aggregateScore=0.0,
                knownMalicious=False,
                categories=[],
            )

        async def fakeLookup(domain, ipAddresses=None, timeout=None):
            calls["n"] += 1
            return makeResult(rc.LookupStatus.SUCCESS)

        rc._REPUTATION_CACHE.clear()
        with patch.object(rc, "lookupReputation", side_effect=fakeLookup):
            r1 = await lookupReputationCached("cached.example")
            r2 = await lookupReputationCached("cached.example")

        assert calls["n"] == 1, "second lookup should be a cache hit"
        assert r1 is r2
        rc._REPUTATION_CACHE.clear()

    @pytest.mark.asyncio
    async def test_failures_are_not_cached(self):
        calls = {"n": 0}

        def makeResult(status):
            return rc.ReputationResult(
                source=DataSource.REPUTATION,
                status=status,
                domain="flaky.example",
                durationMs=1.0,
                checks=[],
                aggregateScore=0.0,
                knownMalicious=False,
                categories=[],
            )

        async def fakeLookup(domain, ipAddresses=None, timeout=None):
            calls["n"] += 1
            return makeResult(rc.LookupStatus.TIMEOUT)

        rc._REPUTATION_CACHE.clear()
        with patch.object(rc, "lookupReputation", side_effect=fakeLookup):
            await lookupReputationCached("flaky.example")
            await lookupReputationCached("flaky.example")

        assert calls["n"] == 2, "failed lookups must be retried, not cached"
        rc._REPUTATION_CACHE.clear()
