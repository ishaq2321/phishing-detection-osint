"""
Unit tests for ``backend.health``.

Customers

* ``markBootComplete`` flips the ``ready`` flag.
* ``uptimeSeconds`` returns a positive number that increases.
* ``_aggregateStatus`` collapses a checks-dict into
  ``healthy | degraded | unhealthy`` according to the documented rules.
* ``servicesFromChecks`` re-derives the legacy ``services`` map.
* ``isUp`` and ``shouldReturn503`` are pure helpers with no I/O.
* The probe timeouts are configurable via env vars.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import time

import pytest

import backend.health as health_mod


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------
def test_isUp_returnsFalseForNone():
    assert health_mod.isUp(None) is False


def test_isUp_returnsTrueForUpDict():
    assert health_mod.isUp({"status": "up", "latencyMs": 5}) is True


def test_isUp_returnsFalseForDownDict():
    assert health_mod.isUp({"status": "down", "latencyMs": 5}) is False


def test_isUp_returnsFalseWhenStatusKeyMissing():
    assert health_mod.isUp({"latencyMs": 5}) is False


def test_shouldReturn503_onlyOnUnhealthy():
    assert health_mod.shouldReturn503("healthy") is False
    assert health_mod.shouldReturn503("degraded") is False
    assert health_mod.shouldReturn503("unhealthy") is True


# ---------------------------------------------------------------------------
# _aggregateStatus
# ---------------------------------------------------------------------------
def test_aggregateStatus_allUp_healthy():
    checks = {
        "dns": {"status": "up"},
        "ml": {"status": "up"},
        "imports": {"status": "up"},
    }
    assert health_mod._aggregateStatus(checks) == "healthy"


def test_aggregateStatus_mlDown_unhealthy():
    """ML down -> unhealthy: URL phishing scoring cannot work."""
    checks = {
        "dns": {"status": "up"},
        "ml": {"status": "down", "detail": "x"},
        "imports": {"status": "up"},
    }
    assert health_mod._aggregateStatus(checks) == "unhealthy"


def test_aggregateStatus_importsDown_unhealthy():
    """Analyzer imports down -> unhealthy: routes cannot import."""
    checks = {
        "dns": {"status": "up"},
        "ml": {"status": "up"},
        "imports": {"status": "down", "detail": "x"},
    }
    assert health_mod._aggregateStatus(checks) == "unhealthy"


def test_aggregateStatus_dnsDown_isDegraded():
    """DNS down with everything else up -> degraded."""
    checks = {
        "dns": {"status": "down", "detail": "x"},
        "ml": {"status": "up"},
        "imports": {"status": "up"},
    }
    assert health_mod._aggregateStatus(checks) == "degraded"


def test_aggregateStatus_emptyChecks_unhealthy():
    """No checks -> conservative unhealthy response."""
    assert health_mod._aggregateStatus({}) == "unhealthy"


def test_aggregateStatus_handlesMissingKeys():
    """Missing keys treated as down."""
    assert health_mod._aggregateStatus({"dns": {"status": "up"}}) == "unhealthy"


# ---------------------------------------------------------------------------
# servicesFromChecks
# ---------------------------------------------------------------------------
def test_servicesFromChecks_allUp():
    checks = {
        "dns": {"status": "up"},
        "ml": {"status": "up"},
        "imports": {"status": "up"},
    }
    services = health_mod.servicesFromChecks(checks)
    assert services == {"osint": True, "analyzer": True, "ml": True}


def test_servicesFromChecks_dnsDown():
    checks = {
        "dns": {"status": "down"},
        "ml": {"status": "up"},
        "imports": {"status": "up"},
    }
    services = health_mod.servicesFromChecks(checks)
    assert services == {"osint": False, "analyzer": True, "ml": True}


def test_servicesFromChecks_mlDown():
    checks = {
        "dns": {"status": "up"},
        "ml": {"status": "down"},
        "imports": {"status": "up"},
    }
    services = health_mod.servicesFromChecks(checks)
    assert services == {"osint": True, "analyzer": True, "ml": False}


# ---------------------------------------------------------------------------
# markBootComplete + uptimeSeconds
# ---------------------------------------------------------------------------
def test_markBootComplete_setsFlag():
    """The flag flips True after ``markBootComplete`` returns."""
    # Reset to a known-false-ish state by reimporting the module in a
    # child mock -- use direct attribute read.
    health_mod._HAS_RUN_ONCE = False
    assert health_mod._HAS_RUN_ONCE is False
    health_mod.markBootComplete()
    assert health_mod._HAS_RUN_ONCE is True


def test_uptimeSeconds_isPositiveAndIncreases():
    a = health_mod.uptimeSeconds()
    time.sleep(0.01)
    b = health_mod.uptimeSeconds()
    assert b >= a
    assert b - a >= 0.005  # at least 5ms passed


# ---------------------------------------------------------------------------
# Module tunables
# ---------------------------------------------------------------------------
def test_dnsProbeDomainIsExampleDotCom():
    """The default probe domain is a stable ICANN-controlled hostname."""
    assert health_mod.DNS_PROBE_DOMAIN == "example.com"


def test_dnsProbeTimeoutDefaultsTo3Seconds():
    """3s is the documented default; overridable via env."""
    assert health_mod.DNS_PROBE_TIMEOUT_SECONDS == 3.0


def test_mlProbeTimeoutDefaultsTo1Second():
    """1s default; the predictor should always respond within that."""
    assert health_mod.ML_PROBE_TIMEOUT_SECONDS == 1.0


# ---------------------------------------------------------------------------
# Probe correctness via mocking (no real DNS / model)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_checkImports_successFast():
    """Imports probe should always succeed (modules import at app start)."""
    result = await health_mod._checkImports()
    assert result["status"] == "up"
    assert "latencyMs" in result
    assert result["latencyMs"] >= 0


@pytest.mark.asyncio
async def test_checkDns_returnsStructuredResult():
    """DNS probe yields a structured dict regardless of outcome."""
    result = await health_mod._checkDns()
    assert isinstance(result, dict)
    assert result["status"] in {"up", "down"}
    assert isinstance(result["latencyMs"], int)
    assert "detail" in result


@pytest.mark.asyncio
async def test_checkMl_returnsStructuredResult():
    """ML probe yields a structured dict regardless of outcome."""
    result = await health_mod._checkMl()
    assert isinstance(result, dict)
    assert result["status"] in {"up", "down"}
    assert isinstance(result["latencyMs"], int)
    assert "detail" in result


@pytest.mark.asyncio
async def test_checkDns_handlesTimeout(monkeypatch):
    """A wedged resolver must produce a 'down' result, not raise."""
    async def _fakeLookup(self, domain):
        raise TimeoutError("simulated wedged resolver")

    # Patch DnsChecker.lookup so we never actually hit a resolver.
    from backend.osint import dnsChecker
    monkeypatch.setattr(dnsChecker.DnsChecker, "lookup", _fakeLookup)

    # With a short probe timeout, the probe should still return {'status': 'down'}.
    monkeypatch.setattr(health_mod, "DNS_PROBE_TIMEOUT_SECONDS", 0.1)
    result = await health_mod._checkDns()
    assert result["status"] == "down"
    assert "latencyMs" in result
    assert result["latencyMs"] >= 0


@pytest.mark.asyncio
async def test_checkMl_handleXGBoostNotLoaded(monkeypatch):
    """A missing model should produce 'down', not crash the endpoint."""

    class _FakeUnloadedPredictor:
        isLoaded = False
        _featureCount = 0

    import asyncio as _asyncio

    def _fakePredictor():
        return _FakeUnloadedPredictor()

    monkeypatch.setattr(health_mod, "PhishingPredictor", _fakePredictor)
    result = await health_mod._checkMl()
    assert result["status"] == "down"
    assert "not loaded" in result["detail"].lower()


@pytest.mark.asyncio
async def test_runDeepChecks_returnsAllThreeChecks():
    """The aggregator must produce dns, ml, imports keys."""
    checks = await health_mod.runDeepChecks()
    assert set(checks.keys()) == {"dns", "ml", "imports"}
    for name, value in checks.items():
        assert "status" in value
        assert value["status"] in {"up", "down"}
