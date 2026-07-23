"""
Unit tests for the Tier 1.6 liveness/readiness split.

Customers

* ``livenessHandler`` returns the canonical ``alive`` payload and
  never raises even when first called immediately after import.
* ``livenessHandler`` does not await ``runDeepChecks`` -- tested by
  ensuring it does not block on DNS, the metric we care about.
* ``readinessHandler`` delegates to ``runDeepChecks`` and applies
  the same 503-on-unhealthy logic as the legacy ``/api/health``.
* ``registerHealthEndpoints`` is idempotent: running it twice on
  different apps doesn't throw.
* ``APP_VERSION`` is a non-empty string.
"""

from __future__ import annotations

import asyncio
import time

import pytest

import backend.health as health_mod


# ---------------------------------------------------------------------------
# APP_VERSION
# ---------------------------------------------------------------------------
def test_appVersionIsNonEmptyString():
    assert isinstance(health_mod.APP_VERSION, str)
    assert health_mod.APP_VERSION.strip()


def test_appVersionFollowsSemverShape():
    """Two-or-three-segment numeric version."""
    parts = health_mod.APP_VERSION.split(".")
    assert 2 <= len(parts) <= 3, (
        f"APP_VERSION must be semver-ish, got {health_mod.APP_VERSION!r}"
    )
    for part in parts:
        assert part.isdigit(), (
            f"version segment {part!r} is not numeric"
        )


# ---------------------------------------------------------------------------
# livenessHandler
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_livenessHandler_returnsAlivePayload():
    result = await health_mod.livenessHandler()
    assert result["status"] == "alive"
    assert "uptimeSeconds" in result
    assert isinstance(result["uptimeSeconds"], (int, float))
    assert result["uptimeSeconds"] >= 0.0


@pytest.mark.asyncio
async def test_livenessHandler_isSyncFast():
    """The handler completes in milliseconds (<0.05 s)."""
    started = time.perf_counter()
    await health_mod.livenessHandler()
    elapsed = time.perf_counter() - started
    assert elapsed < 0.05, (
        f"livenessHandler took {elapsed * 1000:.1f} ms; must be near-instant"
    )


@pytest.mark.asyncio
async def test_livenessHandler_doesNotCallRunDeepChecks(monkeypatch):
    """Spy on ``runDeepChecks`` and verify it's NOT invoked."""
    sentinel = {"calls": 0}

    async def _spy():
        sentinel["calls"] += 1
        return {"dns": {"status": "up"}, "ml": {"status": "up"}, "imports": {"status": "up"}}

    monkeypatch.setattr(health_mod, "runDeepChecks", _spy)
    await health_mod.livenessHandler()
    assert sentinel["calls"] == 0, (
        "livenessHandler must NEVER trigger deep probes"
    )


# ---------------------------------------------------------------------------
# readinessHandler
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_readinessHandler_returnsDeepChecksShape():
    """The handler emits the same envelope as ``/api/health``."""
    from starlette.responses import Response as StarletteResponse

    # The handler expects a FastAPI-style Response so it can flip 503.
    # We synthesise one with the same API.
    inner = StarletteResponse()
    # StarletteResponse default status code is 200 -- assert that
    # behaviour here so the test surface mirrors the production
    # invocation pattern.
    assert inner.status_code == 200

    # Now invoke the readiness handler.
    body = await health_mod.readinessHandler(inner)
    assert body["status"] in {"healthy", "degraded", "unhealthy"}
    assert "checks" in body
    assert "services" in body
    assert body["ready"] is True
    assert "uptimeSeconds" in body


@pytest.mark.asyncio
async def test_readinessHandler_flipsTo503WhenUnhealthy(monkeypatch):
    """An unhealthy aggregated status flips HTTP code to 503."""
    from starlette.responses import Response as StarletteResponse

    inner = StarletteResponse()

    async def _allUp():
        return {
            "dns": {"status": "up"},
            "ml": {"status": "down"},
            "imports": {"status": "up"},
        }

    monkeypatch.setattr(health_mod, "runDeepChecks", _allUp)
    body = await health_mod.readinessHandler(inner)
    assert body["status"] == "unhealthy"
    assert inner.status_code == 503


@pytest.mark.asyncio
async def test_readinessHandler_keeps200WhenDegraded(monkeypatch):
    """Degraded states do NOT flip to 503."""
    from starlette.responses import Response as StarletteResponse

    inner = StarletteResponse()

    async def _dnsDown():
        return {
            "dns": {"status": "down"},
            "ml": {"status": "up"},
            "imports": {"status": "up"},
        }

    monkeypatch.setattr(health_mod, "runDeepChecks", _dnsDown)
    body = await health_mod.readinessHandler(inner)
    assert body["status"] == "degraded"
    assert inner.status_code == 200


@pytest.mark.asyncio
async def test_readinessHandler_keeps200WhenHealthy(monkeypatch):
    from starlette.responses import Response as StarletteResponse

    inner = StarletteResponse()

    async def _allUp():
        return {
            "dns": {"status": "up"},
            "ml": {"status": "up"},
            "imports": {"status": "up"},
        }

    monkeypatch.setattr(health_mod, "runDeepChecks", _allUp)
    body = await health_mod.readinessHandler(inner)
    assert body["status"] == "healthy"
    assert inner.status_code == 200


# ---------------------------------------------------------------------------
# registerHealthEndpoints
# ---------------------------------------------------------------------------
def test_registerHealthEndpoints_isCallable():
    assert callable(health_mod.registerHealthEndpoints)


def test_registerHealthEndpoints_doesNotRaiseOnFreshApp():
    from fastapi import FastAPI

    app = FastAPI()
    health_mod.registerHealthEndpoints(app)
    # Second call should also not raise (new app), confirming the
    # function is idempotent across distinct apps.
    health_mod.registerHealthEndpoints(FastAPI())


def test_registerHealthEndpoints_appendsExpectedRoutes():
    """The registered router contains ``/live``, ``/ready``, and the
    bare ``/api/health`` (alias) paths."""
    from fastapi import FastAPI

    app = FastAPI()
    health_mod.registerHealthEndpoints(app)
    paths = {route.path for route in app.routes}
    assert "/api/health/live" in paths
    assert "/api/health/ready" in paths
    assert "/api/health" in paths
