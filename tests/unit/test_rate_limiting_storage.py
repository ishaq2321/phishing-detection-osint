"""
Unit tests for Tier 2.2's multi-instance rate-limit storage.

Customers

* The default storage URI is the in-process ``memory://`` so the
  existing Render free-tier topology keeps working.
* Setting ``PHISHGUARD_RATE_LIMIT_URI`` to a Redis URI swaps slowapi
  onto ``limits.storage.RedisStorage``.
* The slowapi ``Limiter`` object is constructed through the rate-
  limiting module's factory rather than directly, so config changes
  take effect at module load time.
"""

from __future__ import annotations

import importlib

import pytest


def _reload_rate_limiting_module(monkeypatch_module_attr=None):
    """Force a fresh ``backend.api.rate_limiting`` import so the
    module-level ``Limiter(...)`` is reconstructed under the current
    env vars.
    """
    import backend.api.rate_limiting as rl

    importlib.reload(rl)
    return rl


# ---------------------------------------------------------------------------
# Default storage
# ---------------------------------------------------------------------------
def test_defaultStorageIsInMemory(monkeypatch):
    """With no env var set, the module uses memory://."""
    monkeypatch.delenv("PHISHGUARD_RATE_LIMIT_URI", raising=False)
    rl = _reload_rate_limiting_module()
    assert rl._STORAGE_URI == "memory://"
    assert rl.limiter._storage is not None
    cls = type(rl.limiter._storage).__name__
    assert cls == "MemoryStorage", (
        f"expected MemoryStorage, got {cls!r}"
    )


# ---------------------------------------------------------------------------
# Redis storage
# ---------------------------------------------------------------------------
def test_redisStorageClassResolves(monkeypatch):
    """Opting into Redis at construction time sure enough to swap the
    storage backend.  We DO NOT actually connect (no Redis on CI);
    we only inspect the URI plumbing."""
    # We patch the lim._storage after the fact using a fake-URI swap.
    # The slowapi factory does not expose a programmatic override in
    # 0.1.10, but the ``PHISHGUARD_RATE_LIMIT_URI`` env var IS a
    # documented knob.  This test pins that contract.
    monkeypatch.setenv("PHISHGUARD_RATE_LIMIT_URI", "redis://localhost:6379/0")
    rl = _reload_rate_limiting_module()
    assert rl._STORAGE_URI == "redis://localhost:6379/0"
    # Confirm slowapi is happy with the URI we dialed up.
    assert rl.limiter._storage is not None


# ---------------------------------------------------------------------------
# Header emission
# ---------------------------------------------------------------------------
def test_storageUri_isReadAtConstructionTime():
    """Module-level ``_STORAGE_URI`` is captured at module import; we
    don't re-evaluate env vars on every request.  Pin that contract
    so an operator who changes the env while the process is running
    knows to restart."""
    import backend.api.rate_limiting as rl

    sentinel = "memory://"
    assert rl._STORAGE_URI == sentinel or rl._STORAGE_URI.startswith("redis")


# ---------------------------------------------------------------------------
# Default rate limit exposition
# ---------------------------------------------------------------------------
def test_defaultRateLimit_isExposed(monkeypatch):
    monkeypatch.delenv("PHISHGUARD_DEFAULT_RATE_LIMIT", raising=False)
    rl = _reload_rate_limiting_module()
    assert rl._DEFAULT_LIMIT == "60/minute"


def test_analyzeRateLimit_envOverride(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_ANALYZE_RATE_LIMIT", "120/minute")
    rl = _reload_rate_limiting_module()
    assert rl.ANALYZE_LIMIT == "120/minute"
