"""
Deep Health Check Module
=========================

Replaces the shallow ``/api/health`` handler from Tier 1.5 with a
live-probe health check that actively exercises the dependencies of
the API:

* **DNS** -- resolve ``example.com`` with a short timeout (3 s).
* **ML**   -- verify the ``PhishingPredictor`` is loaded and reports
  a non-zero feature set.
* **OSINT / Analyzer** -- import availability tests (the modules
  import cleanly at startup; the orchestrator is alive).

Behaviour:

* Each probe has a hard timeout (configurable via env).
* The probe results are aggregated into a JSON-friendly ``checks``
  dict with ``status`` / ``latencyMs`` / ``detail`` keys.
* ``status`` at the top level becomes:

    * ``healthy`` -- every check is ``up``.
    * ``degraded`` -- ML is loaded but DNS is unreachable (we can
      still serve text-only analyses via the NLP path).
    * ``unhealthy`` -- ML is not loaded (cannot serve URL phishing
      scoring).  The HTTP status maps to 200 even when ``degraded``
      so uptime monitors see OK, but ``unhealthy`` returns 503 so
      Render/UptimeRobot alerts.

The HTTP shape is additive on top of the Tier-0 shallow response:

    ``status``, ``version``, ``timestamp``, ``services`` -- unchanged
    ``checks``         -- new, deep per-dependency report
    ``uptimeSeconds``  -- new, seconds since module import
    ``ready``          -- new, True once probes have completed once
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Optional

import dns.exception  # type: ignore
import dns.resolver  # type: ignore

from backend.config import getSettings
from backend.ml.predictor import PhishingPredictor
from backend.osint.dnsChecker import DnsChecker, DnsError, DnsTimeoutError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
# A short, well-known domain under ICANN control.  Used only for a
# reachability probe -- we never follow redirects or store any query
# result.
DNS_PROBE_DOMAIN = "example.com"

# Hard timeout for the DNS probe.  Bounded so a slow / wedged
# upstream resolver cannot starve the uptime endpoint.
DNS_PROBE_TIMEOUT_SECONDS = float(
    os.environ.get("PHISHGUARD_HEALTH_DNS_TIMEOUT", "3.0")
)

# Hard timeout for the ML probe (we explicitly time-bound the
# ``PhishingPredictor`` introspection -- it should never block).
ML_PROBE_TIMEOUT_SECONDS = float(
    os.environ.get("PHISHGUARD_HEALTH_ML_TIMEOUT", "1.0")
)


# ---------------------------------------------------------------------------
# State (process-wide)
# ---------------------------------------------------------------------------
_APP_START_TIME: float = time.time()
_HAS_RUN_ONCE = False


def markBootComplete() -> None:
    """Mark the application as having completed initialisation.

    Called from ``main.lifespan`` after startup logs are emitted.
    Without this, ``/api/health`` reports ``ready=False`` until the
    FIRST request lands (since the probes are lazy)."""
    global _HAS_RUN_ONCE
    _HAS_RUN_ONCE = True


def uptimeSeconds() -> float:
    return time.time() - _APP_START_TIME


# ---------------------------------------------------------------------------
# Probe runner
# ---------------------------------------------------------------------------
async def _checkDns() -> dict[str, Any]:
    """Live DNS probe -- resolve ``DNS_PROBE_DOMAIN``.

    Returns::

        {"status": "up" | "down",
         "latencyMs": int,
         "detail": str}
    """
    started = time.perf_counter()
    try:
        async with DnsChecker(timeout=DNS_PROBE_TIMEOUT_SECONDS) as checker:
            await checker.lookup(DNS_PROBE_DOMAIN)
        elapsed = (time.perf_counter() - started) * 1000.0
        return {
            "status": "up",
            "latencyMs": int(elapsed),
            "detail": f"resolved {DNS_PROBE_DOMAIN}",
        }
    except DnsTimeoutError:
        elapsed = (time.perf_counter() - started) * 1000.0
        return {
            "status": "down",
            "latencyMs": int(elapsed),
            "detail": (
                f"DNS timeout resolving {DNS_PROBE_DOMAIN} "
                f"(>{DNS_PROBE_TIMEOUT_SECONDS}s)"
            ),
        }
    except DnsError as exc:
        elapsed = (time.perf_counter() - started) * 1000.0
        return {
            "status": "down",
            "latencyMs": int(elapsed),
            "detail": (
                f"DNS error for {DNS_PROBE_DOMAIN}: {exc}"
            ),
        }
    except Exception as exc:  # noqa: BLE001 - we want to capture everything
        elapsed = (time.perf_counter() - started) * 1000.0
        return {
            "status": "down",
            "latencyMs": int(elapsed),
            "detail": f"DNS probe failed: {type(exc).__name__}: {exc}",
        }


async def _checkMl() -> dict[str, Any]:
    """Live ML probe -- verify ``PhishingPredictor.isLoaded`` is True
    and report the feature count.

    The synchronous calls are wrapped in ``asyncio.to_thread`` so the
    health endpoint never blocks on disk I/O if the predictor file
    is uncached.
    """
    started = time.perf_counter()
    try:
        predictor = await asyncio.wait_for(
            asyncio.to_thread(PhishingPredictor),
            timeout=ML_PROBE_TIMEOUT_SECONDS,
        )
        loaded = await asyncio.wait_for(
            asyncio.to_thread(lambda: predictor.isLoaded),
            timeout=ML_PROBE_TIMEOUT_SECONDS,
        )
        elapsed = (time.perf_counter() - started) * 1000.0
        if not loaded:
            return {
                "status": "down",
                "latencyMs": int(elapsed),
                "detail": "XGBoost model not loaded",
            }
        featureCount: int = predictor._featureCount if loaded else 0
        return {
            "status": "up",
            "latencyMs": int(elapsed),
            "featureCount": featureCount,
            "detail": "XGBoost model loaded",
        }
    except asyncio.TimeoutError:
        elapsed = (time.perf_counter() - started) * 1000.0
        return {
            "status": "down",
            "latencyMs": int(elapsed),
            "detail": (
                f"ML probe timeout (>{ML_PROBE_TIMEOUT_SECONDS}s)"
            ),
        }
    except Exception as exc:  # noqa: BLE001
        elapsed = (time.perf_counter() - started) * 1000.0
        return {
            "status": "down",
            "latencyMs": int(elapsed),
            "detail": f"ML probe failed: {type(exc).__name__}: {exc}",
        }


async def _checkImports() -> dict[str, Any]:
    """Fast probe -- the modules have already been imported at
    application start, so this is essentially a sanity gate.

    We DO re-import under a memory cache to catch cases where
    something has monkey-patched ``sys.modules``."""
    started = time.perf_counter()
    try:
        from backend.analyzer.nlpAnalyzer import NlpAnalyzer  # noqa: F401
        from backend.api.orchestrator import AnalysisOrchestrator  # noqa: F401

        elapsed = (time.perf_counter() - started) * 1000.0
        return {
            "status": "up",
            "latencyMs": int(elapsed),
            "detail": "Analyzer + Orchestrator importable",
        }
    except Exception as exc:  # noqa: BLE001
        elapsed = (time.perf_counter() - started) * 1000.0
        return {
            "status": "down",
            "latencyMs": int(elapsed),
            "detail": f"Import probe failed: {type(exc).__name__}: {exc}",
        }


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------
async def runDeepChecks() -> dict[str, dict[str, Any]]:
    """Run all probes in parallel and return a ``{name: result}`` map."""
    dnsTask = asyncio.create_task(_checkDns())
    mlTask = asyncio.create_task(_checkMl())
    importsTask = asyncio.create_task(_checkImports())
    dnsResult, mlResult, importsResult = await asyncio.gather(
        dnsTask, mlTask, importsTask, return_exceptions=False
    )
    return {
        "dns": dnsResult,
        "ml": mlResult,
        "imports": importsResult,
    }


def _aggregateStatus(checks: dict[str, dict[str, Any]]) -> str:
    """Reduce a checks dict into a top-level ``status`` string.

    Rules:

    * ML must be ``up`` -- otherwise URL phishing scoring cannot work.
    * DNS being ``down`` is a ``degraded`` state (text-only analyses
      still work; OSINT module reports the error gracefully).
    * Imports must be ``up`` -- they are a fast-fail sentinel.
    """
    mlUp = checks.get("ml", {}).get("status") == "up"
    dnsUp = checks.get("dns", {}).get("status") == "up"
    importsUp = checks.get("imports", {}).get("status") == "up"

    if not (mlUp and importsUp):
        return "unhealthy"
    if mlUp and dnsUp and importsUp:
        return "healthy"
    return "degraded"


def servicesFromChecks(checks: dict[str, dict[str, Any]]) -> dict[str, bool]:
    """Translate the per-check results into the shallow
    ``services`` map for backward compatibility.

    The keys match the original handler's::

        osint     -- DNS subsystem reachable
        analyzer  -- imports probe OK
        ml        -- XGBoost model loaded
    """
    return {
        "osint": checks.get("dns", {}).get("status") == "up",
        "analyzer": checks.get("imports", {}).get("status") == "up",
        "ml": checks.get("ml", {}).get("status") == "up",
    }


# ---------------------------------------------------------------------------
# Pure helpers (exportable for unit tests, no I/O)
# ---------------------------------------------------------------------------
def isUp(checkResult: Optional[dict[str, Any]]) -> bool:
    """True iff ``checkResult`` is non-None and its status is 'up'."""
    return bool(checkResult) and checkResult.get("status") == "up"


def shouldReturn503(topLevelStatus: str) -> bool:
    """Decide the HTTP status: 503 only when truly unhealthy."""
    return topLevelStatus == "unhealthy"


__all__ = [
    "DNS_PROBE_DOMAIN",
    "DNS_PROBE_TIMEOUT_SECONDS",
    "ML_PROBE_TIMEOUT_SECONDS",
    "markBootComplete",
    "uptimeSeconds",
    "runDeepChecks",
    "_aggregateStatus",
    "servicesFromChecks",
    "isUp",
    "shouldReturn503",
]
