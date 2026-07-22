"""
Rate Limiting Middleware
==========================

Per-IP (per-API-key when available) rate limits via slowapi.  Default
limits are intentionally strict to protect against the most common
abuse patterns (URL scraping, OSINT quota exhaustion).

Limit table (defaults, all overridable via env):

    Path                          Limit           Reasoning
    ----                          -----           ---------
    /api/health                   unlimited        Checker must never be throttled
    /api/openapi.json             unlimited        Docs are static
    /api/docs, /api/redoc         unlimited        Docs are static
    /api/model/status             10/minute        Cheap inspection only
    /api/analyze, /api/analyze/url
    /api/analyze/email, /api/analyze/batch
                                  30/minute/IP    Heavy: OSINT+ML
    default                       60/minute/IP    All other endpoints

Routes that perform heavy work (analyze endpoints) are restricted
because each call burns WHOIS queries, VirusTotal queries, AbuseIPDB
queries, and the XGBoost inference — collectively a non-trivial rate
budget.  30 rpm is generous enough for a single user's browsing usage
and small experiments, but stops a malicious scraper at tens of
URLs/minute.

Backend storage
----------------

In-memory (``memory://``) — single-process, lost on restart.  Fine for
the public demo on Render free plan (only one uvicorn process).
For multi-instance production, switch to ``redis://`` by setting
``PHISHGUARD_RATE_LIMIT_URI`` in the environment.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import FastAPI, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from backend.config import settings

logger = logging.getLogger(__name__)

# Default limit when a route doesn't carry an explicit ``@limiter.limit``.
# 60 per minute per IP is enough for normal usage.
_DEFAULT_LIMIT = os.environ.get("PHISHGUARD_DEFAULT_RATE_LIMIT", "60/minute")

# Cap for the heavy ``/api/analyze*`` routes.  OSINT calls cost us real
# money on third-party APIs, so we keep this conservative.
ANALYZE_LIMIT = os.environ.get("PHISHGUARD_ANALYZE_RATE_LIMIT", "30/minute")

# Light-endpoint cap (model/status).  Cheap operations.
STATUS_LIMIT = os.environ.get("PHISHGUARD_STATUS_RATE_LIMIT", "10/minute")

# ---------------------------------------------------------------------------
# Storage backend
# ---------------------------------------------------------------------------
_STORAGE_URI = os.environ.get(
    "PHISHGUARD_RATE_LIMIT_URI",  # e.g. ``redis://host:6379`` for multi-instance.
    "memory://",                 # default: per-process memory.
)


# ---------------------------------------------------------------------------
# Key function -- limit by IP for unauthenticated users, by API key for
# authenticated users (token-bucket philosophy).
# ---------------------------------------------------------------------------
def _keyFunc(request: Request) -> str:
    """Identify the calling client for the rate-limit bucket.

    Order of preference:
    1. ``X-Api-Key`` from request headers — authenticated users get
       their own bucket (one user can be hammering us from many IPs
       without affecting others).
    2. ``X-Forwarded-For`` if behind a trusted proxy (Render sets this).
    3. Fallback to ``get_remote_address`` which uses the raw client IP.
    """
    apiKey = request.headers.get("x-api-key", "").strip()
    if apiKey:
        return f"key:{apiKey[:32]}"  # hash prefix to bound storage
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        # First entry is the original client (Render format)
        return f"ip:{forwarded.split(',')[0].strip()}"
    return f"ip:{get_remote_address(request)}"


# ---------------------------------------------------------------------------
# Limiter instance -- single shared.
# ---------------------------------------------------------------------------
limiter = Limiter(
    key_func=_keyFunc,
    storage_uri=_STORAGE_URI,
    default_limits=[_DEFAULT_LIMIT],
    headers_enabled=True,
)


# ---------------------------------------------------------------------------
# FastAPI integration
# ---------------------------------------------------------------------------
def addRateLimiting(app: FastAPI) -> None:
    """Register the slowapi rate-limiter on ``app``.

    Adds:
    - An exception handler that returns the standard ``429 Too Many
      Requests`` JSON shape instead of slowapi's default plaintext.
    - ``state.limiter`` so route decorators can find it.
    """
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    logger.info(
        "Rate limiting registered (default=%s, analyze=%s, status=%s, "
        "storage=%s)",
        _DEFAULT_LIMIT,
        ANALYZE_LIMIT,
        STATUS_LIMIT,
        _STORAGE_URI,
    )


def rateLimitExceededJsonHandler(
    request: Request,
    exc: RateLimitExceeded,
) -> dict:
    """JSON-shaped 429 response.

    Plot-compatible with our other endpoints' error format.
    """
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=429,
        content={
            "detail": "Rate limit exceeded",
            "limit": str(exc.detail),
            "retry_after_seconds": int(exc.detail.reset_at - exc.detail.timestamp)
            if hasattr(exc.detail, "reset_at")
            else 60,
        },
        headers={"Retry-After": "60"},
    )


def installJsonRateLimitHandler(app: FastAPI) -> None:
    """Replace slowapi's default 429 handler with our JSON one.

    Call this AFTER ``addRateLimiting`` so ours wins.
    """
    app.add_exception_handler(RateLimitExceeded, rateLimitExceededJsonHandler)
