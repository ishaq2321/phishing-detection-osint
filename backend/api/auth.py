"""
Optional API-Key Authentication Middleware
==========================================

Adds a thin shared-secret authentication layer for the heavy analysis
endpoints (``/api/analyze*``).  Behaviour:

* If ``settings.apiKeys`` is non-empty, a valid ``X-Api-Key`` header
  must be present and must hash-equal one of the configured keys.
* If ``settings.apiKeys`` is empty (the default), the middleware is
  a pass-through -- preserves the current public-demo experience
  while letting operators tighten access by setting one env var.

Why middleware (not ``Depends()``)
-----------------------------------

* One place to opt in/out based on a runtime setting.
* Keeps route signatures untouched so existing tests, the orchestrator,
  and the OpenAPI schema do not need to change.
* Symmetrical to ``security_headers.py`` and ``rate_limiting.py``
  registration in ``main.py``.

The X-Api-Key check fires BEFORE the rate-limit hit so an attacker
cannot exhaust the budget by spamming bad keys.  We return 401
first, short-circuiting the chain.

Comparison semantics
--------------------

Configured keys are stored as sha256 hex digests.  Each incoming key
is digested and compared to the set with ``hmac.compare_digest`` so
timing attacks cannot reveal the key byte-by-byte.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Awaitable, Callable, Iterable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from backend.config import getSettings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
HEADER_API_KEY = "x-api-key"
WWW_AUTH_HEADER = "WWW-Authenticate"

# Routes that require X-Api-Key when ``settings.apiKeys`` is set.
# Anything outside this set (``/api/health``, ``/api/model/status``,
# ``/api/history*``, ``/docs``) is always public.
# ``/api/ingest`` is grouped with the analyse routes: it runs the same
# heavy OSINT+ML pipeline and must not be cheaper to abuse.
_PROTECTED_PREFIXES: tuple[str, ...] = (
    "/api/analyze",
    "/api/ingest",
)


# ---------------------------------------------------------------------------
# Helpers (exportable for tests)
# ---------------------------------------------------------------------------
def hashKey(key: str) -> str:
    """Return the sha256 hex digest of ``key``."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def configuredHashes(rawConfig: str | None) -> frozenset[str]:
    """Parse a comma-separated ``rawConfig`` into a frozenset of digests.

    Empty / unset config returns an empty frozenset.
    """
    if not rawConfig or not rawConfig.strip():
        return frozenset()
    return frozenset(
        hashKey(piece)
        for piece in (s.strip() for s in rawConfig.split(","))
        if piece
    )


def isProtected(path: str) -> bool:
    return any(path.startswith(p) for p in _PROTECTED_PREFIXES)


def unauthorized(message: str) -> JSONResponse:
    """A 401 JSON body plus RFC-7235 ``WWW-Authenticate``."""
    return JSONResponse(
        status_code=401,
        content={"detail": message},
        headers={WWW_AUTH_HEADER: "ApiKey"},
    )


def constantTimeContains(target: str, candidates: Iterable[str]) -> bool:
    """True iff some element of ``candidates`` matches ``target`` in
    constant time per-element."""
    matched = False
    for candidate in candidates:
        matched = matched or hmac.compare_digest(target, candidate)
    return matched


# ---------------------------------------------------------------------------
# Middleware factory (mirrors security_headers pattern)
# ---------------------------------------------------------------------------
def makeAuthDispatch(
    configured: frozenset[str],
) -> Callable:
    """Build the async dispatch function for the auth middleware.

    Two states:

    * ``configured`` empty  -- middleware is a pass-through.  This is
      the public-demo default.
    * ``configured`` non-empty -- middleware actively checks each
      request to a protected route.

    Captured at registration time.  Tests that flip ``settings``
    mid-run must call ``addApiKeyAuth`` again on a fresh app.
    """

    authEnabled = bool(configured)

    async def _dispatch(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if not authEnabled or not isProtected(request.url.path):
            return await call_next(request)

        apiKey = request.headers.get(HEADER_API_KEY, "").strip()
        if not apiKey:
            logger.warning(
                "API key missing on protected route %s -- rejected",
                request.url.path,
            )
            return unauthorized("Missing X-Api-Key header")

        keyHash = hashKey(apiKey)
        if not constantTimeContains(keyHash, configured):
            logger.warning(
                "Invalid API key on protected route %s",
                request.url.path,
            )
            return unauthorized("Invalid X-Api-Key")

        return await call_next(request)

    return _dispatch


# ---------------------------------------------------------------------------
# FastAPI integration
# ---------------------------------------------------------------------------
def addApiKeyAuth(app: FastAPI) -> bool:
    """Register the API-key middleware on ``app``.

    Returns ``True`` when authentication is actually enabled (one or
    more keys configured), ``False`` otherwise.
    """
    hashes = configuredHashes(getSettings().apiKeys)
    dispatch = makeAuthDispatch(hashes)
    app.middleware("http")(dispatch)
    if hashes:
        logger.info(
            "API-key auth ENABLED for %s (N keys=%d)",
            _PROTECTED_PREFIXES,
            len(hashes),
        )
    else:
        logger.info("API-key auth DISABLED -- no apiKeys configured")
    return bool(hashes)
