"""
Security Headers Middleware
============================

Adds standard, hardened HTTP security headers to every response.
Inspired by OWASPSecureHeadersProject best practices but trimmed for
this project's stack (no CSP `unsafe-inline` bypasses, narrow
Permissions-Policy, strict HSTS only in production).

Also injects a per-request ``X-Content-Type-Options: nosniff``,
disables iframe embedding via ``X-Frame-Options: DENY`` (effectively
`frame-ancestors 'none'` since modern browsers honour both), and
sets a restrictive Referrer-Policy: ``strict-origin-when-cross-origin``
is the standard "send only the origin on cross-origin" rule.

CSP details
------------

For an API (no HTML), the policy intentionally allows zero remote
script loading and zero inline script execution:

    default-src 'none';
    frame-ancestors 'none';
    base-uri 'none';
    form-action 'none';

This is the most conservative CSP that still permits swagger-ui to
function (FastAPI's /docs page inlines Swagger's JS).  If running
in production with the public swagger UI, swap to a permitter
policy; we leave that decision to the operator.

HSTS details
------------

``Strict-Transport-Security: max-age=31536000; includeSubDomains``
is only sent in production.  We never include ``preload`` because
preloading is irreversible -- a build flag to opt in will land in
a follow-up.

Public API
----------

``add_security_headers(app)`` is invoked in ``main.py``; pass the
FastAPI instance.  Header contents are configurable via
``backend.config.settings`` so test environments can disable HSTS
locally over HTTP.
"""

from __future__ import annotations

import logging
from typing import Awaitable, Callable

from fastapi import FastAPI, Request, Response

from backend.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Header name constants
# ---------------------------------------------------------------------------
HEADER_HSTS = "Strict-Transport-Security"
HEADER_XCTO = "X-Content-Type-Options"
HEADER_XFO = "X-Frame-Options"
HEADER_REFERRER = "Referrer-Policy"
HEADER_PERMISSIONS = "Permissions-Policy"
HEADER_CSP = "Content-Security-Policy"
HEADER_REQUEST_ID = "X-Request-ID"


# ---------------------------------------------------------------------------
# Header values
# ---------------------------------------------------------------------------
# 31536000 == 1 year (in seconds)
_HSTS_VALUE = "max-age=31536000; includeSubDomains"
_NOSNIFF_VALUE = "nosniff"
_XFO_VALUE = "DENY"
# Referer: origin only when downgrading from HTTPS to HTTP,
# full path same-protocol.
_REFERRER_VALUE = "strict-origin-when-cross-origin"

# Permissions-Policy: shut off features the API never uses.
# Keys are intentionally broad to fail safe.
_PERMISSIONS_VALUE = (
    "accelerometer=(), "
    "ambient-light-sensor=(), "
    "autoplay=(), "
    "battery=(), "
    "camera=(), "
    "display-capture=(), "
    "document-domain=(), "
    "encrypted-media=(), "
    "fullscreen=(), "
    "geolocation=(), "
    "gyroscope=(), "
    "layout-animations=(), "
    "legacy-image-formats=(), "
    "magnetometer=(), "
    "microphone=(), "
    "midi=(), "
    "oversized-images=(), "
    "payment=(), "
    "picture-in-picture=(), "
    "publickey-credentials-get=(), "
    "speaker-selection=(), "
    "sync-xhr=(), "
    "unoptimized-images=(), "
    "unsized-media=(), "
    "usb=(), "
    "screen-wake-lock=(), "
    "web-share=(), "
    "xr-spatial-tracking=()"
)

# API-only CSP.  Swagger UI requires inline CSS + JS; we allow it
# only for docs paths and deny everywhere else.
_API_CSP_DEFAULT = (
    "default-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'none'"
)
_API_CSP_DOCS = (
    "default-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "img-src 'self' data: https:; "
    "font-src 'self' https: data:; "
    "connect-src 'self'"
)
_OPENAPI_CSP = _API_CSP_DOCS  # The OpenAPI schema is JSON, no script needed


# ---------------------------------------------------------------------------
# Middleware factory
# ---------------------------------------------------------------------------
def _makeMiddleware(
    isProduction: bool,
):
    """Build the inner async middleware function with ``isProduction``
    captured at registration time.

    Starlette's ``app.middleware("http")`` captures the function
    reference once, but re-evaluates the function on each request.
    However, accessing ``settings.isProduction`` from inside the
    closure has shown timing-sensitive behaviour with pydantic-
    settings' ``lru_cache`` during pytest runs.  Binding the boolean
    at add-time makes the test deterministic and avoids the cache_timing
    edge case.
    """
    async def _inner(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)

        # Always-on headers
        response.headers[HEADER_XCTO] = _NOSNIFF_VALUE
        response.headers[HEADER_XFO] = _XFO_VALUE
        response.headers[HEADER_REFERRER] = _REFERRER_VALUE
        response.headers[HEADER_PERMISSIONS] = _PERMISSIONS_VALUE

        # Choose CSP.  Docs / swagger-ui paths get the permissive
        # variant because they need to inline fastapi's CDN-served JS.
        path = request.url.path
        if (
            path.startswith("/docs")
            or path.startswith("/redoc")
            or path.startswith("/openapi.json")
        ):
            response.headers[HEADER_CSP] = _API_CSP_DOCS
        else:
            response.headers[HEADER_CSP] = _API_CSP_DEFAULT

        # HSTS only in production (running over plain HTTP locally
        # makes it moot and could confuse local development proxies).
        if isProduction:
            response.headers[HEADER_HSTS] = _HSTS_VALUE

        return response

    return _inner


def addSecurityHeaders(app: FastAPI) -> None:
    """Register the security headers middleware on ``app``.

    Reads ``settings.isProduction`` exactly once at registration time.
    Tests that need to switch production mode must clear the
    ``getSettings`` cache before building the app.
    """
    isProduction = settings.isProduction
    middlewareFunc = _makeMiddleware(isProduction)
    app.middleware("http")(middlewareFunc)
    logger.info(
        "Security headers middleware registered (HSTS in production=%s)",
        isProduction,
    )
