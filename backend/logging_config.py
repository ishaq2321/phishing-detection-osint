"""
Structured Logging Configuration
================================

Wires ``structlog`` on top of the standard-library ``logging``
module so existing ``logger.info(...)`` call sites produce structured
output.  Configuration choices:

* When ``LOG_FORMAT=json`` *or* ``settings.isProduction`` --
  **single-line JSON per log record.** Renders cleanly in
  log-aggregation back-ends (Render, Datadog, etc.).  Times are
  ISO 8601 UTC.
* Otherwise (development / testing on the operator's terminal) --
  ``key=value`` colourised output via ``ConsoleRenderer`` for
  readability.

Both renderers attach a fixed set of standard fields:

    timestamp, level, logger, event, plus any kwargs passed at
    the call site, plus any thread-local context bound via
    ``structlog.contextvars.bind_contextvars``.

Per-request id
--------------

A second middleware (in this module) ensures every request gets an
``X-Request-ID`` -- either echoed from the client-supplied header or
generated -- and binds it into the structlog context.  Downstream
log records during that request carry ``request_id`` automatically.

Public API
----------

* ``configure_structlog()`` -- call once at startup (already done
  inside ``main.lifespan``).  Idempotent.
* ``add_request_id_middleware(app)`` -- installs the X-Request-ID
  middleware on ``app``.  Order matters: install this BEFORE the
  other middlewares so subsequent ones still see the id in
  ``request.state.request_id`` and in structlog context.
"""

from __future__ import annotations

import logging
import logging.config
import os
import sys
import uuid
from typing import Any, Awaitable, Callable

import structlog
from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from backend.config import getSettings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants (exported)
# ---------------------------------------------------------------------------
HEADER_REQUEST_ID = "X-Request-ID"
_LOG_CONTEXT_KEY_REQUEST_ID = "request_id"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _isJsonFormat() -> bool:
    """True if we should emit JSON instead of pretty dev output."""
    explicitFlag = os.environ.get("LOG_FORMAT", "").strip().lower()
    if explicitFlag == "json":
        return True
    if explicitFlag == "pretty":
        return False
    # Fall back to environment-driven default.
    try:
        return bool(getSettings().isProduction)
    except Exception:
        # Settings can fail to load if .env is partial -- default to JSON.
        return True


def _add_log_level(logger: Any, methodName: str, eventDict: dict) -> dict:
    """Structlog processor that copies the stdlib log level into the
    event dictionary under the canonical ``level`` key.
    """
    level = getattr(methodName, "upper", lambda: methodName)()
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        level = methodName.upper()
    eventDict["level"] = level
    return eventDict


def _add_call_site(
    logger: Any, methodName: str, eventDict: dict
) -> dict:
    """Attach ``module`` and ``func`` so JSON logs are traceable back
    to the originating line without a debugger.
    """
    record = eventDict.get("_record")
    if record is not None:
        eventDict.setdefault("module", record.module)
        eventDict.setdefault("func", record.funcName)
    return eventDict


def _drop_color_message(
    logger: Any, methodName: str, eventDict: dict
) -> dict:
    """Drop the duplicate ``color_message`` key that ``structlog.stdlib``
    adds when wrapping the stdlib formatter.  Avoids noisy duplicated
    fields in stdout."""
    eventDict.pop("color_message", None)
    return eventDict


# ---------------------------------------------------------------------------
# Public entry-points
# ---------------------------------------------------------------------------
def configureStructlog() -> None:
    """Idempotently install structlog + stdlib logging config.

    Call once at application startup.  Subsequent calls are no-ops
    because structlog caches the configuration on first call, and
    ``logging.config.dictConfig`` is rerun safely because we always
    point at the same handlers.

    The shared processors are run for both structlog-direct calls
    (``log.info("msg", foo=bar)``) and stdlib-bridged calls
    (``logging.getLogger(__name__).info("msg %s", x)``).
    """
    useJson = _isJsonFormat()

    # 1. shared processor chain -- runs for every record
    sharedProcessors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _add_call_site,
    ]

    if useJson:
        # JSON output: machine-readable, no colour.
        finalRenderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        # Console output: human-readable colours.
        finalRenderer = structlog.dev.ConsoleRenderer(colors=True)

    # 2. structlog config -- structlog.make_filtering_bound_logger is
    #    used instead of Filterer so we don't lose DEBUG records when
    #    the operator runs with LOG_LEVEL=DEBUG.
    structlog.configure(
        processors=sharedProcessors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(getSettings().logLevel.value)
            if hasattr(getSettings(), "logLevel")
            else logging.INFO
        ),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # 3. formatter used by the stdlib handler when routing through
    #    ProcessorFormatter -- finds the existing record and replays
    #    it through the structlog chain so bridge calls are uniform.
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=sharedProcessors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            _add_log_level,
            _drop_color_message,
            finalRenderer,
        ],
    )

    # 4. install the formatter on the root logger via dictConfig
    handler: logging.Handler
    logStream = sys.stdout
    handler = logging.StreamHandler(logStream)
    handler.setFormatter(formatter)
    rootLogger = logging.getLogger()
    # Clear any prior handlers so test runs don't double-print.
    for h in list(rootLogger.handlers):
        rootLogger.removeHandler(h)
    rootLogger.addHandler(handler)

    # 5. Set root logger level (overridable by env).  Use the
    #    numerical value to play nice with structlog.
    levelName = (
        getSettings().logLevel.value
        if hasattr(getSettings(), "logLevel")
        else "INFO"
    )
    numeric = logging.getLevelName(levelName)
    if not isinstance(numeric, int):
        numeric = logging.INFO
    rootLogger.setLevel(numeric)

    # 6. Quiet noisy third-party loggers in JSON mode.
    if useJson:
        for noisy in ("uvicorn.access", "uvicorn.error", "asyncio"):
            logging.getLogger(noisy).setLevel(max(numeric, logging.INFO))

    logger.info(
        "structlog configured (json=%s, level=%s)", useJson, levelName
    )


# ---------------------------------------------------------------------------
# Per-request id middleware
# ---------------------------------------------------------------------------
def _generateRequestId() -> str:
    """Generate a 12-char hex request id.

    48 bits of entropy is well above what we need for correlation
    and short enough to stay readable in operator eyeballing.
    """
    return uuid.uuid4().hex[:12]


class _RequestIdMiddleware(BaseHTTPMiddleware):
    """Threads ``X-Request-ID`` through the request lifecycle.

    Behaviour:

    * If the incoming request already carries an ``X-Request-ID``
      header, we use it (operator-driven tracing from a load
      balancer or upstream service).
    * Otherwise we generate a new 12-char hex id.
    * The id is bound to structlog's contextvars for the lifetime
      of the request so every log line emits ``request_id=...``.
    * The response carries the id back as ``X-Request-ID`` so
      operators can correlate logs to a specific client session.
    """

    async def dispatch(  # type: ignore[override]
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        incoming = request.headers.get(HEADER_REQUEST_ID, "").strip()
        requestId = incoming or _generateRequestId()
        request.state.request_id = requestId

        structlog.contextvars.bind_contextvars(
            **{_LOG_CONTEXT_KEY_REQUEST_ID: requestId}
        )
        try:
            response = await call_next(request)
        finally:
            structlog.contextvars.unbind_contextvars(
                _LOG_CONTEXT_KEY_REQUEST_ID
            )
        response.headers[HEADER_REQUEST_ID] = requestId
        return response


def addRequestIdMiddleware(app: FastAPI) -> None:
    """Register the request-id middleware on ``app``.

    Idempotent-guard removed (FastAPI deduplicates middleware by
    class identity, so re-adding the same class is a no-op)."""
    app.add_middleware(_RequestIdMiddleware)
    logger.info("X-Request-ID middleware registered")
