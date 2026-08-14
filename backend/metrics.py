"""
Zero-Dependency Prometheus Metrics (Tier 4 D)
=============================================

Exposes a Prometheus-compatible ``/metrics`` endpoint without pulling
in ``prometheus-client`` -- the text exposition format (version 0.0.4)
is a simple, stable line protocol, and hand-rolling it keeps the
deployment dependency tree unchanged and the format fully pinned by
golden tests.

What is exposed
---------------

* ``phishguard_http_requests_total{method,path,status}`` -- counter of
  every HTTP request handled (excluding ``/metrics`` and
  ``/api/health`` so scrapers and uptime monitors do not pollute their
  own signal).
* ``phishguard_http_request_duration_seconds{method,path}`` --
  histogram of request latency using the standard Prometheus default
  buckets (5 ms .. 10 s).
* ``phishguard_analysis_total{content_type,threat_level}`` -- counter
  of completed analyses, fed from the single funnel every analysis
  path (single, batch, ingest) goes through:
  ``AnalysisOrchestrator.analyze``.

Concurrency
-----------

FastAPI runs handlers on one event loop, but middleware, background
tasks, and the orchestrator can touch the metrics from different
contexts, so every mutation is guarded by a module-level ``Lock``.

Format notes
------------

* HELP/TYPE lines are emitted once per metric; each labelled series
  follows on its own line.
* Label values are escaped per the exposition spec (backslash, quote,
  newline).
* Values are floats rendered shortest-round-trip (``42.0``, not
  ``42``), matching what Prometheus' own client emits.
"""

from __future__ import annotations

import threading
import time
from typing import Iterable, Optional

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

# Histogram buckets in seconds -- the standard Prometheus defaults.
DEFAULT_BUCKETS: tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
)

EXPOSITION_CONTENT_TYPE = "text/plain; version=0.0.4"

# Paths that must never be self-instrumented.
_EXCLUDED_PATHS = frozenset({"/metrics", "/api/health"})

_lock = threading.Lock()
_registry: list["_LabeledMetric"] = []


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _escapeLabel(value: str) -> str:
    """Escape a label value per the exposition spec."""
    return (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace('"', '\\"')
    )


def _fmtValue(value: float) -> str:
    """Shortest round-trip float representation (``42.0``, ``0.5``)."""
    return repr(float(value))


def _labelsBody(labelnames: tuple[str, ...], values: tuple[str, ...]) -> str:
    """Render ``name="value",...`` WITHOUT braces (empty when no labels)."""
    return ",".join(
        f'{name}="{_escapeLabel(value)}"'
        for name, value in zip(labelnames, values)
    )


def _labelsPart(labelnames: tuple[str, ...], values: tuple[str, ...]) -> str:
    """Render ``{name="value",...}`` (empty when no labels)."""
    body = _labelsBody(labelnames, values)
    return "{" + body + "}" if body else ""


# ---------------------------------------------------------------------------
# Metric primitives
# ---------------------------------------------------------------------------

class _LabeledMetric:
    """Base for labelled metric types with lock-guarded storage."""

    def __init__(
        self,
        name: str,
        helpText: str,
        metricType: str,
        labelnames: Iterable[str],
    ) -> None:
        self.name = name
        self.helpText = helpText
        self.metricType = metricType
        self.labelnames = tuple(labelnames)
        self._values: dict[tuple[str, ...], object] = {}

    def _reset(self) -> None:
        with _lock:
            self._values.clear()

    def _seriesLines(self, key: tuple[str, ...]) -> list[str]:
        raise NotImplementedError


class Counter(_LabeledMetric):
    """Monotonic counter, incremented with ``inc(**labels)``."""

    def __init__(
        self,
        name: str,
        helpText: str,
        labelnames: Iterable[str] = (),
    ) -> None:
        super().__init__(name, helpText, "counter", labelnames)

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        if amount < 0:
            raise ValueError("counter increments must be non-negative")
        key = tuple(labels.get(n, "") for n in self.labelnames)
        with _lock:
            current = self._values.get(key, 0.0)
            self._values[key] = current + amount

    def _seriesLines(self, key: tuple[str, ...]) -> list[str]:
        return [
            f"{self.name}{_labelsPart(self.labelnames, key)} "
            f"{_fmtValue(float(self._values[key]))}"
        ]


class Histogram(_LabeledMetric):
    """Histogram of observed values with cumulative buckets."""

    def __init__(
        self,
        name: str,
        helpText: str,
        labelnames: Iterable[str] = (),
        buckets: tuple[float, ...] = DEFAULT_BUCKETS,
    ) -> None:
        super().__init__(name, helpText, "histogram", labelnames)
        self.buckets = tuple(sorted(buckets))
        if not self.buckets:
            raise ValueError("histogram requires at least one bucket")

    def observe(self, value: float, **labels: str) -> None:
        key = tuple(labels.get(n, "") for n in self.labelnames)
        with _lock:
            state = self._values.get(key)
            if state is None:
                state = {
                    "buckets": [0.0] * len(self.buckets),
                    "sum": 0.0,
                    "count": 0.0,
                }
                self._values[key] = state
            state["sum"] += value
            state["count"] += 1.0
            for i, upper in enumerate(self.buckets):
                if value <= upper:
                    state["buckets"][i] += 1.0

    def _seriesLines(self, key: tuple[str, ...]) -> list[str]:
        state = self._values[key]
        # Prometheus requires the suffix (_bucket/_sum/_count) BEFORE
        # the label set, and ``le`` lives INSIDE the same braces as the
        # other labels: ``name_bucket{method="GET",le="0.1"}``.
        body = _labelsBody(self.labelnames, key)

        def _bucketSeries(name: str, leValue: str) -> str:
            inner = f'le="{leValue}"'
            if body:
                inner = body + "," + inner
            return f"{name}{{{inner}}}"

        lines: list[str] = []
        for i, upper in enumerate(self.buckets):
            lines.append(
                f"{_bucketSeries(self.name + '_bucket', _fmtValue(upper))} "
                f"{_fmtValue(float(state['buckets'][i]))}"
            )
        lines.append(
            f"{_bucketSeries(self.name + '_bucket', '+Inf')} "
            f"{_fmtValue(float(state['count']))}"
        )
        labelPart = _labelsPart(self.labelnames, key)
        # Round the sum at render time: float accumulation of many
        # small observations drifts (0.05+0.3+1.2 == 1.54999...); six
        # decimals is far beyond any latency measurement we make.
        lines.append(
            f"{self.name}_sum{labelPart} "
            f"{_fmtValue(round(float(state['sum']), 6))}"
        )
        lines.append(
            f"{self.name}_count{labelPart} {_fmtValue(float(state['count']))}"
        )
        return lines


# ---------------------------------------------------------------------------
# The three exported metrics
# ---------------------------------------------------------------------------

REQUESTS_TOTAL = Counter(
    "phishguard_http_requests_total",
    "Total HTTP requests handled (excluding /metrics and /api/health).",
    labelnames=["method", "path", "status"],
)

REQUEST_DURATION = Histogram(
    "phishguard_http_request_duration_seconds",
    "HTTP request latency in seconds.",
    labelnames=["method", "path"],
)

ANALYSIS_TOTAL = Counter(
    "phishguard_analysis_total",
    "Completed analyses by resolved content type and threat level.",
    labelnames=["content_type", "threat_level"],
)


# ---------------------------------------------------------------------------
# Exposition
# ---------------------------------------------------------------------------

def generateMetrics() -> str:
    """Render the full exposition document for all registered metrics."""
    lines: list[str] = []
    with _lock:
        for metric in _registry:
            lines.append(f"# HELP {metric.name} {metric.helpText}")
            lines.append(f"# TYPE {metric.name} {metric.metricType}")
            for key in metric._values:
                lines.extend(metric._seriesLines(key))
    return "\n".join(lines) + ("\n" if lines else "")


def resetMetrics() -> None:
    """Clear all metric values (used by tests and demo resets)."""
    with _lock:
        for metric in _registry:
            metric._values.clear()


def _register(metric: _LabeledMetric) -> _LabeledMetric:
    with _lock:
        _registry.append(metric)
    return metric


# Register the module-level metrics once at import time.
_register(REQUESTS_TOTAL)
_register(REQUEST_DURATION)
_register(ANALYSIS_TOTAL)


# ---------------------------------------------------------------------------
# ASGI middleware
# ---------------------------------------------------------------------------

class MetricsMiddleware(BaseHTTPMiddleware):
    """Count every request and its latency, minus the excluded paths."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self, request: Request, call_next: ASGIApp
    ) -> Response:
        path = request.url.path
        if path in _EXCLUDED_PATHS:
            return await call_next(request)

        method = request.method or "GET"
        start = time.perf_counter()
        response: Optional[Response] = None
        try:
            response = await call_next(request)
            return response
        finally:
            # ``response`` stays None when ``call_next`` raised -- the
            # request still happened, so count it as status 0 (a
            # client-disconnect or middleware error must not vanish
            # from the metrics).
            status = getattr(response, "status_code", 0)
            REQUESTS_TOTAL.inc(
                method=method, path=path, status=str(status)
            )
            REQUEST_DURATION.observe(
                time.perf_counter() - start, method=method, path=path
            )


def addMetricsMiddleware(app: FastAPI) -> None:
    """Register the request-counting middleware on ``app``."""
    app.add_middleware(MetricsMiddleware)


def registerMetricsEndpoint(app: FastAPI) -> None:
    """Mount ``GET /metrics`` (raw Prometheus text exposition).

    Intentionally NOT rate-limited with an explicit decorator (the
    default 60/min applies) and NOT behind the API-key middleware so
    monitoring scrapers can poll without credentials -- the same
    posture as ``/api/health``.
    """

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        return Response(
            content=generateMetrics(),
            media_type=EXPOSITION_CONTENT_TYPE,
        )
