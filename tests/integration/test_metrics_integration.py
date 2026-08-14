"""
Integration tests for ``GET /metrics`` (Tier 4 D end-to-end).

Customers

* ``/metrics`` returns 200 with the Prometheus text exposition content
  type.
* The body is parseable line-by-line and carries HELP/TYPE for all
  three production metrics.
* Real requests through the middleware populate the request counter
  and latency histogram.
* A real analysis populates ``phishguard_analysis_total`` with the
  resolved content type and threat level.
* Self-exclusion: ``/metrics`` and ``/api/health`` never appear as
  series in their own exposition.
"""

from __future__ import annotations

from collections import defaultdict

import pytest
from fastapi.testclient import TestClient

from backend import metrics as m
from backend.main import app


@pytest.fixture(autouse=True)
def _cleanMetrics():
    m.resetMetrics()
    yield
    m.resetMetrics()


@pytest.fixture(autouse=True)
def _mockOsint(monkeypatch):
    from backend.api.orchestrator import AnalysisOrchestrator

    async def _noOsint(self, domain: str, url: str = "") -> None:
        return None

    monkeypatch.setattr(AnalysisOrchestrator, "_collectOsintData", _noOsint)


@pytest.fixture
def client():
    return TestClient(app)


def _parseMetrics(text: str) -> dict[str, dict[str, str]]:
    """Split the exposition into {series_name+labels: value}."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        series, value = line.rsplit(" ", 1)
        result[series] = value
    return result


# ---------------------------------------------------------------------------
# Endpoint basics
# ---------------------------------------------------------------------------

def test_metrics_endpoint_returns_prometheus_content_type(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain; version=0.0.4")


def test_metrics_endpoint_has_help_and_type_for_all_metrics(client):
    body = client.get("/metrics").text
    for metric in (
        "phishguard_http_requests_total",
        "phishguard_http_request_duration_seconds",
        "phishguard_analysis_total",
    ):
        assert f"# HELP {metric} " in body
        assert f"# TYPE {metric} " in body


# ---------------------------------------------------------------------------
# Middleware: request counting + latency
# ---------------------------------------------------------------------------

def test_requests_are_counted_by_middleware(client):
    client.get("/api/model/status")
    client.get("/api/model/status")
    body = client.get("/metrics").text
    series = _parseMetrics(body)
    key = 'phishguard_http_requests_total{method="GET",path="/api/model/status",status="200"}'
    assert series.get(key) == "2.0"


def test_latency_histogram_counts_requests(client):
    client.get("/api/model/status")
    body = client.get("/metrics").text
    series = _parseMetrics(body)
    key = 'phishguard_http_request_duration_seconds_count{method="GET",path="/api/model/status"}'
    assert float(series[key]) >= 1.0
    sumKey = 'phishguard_http_request_duration_seconds_sum{method="GET",path="/api/model/status"}'
    assert float(series[sumKey]) >= 0.0


def test_metrics_and_health_are_self_excluded(client):
    """Scraping /metrics and polling /health must not pollute them."""
    client.get("/metrics")
    client.get("/api/health")
    body = client.get("/metrics").text
    assert 'path="/metrics"' not in body
    assert 'path="/api/health"' not in body


# ---------------------------------------------------------------------------
# Analysis counter (fed by the orchestrator)
# ---------------------------------------------------------------------------

def test_analysis_total_reflects_real_analysis(client):
    r = client.post(
        "/api/analyze/url",
        json={"url": "https://example.com"},
    )
    assert r.status_code == 200
    threat = r.json()["verdict"]["threatLevel"]

    body = client.get("/metrics").text
    series = _parseMetrics(body)
    key = f'phishguard_analysis_total{{content_type="url",threat_level="{threat}"}}'
    assert series.get(key) == "1.0"


def test_analysis_total_counts_email_and_batch_paths(client):
    client.post("/api/analyze/email", json={"content": "Hello world"})
    client.post(
        "/api/analyze/batch",
        json={"items": [{"type": "url", "url": "https://example.com"}]},
    )
    body = client.get("/metrics").text
    series = _parseMetrics(body)
    emailKeys = [k for k in series if 'content_type="email"' in k]
    urlKeys = [k for k in series if 'content_type="url"' in k]
    assert len(emailKeys) == 1
    assert len(urlKeys) == 1
    assert series[urlKeys[0]] == "1.0"


def test_metrics_endpoint_not_in_openapi(client):
    """/metrics is operational, not part of the documented API schema."""
    r = client.get("/openapi.json")
    assert "/metrics" not in r.json()["paths"]
