"""
Unit tests for ``backend/metrics.py`` (Tier 4 D).

Pins the Prometheus text exposition format (version 0.0.4):

* HELP / TYPE lines appear once per metric
* counter series render with the given labels, floats as ``42.0``
* histogram buckets are cumulative, with ``+Inf``, ``_sum``, ``_count``
* label values are escaped (backslash, quote, newline)
* reset clears values but keeps the definitions (HELP/TYPE persist)
"""

from __future__ import annotations

import pytest

from backend import metrics as m


@pytest.fixture(autouse=True)
def _cleanMetrics():
    m.resetMetrics()
    yield
    m.resetMetrics()


# ---------------------------------------------------------------------------
# Counter
# ---------------------------------------------------------------------------

def test_counter_renders_help_type_and_series():
    c = m.Counter("test_counter_total", "A test counter.", labelnames=["kind"])
    m._register(c)
    c.inc(kind="url")
    out = m.generateMetrics()
    assert "# HELP test_counter_total A test counter." in out
    assert "# TYPE test_counter_total counter" in out
    assert 'test_counter_total{kind="url"} 1.0' in out


def test_counter_accumulates_and_formats_floats():
    c = m.Counter("test_counter_total", "Accumulates.", labelnames=[])
    m._register(c)
    c.inc(2.5)
    c.inc(3)
    out = m.generateMetrics()
    # 5.5 must render shortest-round-trip float, not 5 or 5.500000.
    assert "\ntest_counter_total 5.5\n" in out


def test_counter_multiple_label_sets():
    c = m.Counter("test_counter_total", "Labelled.", labelnames=["a", "b"])
    m._register(c)
    c.inc(a="x", b="y")
    c.inc(a="x", b="y")
    c.inc(a="p", b="q")
    out = m.generateMetrics()
    assert 'test_counter_total{a="x",b="y"} 2.0' in out
    assert 'test_counter_total{a="p",b="q"} 1.0' in out


def test_counter_negative_increment_rejected():
    c = m.Counter("test_counter_total", "No negatives.")
    m._register(c)
    with pytest.raises(ValueError):
        c.inc(-1)


# ---------------------------------------------------------------------------
# Histogram
# ---------------------------------------------------------------------------

def test_histogram_buckets_are_cumulative():
    h = m.Histogram(
        "test_latency_seconds",
        "Latency.",
        buckets=(0.1, 0.5, 1.0),
    )
    m._register(h)
    h.observe(0.05)   # bucket 0
    h.observe(0.3)    # bucket 1
    h.observe(1.2)    # +Inf only
    out = m.generateMetrics()

    assert '# TYPE test_latency_seconds histogram' in out
    assert 'test_latency_seconds_bucket{le="0.1"} 1.0' in out
    assert 'test_latency_seconds_bucket{le="0.5"} 2.0' in out
    assert 'test_latency_seconds_bucket{le="1.0"} 2.0' in out
    assert 'test_latency_seconds_bucket{le="+Inf"} 3.0' in out
    assert 'test_latency_seconds_sum 1.55' in out
    assert 'test_latency_seconds_count 3.0' in out


def test_histogram_observation_at_exact_boundary():
    h = m.Histogram("test_latency_seconds", "Boundary.", buckets=(0.5,))
    m._register(h)
    h.observe(0.5)  # <= 0.5 -> first bucket
    out = m.generateMetrics()
    assert 'test_latency_seconds_bucket{le="0.5"} 1.0' in out


def test_histogram_labelled():
    h = m.Histogram(
        "test_latency_seconds",
        "Labelled latency.",
        labelnames=["method"],
        buckets=(1.0,),
    )
    m._register(h)
    h.observe(0.2, method="GET")
    out = m.generateMetrics()
    assert 'test_latency_seconds_bucket{method="GET",le="1.0"} 1.0' in out
    assert 'test_latency_seconds_sum{method="GET"} 0.2' in out
    assert 'test_latency_seconds_count{method="GET"} 1.0' in out


# ---------------------------------------------------------------------------
# Label escaping
# ---------------------------------------------------------------------------

def test_label_values_escaped():
    c = m.Counter("test_esc_total", "Escaping.", labelnames=["path"])
    m._register(c)
    c.inc(path='a"b\\c\nd')
    out = m.generateMetrics()
    assert 'test_esc_total{path="a\\"b\\\\c\\nd"} 1.0' in out


# ---------------------------------------------------------------------------
# Reset / empty state
# ---------------------------------------------------------------------------

def test_reset_clears_values_keeps_definitions():
    c = m.Counter("test_counter_total", "Reset.", labelnames=["kind"])
    m._register(c)
    c.inc(kind="url")
    m.resetMetrics()
    out = m.generateMetrics()
    # HELP/TYPE still present (definition), but no series lines.
    assert "# TYPE test_counter_total counter" in out
    assert 'test_counter_total{kind="url"}' not in out


def test_generate_empty_with_no_registered_metrics():
    # Use a fresh counter we never register: it must not appear at all.
    c = m.Counter("ghost_total", "Never registered.")
    c.inc()
    out = m.generateMetrics()
    assert "ghost_total" not in out


# ---------------------------------------------------------------------------
# The three production metrics
# ---------------------------------------------------------------------------

def test_production_metrics_defined_and_renderable():
    reset = m.generateMetrics()
    assert "# HELP phishguard_http_requests_total" in reset
    assert "# TYPE phishguard_http_requests_total counter" in reset
    assert "# TYPE phishguard_http_request_duration_seconds histogram" in reset
    assert "# TYPE phishguard_analysis_total counter" in reset


def test_analysis_total_counts_content_type_and_threat():
    m.ANALYSIS_TOTAL.inc(content_type="url", threat_level="dangerous")
    m.ANALYSIS_TOTAL.inc(content_type="email", threat_level="safe")
    out = m.generateMetrics()
    assert 'phishguard_analysis_total{content_type="url",threat_level="dangerous"} 1.0' in out
    assert 'phishguard_analysis_total{content_type="email",threat_level="safe"} 1.0' in out


def test_request_metrics_labelled():
    m.REQUESTS_TOTAL.inc(method="POST", path="/api/analyze", status="200")
    out = m.generateMetrics()
    assert 'phishguard_http_requests_total{method="POST",path="/api/analyze",status="200"} 1.0' in out
