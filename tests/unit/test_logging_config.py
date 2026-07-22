"""
Unit tests for ``backend.logging_config``.

Customers

* ``_isJsonFormat`` honours ``LOG_FORMAT=json|pretty`` and falls
  back to ``settings.isProduction``.
* ``_generateRequestId`` returns a 12-char hex string.
* ``configureStructlog`` is idempotent and prints the configured
  format correctly.
* ``_add_log_level`` injects a ``level`` key.
* ``_drop_color_message`` strips the ``color_message`` key.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re

import pytest
import structlog

from backend.logging_config import (
    HEADER_REQUEST_ID,
    _add_log_level,
    _drop_color_message,
    _generateRequestId,
    _isJsonFormat,
    configureStructlog,
)


# ---------------------------------------------------------------------------
# _isJsonFormat
# ---------------------------------------------------------------------------
def test_isJsonFormat_explicitJson(monkeypatch):
    monkeypatch.setenv("LOG_FORMAT", "json")
    monkeypatch.setenv("ENVIRONMENT", "development")
    import backend.config as cfg

    cfg.getSettings.cache_clear()
    try:
        assert _isJsonFormat() is True
    finally:
        cfg.getSettings.cache_clear()


def test_isJsonFormat_explicitPretty(monkeypatch):
    monkeypatch.setenv("LOG_FORMAT", "pretty")
    monkeypatch.setenv("ENVIRONMENT", "production")
    import backend.config as cfg

    cfg.getSettings.cache_clear()
    try:
        assert _isJsonFormat() is False
    finally:
        cfg.getSettings.cache_clear()


def test_isJsonFormat_defaultsToProduction(monkeypatch):
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "production")
    import backend.config as cfg

    cfg.getSettings.cache_clear()
    try:
        assert _isJsonFormat() is True
    finally:
        cfg.getSettings.cache_clear()


def test_isJsonFormat_defaultsToPrettyInDev(monkeypatch):
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "development")
    import backend.config as cfg

    cfg.getSettings.cache_clear()
    try:
        assert _isJsonFormat() is False
    finally:
        cfg.getSettings.cache_clear()


# ---------------------------------------------------------------------------
# _generateRequestId
# ---------------------------------------------------------------------------
def test_generateRequestId_isHexLength12():
    rid = _generateRequestId()
    assert len(rid) == 12
    assert re.fullmatch(r"[0-9a-f]{12}", rid)


def test_generateRequestId_isUniquePerCall():
    """Two consecutive calls produce different ids."""
    a = _generateRequestId()
    b = _generateRequestId()
    assert a != b


# ---------------------------------------------------------------------------
# _add_log_level
# ---------------------------------------------------------------------------
def test_addLogLevel_normalisesUppercase():
    eventDict: dict = {}
    result = _add_log_level(None, "info", eventDict)
    assert result["level"] == "INFO"


def test_addLogLevel_acceptsUppercaseDirectly():
    eventDict: dict = {}
    result = _add_log_level(None, "WARNING", eventDict)
    assert result["level"] == "WARNING"


# ---------------------------------------------------------------------------
# _drop_color_message
# ---------------------------------------------------------------------------
def test_dropColorMessage_removesOnlyTheColorKey():
    eventDict = {"color_message": "blue!", "event": "hello"}
    result = _drop_color_message(None, "info", eventDict)
    assert "color_message" not in result
    assert result["event"] == "hello"


def test_dropColorMessage_safeWhenAbsent():
    eventDict = {"event": "hello"}
    result = _drop_color_message(None, "info", eventDict)
    assert result == {"event": "hello"}


# ---------------------------------------------------------------------------
# configureStructlog integration
# ---------------------------------------------------------------------------
def test_configureStructlog_isIdempotent(caplog):
    """Calling twice should not raise."""
    configureStructlog()
    configureStructlog()  # second time should be a no-op


def test_configureStructlog_jsonModeEmitsValidJson(caplog, monkeypatch):
    """In JSON mode the root handler emits single-line JSON records."""
    monkeypatch.setenv("LOG_FORMAT", "json")

    # Capture stdout where the StreamHandler writes.
    import sys
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)

    configureStructlog()

    log = structlog.get_logger("utest")
    log.info("hello-structured", topic="sanity", n=42)

    output = buf.getvalue()
    records = [
        line
        for line in output.splitlines()
        if line.startswith("{") and line.endswith("}")
    ] or [line for line in output.splitlines() if line.startswith("{")]
    # The last record we emitted should be the one with topic=sanity
    matching = [
        r for r in records if '"topic": "sanity"' in r
    ]
    assert matching, (
        f"expected one JSON record with topic=sanity, got: {output!r}"
    )
    parsed = json.loads(matching[-1])
    assert parsed["topic"] == "sanity"
    assert parsed["event"] == "hello-structured"
    assert parsed["level"] == "INFO"


def test_configureStructlog_stdlibLogsAreStructured(caplog, monkeypatch):
    """Stdlib logger calls go through the structlog formatter too."""
    monkeypatch.setenv("LOG_FORMAT", "json")
    import sys
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)
    configureStructlog()

    pyLogger = logging.getLogger("stdlib_bridge")
    pyLogger.info("a bridge message %s", "value")

    output = buf.getvalue()
    matching = [
        line
        for line in output.splitlines()
        if '"logger": "stdlib_bridge"' in line
    ]
    assert matching, (
        "stdlib logger call should appear in the captured stdout"
    )
    parsed = json.loads(matching[-1])
    assert parsed["logger"] == "stdlib_bridge"
    assert "a bridge message value" in parsed["event"]


def test_configureStructlog_requestIdThreadedViaStructlogContext(monkeypatch):
    """Bound context fields appear in subsequent log records."""
    monkeypatch.setenv("LOG_FORMAT", "json")
    configureStructlog()
    import io

    buf = io.StringIO()
    import logging

    # replace root handler's stream with our buffer
    root = logging.getLogger()
    saved = [(h, h.stream) for h in root.handlers]
    for h, _ in saved:
        h.stream = buf

    try:
        import structlog

        structlog.contextvars.bind_contextvars(request_id="abc-12345")
        log = structlog.get_logger("utest")
        log.info("with-context")
        # Capture before unbinding so the request_id is in the log line.
        snapshot = buf.getvalue()
        structlog.contextvars.unbind_contextvars("request_id")
    finally:
        for h, originalStream in saved:
            h.stream = originalStream

    lines = snapshot.splitlines()
    matching = [
        line for line in lines if '"event": "with-context"' in line
    ]
    assert matching, (
        f"expected one JSON line with event=with-context, got {snapshot!r}"
    )
    parsed = json.loads(matching[-1])
    assert parsed.get("request_id") == "abc-12345"
