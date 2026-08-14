"""
Integration tests for ``POST /api/ingest/email`` (Tier 4 E end-to-end).

Customers

* A valid raw .eml upload returns 200 with a full analysis verdict
  and a ``parsed`` summary of the extracted fields.
* The endpoint shows up in OpenAPI with the ``EmailIngestResponse`` schema.
* Oversized payloads are rejected with 413 *before* any parsing.
* Messages with no readable body are rejected with 422.
* Rate-limit ``x-ratelimit-*`` headers are emitted.
* Successful ingests are persisted in the history store.

The analysis pipeline is exercised with OSINT stubbed out (same
dependency-inversion convention as the rest of the integration suite)
so the suite never touches the network.
"""

from __future__ import annotations

import pytest
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from fastapi.testclient import TestClient

import backend.api.rate_limiting as rl
from backend.api import historyStore as hs
from backend.main import app


# ---------------------------------------------------------------------------
# Determinism: never touch the real network.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _mockOsint(monkeypatch):
    from backend.api.orchestrator import AnalysisOrchestrator

    async def _noOsint(self, domain: str, url: str = "") -> None:
        return None

    monkeypatch.setattr(
        AnalysisOrchestrator, "_collectOsintData", _noOsint
    )


@pytest.fixture(autouse=True)
def _resetRateLimiter():
    rl.limiter._route_limits.clear()
    rl.limiter._Limiter__marked_for_limiting.clear()
    rl.limiter._dynamic_route_limits.clear()
    rl.limiter.reset()
    yield
    rl.limiter.reset()


@pytest.fixture
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def sampleEml(subject: str = "Security Alert") -> bytes:
    msg = MIMEText(
        "Urgent! Your account has been suspended. Verify immediately.",
        "plain",
        "utf-8",
    )
    msg["Subject"] = subject
    msg["From"] = "security@paypa1-support.com"
    msg["To"] = "victim@example.com"
    return msg.as_bytes()


def htmlOnlyEml() -> bytes:
    msg = MIMEText(
        "<html><body><p>Your package is <b>waiting</b>.</p></body></html>",
        "html",
        "utf-8",
    )
    msg["Subject"] = "Delivery"
    return msg.as_bytes()


# ---------------------------------------------------------------------------
# OpenAPI
# ---------------------------------------------------------------------------

def test_ingestEndpoint_presentInOpenAPI(client):
    r = client.get("/openapi.json")
    spec = r.json()
    assert "/api/ingest/email" in spec["paths"]
    op = spec["paths"]["/api/ingest/email"]["post"]
    assert op["tags"] == ["phishing-detection"]
    assert "EmailIngestResponse" in op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

def test_ingest_validEmlReturnsVerdictAndParsedSummary(client):
    r = client.post(
        "/api/ingest/email",
        content=sampleEml(),
        headers={"Content-Type": "message/rfc822"},
    )
    assert r.status_code == 200
    data = r.json()

    # Full analysis shape (same contract as /api/analyze/email).
    assert data["success"] is True
    assert "verdict" in data
    assert data["verdict"]["threatLevel"] in ("safe", "suspicious", "dangerous", "critical")

    # Parsed summary reflects the uploaded message.
    parsed = data["parsed"]
    assert parsed["subject"] == "Security Alert"
    assert parsed["senderAddress"] == "security@paypa1-support.com"
    assert parsed["recipients"] == ["victim@example.com"]
    assert parsed["hasAttachments"] is False
    assert parsed["sizeBytes"] == len(sampleEml())
    assert "suspended" in parsed["bodyPreview"]


def test_ingest_htmlOnlyEmailStripsTags(client):
    r = client.post("/api/ingest/email", content=htmlOnlyEml())
    assert r.status_code == 200
    data = r.json()
    assert "waiting" in data["parsed"]["bodyPreview"]
    assert "<b>" not in data["parsed"]["bodyPreview"]


def test_ingest_plainTextContentTypeAccepted(client):
    r = client.post(
        "/api/ingest/email",
        content=sampleEml(),
        headers={"Content-Type": "text/plain"},
    )
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Validation / failure paths
# ---------------------------------------------------------------------------

def test_ingest_oversizedPayloadRejected413(client, monkeypatch):
    from backend.config import getSettings
    getSettings.cache_clear()
    monkeypatch.setenv("EML_MAX_BYTES", "1024")

    big = sampleEml() + b"x" * 2048  # > 1 KB cap
    r = client.post("/api/ingest/email", content=big)
    assert r.status_code == 413
    assert "exceeds" in r.json()["detail"]

    getSettings.cache_clear()


def test_ingest_emptyBodyRejected422(client):
    # A valid message with no text part at all.
    msg = MIMEMultipart()
    msg["Subject"] = "No body"
    r = client.post("/api/ingest/email", content=msg.as_bytes())
    assert r.status_code == 422
    assert "body" in r.json()["detail"].lower()


def test_ingest_emptyPayloadRejected422(client):
    r = client.post("/api/ingest/email", content=b"")
    assert r.status_code == 422


def test_ingest_binaryGarbageRejected422(client):
    # Pure binary with no readable text: the 422 is the honest answer.
    r = client.post("/api/ingest/email", content=b"\x00\xff\x01\x02")
    assert r.status_code == 422


def test_ingest_garbageWithReadableTextIsLenient(client):
    # The parser is deliberately lenient: if the payload carries any
    # readable text, it is analysed rather than rejected.
    r = client.post("/api/ingest/email", content=b"\x00\xff not an email")
    assert r.status_code == 200
    assert "not an email" in r.json()["parsed"]["bodyPreview"]


# ---------------------------------------------------------------------------
# Rate limiting / persistence
# ---------------------------------------------------------------------------

def test_ingest_rateLimitHeadersEmitted(client):
    r = client.post("/api/ingest/email", content=sampleEml())
    assert r.status_code == 200
    assert any(k.startswith("x-ratelimit") for k in r.headers.keys())


def test_ingest_persistsToHistoryStore(client):
    before = hs.historyStore.count
    r = client.post("/api/ingest/email", content=sampleEml())
    assert r.status_code == 200
    after = hs.historyStore.count
    assert after == before + 1
    # The most recent entry is the ingested email body.
    latest = hs.historyStore.list(limit=1)
    assert latest.entries and latest.entries[0].contentType == "email"
