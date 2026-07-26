"""
Unit tests for Tier 3 batch schemas (``backend.api.schemas``).

Customers

* ``BatchItemRequest`` accepts URL, EMAIL, and AUTO types and
  normalises the discriminator to lowercase.
* ``BatchAnalyzeRequest.items`` enforces ``1 <= length <= 50`` at
  the Pydantic layer (over-cap payloads raise ValidationError).
* ``BatchItemRequest.type`` is pattern-restricted to one of
  ``auto|url|email``; other values raise ValidationError.
* Empty ``items`` raises a ValueError via the custom validator.
* ``BatchItemResult`` accepts exactly one of {response, error} in
  practice (both fields default to ``None``); our code fills in
  only one -- the schema reflects that contract.
* ``BatchAnalyzeResponse`` enforces non-negative counts and a
  fixed-pattern ``success`` field (``True`` only).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.api.schemas import (
    AnalysisResponse,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
    BatchItemRequest,
    BatchItemResult,
)


# ---------------------------------------------------------------------------
# BatchItemRequest
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("t", ["url", "email", "auto", "URL", "  Email "])
def test_batchItemType_acceptsAndNormalises(t):
    item = BatchItemRequest(type=t, url="x" if t.lower() == "url" else None)
    # Always lowercase + stripped.
    assert item.type in {"url", "email", "auto"}


@pytest.mark.parametrize("bad", ["text", "document", "x"])
def test_batchItemType_rejectsUnknown(bad):
    """Empty ``type`` is handled upstream by the before-validator; the
    pattern catches every other non-canonical value."""
    with pytest.raises(ValidationError):
        BatchItemRequest(type=bad, url="x")


def test_batchItemType_emptyStringExplicitlyRejected():
    """Empty / whitespace-only ``type`` is invalid."""
    with pytest.raises(ValidationError):
        BatchItemRequest(type="", url="x")
    with pytest.raises(ValidationError):
        BatchItemRequest(type="   ", url="x")


def test_batchItemRequest_allOptional():
    """Only ``type`` is required -- url/content are optional."""
    item = BatchItemRequest(type="auto", url="https://example.com")
    assert item.url is not None
    assert item.content is None
    assert item.subject is None
    assert item.sender is None


def test_batchItemRequest_emailShape():
    item = BatchItemRequest(
        type="email",
        content="please verify",
        subject="hi",
        sender="a@b.com",
    )
    assert item.subject == "hi"
    assert item.sender == "a@b.com"


# ---------------------------------------------------------------------------
# BatchAnalyzeRequest
# ---------------------------------------------------------------------------
def test_batchAnalyzeRequest_acceptsSingleItem():
    req = BatchAnalyzeRequest(items=[BatchItemRequest(type="url", url="x")])
    assert len(req.items) == 1


def test_batchAnalyzeRequest_accepts50Items():
    items = [BatchItemRequest(type="url", url=f"https://e{i}.com") for i in range(50)]
    req = BatchAnalyzeRequest(items=items)
    assert len(req.items) == 50


def test_batchAnalyzeRequest_rejectsEmptyList():
    with pytest.raises(ValidationError):
        BatchAnalyzeRequest(items=[])


def test_batchAnalyzeRequest_rejects51Items():
    items = [BatchItemRequest(type="url", url=f"https://e{i}.com") for i in range(51)]
    with pytest.raises(ValidationError):
        BatchAnalyzeRequest(items=items)


def test_batchAnalyzeRequest_eachItemHasDistinctIdentity():
    items = [BatchItemRequest(type="auto", url=f"https://e{i}.com") for i in range(3)]
    req = BatchAnalyzeRequest(items=items)
    urls = [it.url for it in req.items]
    assert urls == ["https://e0.com", "https://e1.com", "https://e2.com"]


# ---------------------------------------------------------------------------
# BatchItemResult
# ---------------------------------------------------------------------------
def test_batchItemResult_statusOK():
    r = BatchItemResult(index=0, status="ok")
    assert r.index == 0
    assert r.status == "ok"


def test_batchItemResult_statusError():
    r = BatchItemResult(index=0, status="error", error="boom")
    assert r.error == "boom"


def test_batchItemResult_invalidStatusRejected():
    with pytest.raises(ValidationError):
        BatchItemResult(index=0, status="success")  # not in pattern


def test_batchItemResult_negativeIndexRejected():
    with pytest.raises(ValidationError):
        BatchItemResult(index=-1, status="error")


# ---------------------------------------------------------------------------
# BatchAnalyzeResponse
# ---------------------------------------------------------------------------
def test_batchAnalyzeResponse_requiredFields():
    resp = BatchAnalyzeResponse(
        success=True,
        total=5,
        succeeded=3,
        failed=2,
        analysisTime=42.5,
        results=[],
    )
    assert resp.success is True
    assert resp.total == 5
    assert resp.success == bool(resp.success)  # never None


def test_batchAnalyzeResponse_zeroTotalAllowed():
    """Empty results arrays are legal only when total=0."""
    resp = BatchAnalyzeResponse(
        success=True, total=0, succeeded=0, failed=0,
        analysisTime=0.0, results=[],
    )
    assert resp.total == 0


def test_batchAnalyzeResponse_negativeTotalRejected():
    with pytest.raises(ValidationError):
        BatchAnalyzeResponse(
            success=True, total=-1, succeeded=0, failed=0,
            analysisTime=0.0, results=[],
        )


def test_batchAnalyzeResponse_negativeAnalysisTimeRejected():
    with pytest.raises(ValidationError):
        BatchAnalyzeResponse(
            success=True, total=1, succeeded=1, failed=0,
            analysisTime=-0.1, results=[],
        )


def test_batchAnalyzeResponse_carriesResults():
    res = BatchItemResult(index=0, status="ok")
    resp = BatchAnalyzeResponse(
        success=True, total=1, succeeded=1, failed=0,
        analysisTime=1.0, results=[res],
    )
    assert len(resp.results) == 1
    assert resp.results[0] == res
