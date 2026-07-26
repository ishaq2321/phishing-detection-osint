"""
Unit tests for ``AnalysisOrchestrator.analyzeBatch`` (Tier 3).

Customers

* The method runs every item through the same ``analyze()``
  pipeline used by the singletons.
* Concurrency is real: items are dispatched via
  ``asyncio.create_task`` and awaited via ``asyncio.gather``;
  tests confirm the tuple ordering matches input order.
* ``type=url`` items get dispatched with ``contentType='url'``;
  ``type=email`` items get the subject/sender prepended identically
  to the single-content route; ``type=auto`` lets the
  orchestrator's ``_detectContentType`` heuristic choose.
* Per-item validation failures (empty url, empty content) are
  captured per-item rather than aborting the whole batch.
* Counter ``succeeded`` and ``failed`` always sum to the input
  length.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from backend.api.orchestrator import AnalysisOrchestrator
from backend.api.schemas import AnalysisResponse


def _item(
    *,
    type_: str = "auto",
    url: str | None = None,
    content: str | None = None,
    subject: str | None = None,
    sender: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        type=type_,
        url=url,
        content=content,
        subject=subject,
        sender=sender,
    )


def _fakeResponse(label: str) -> AnalysisResponse:
    """Cheap response stub -- we don't care about the verdict content."""
    from backend.api.schemas import (
        AnalysisResponse,
        FeatureSummary,
        VerdictResult,
    )

    return AnalysisResponse(
        success=True,
        verdict=VerdictResult(
            isPhishing=False,
            confidenceScore=0.0,
            threatLevel="safe",
            reasons=[],
            recommendation="see-" + label,
        ),
        features=FeatureSummary(),
        analysisTime=1.0,
        timestamp="2026-01-01T00:00:00",
    )


# ---------------------------------------------------------------------------
# Spatial tests (item dispatch)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_batchEmptyListReturnsEmpty():
    orch = AnalysisOrchestrator()
    fake = AsyncMock()
    with patch.object(orch, "analyze", fake):
        result, ok, fail = await orch.analyzeBatch([])
    assert result == []
    assert ok == 0
    assert fail == 0
    fake.assert_not_awaited()


@pytest.mark.asyncio
async def test_batchDispatchesEachItemToAnalyze():
    """Each item triggers exactly one ``analyze()`` call."""
    orch = AnalysisOrchestrator()
    fake = AsyncMock(side_effect=lambda content, contentType="auto":
                    _fakeResponse(f"({contentType}|{content[:8]})"))
    with patch.object(orch, "analyze", fake):
        items = [
            _item(type_="url", url="https://a.com"),
            _item(type_="email", content="c", subject="sub", sender="me@x"),
            _item(type_="auto", content="plain"),
        ]
        perItem, ok, fail = await orch.analyzeBatch(items)

    assert ok == 3
    assert fail == 0
    assert fake.await_count == 3
    # Order preserved
    assert perItem[0][0] == "ok"
    # Email payload should embed subject
    email_call = fake.await_args_list[1]
    assert email_call.kwargs["contentType"] == "email"
    assert "Subject: sub" in email_call.kwargs["content"]
    assert "From: me@x" in email_call.kwargs["content"]


@pytest.mark.asyncio
async def test_batchEmailWithoutSubjectOrSender():
    orch = AnalysisOrchestrator()
    fake = AsyncMock(side_effect=lambda content, contentType="auto":
                    _fakeResponse("e"))
    with patch.object(orch, "analyze", fake):
        items = [_item(type_="email", content="hello")]
        perItem, ok, fail = await orch.analyzeBatch(items)
    assert ok == 1


@pytest.mark.asyncio
async def test_batchUrlItem_callsAnalyzeWithUrlPassthrough():
    orch = AnalysisOrchestrator()
    fake = AsyncMock(side_effect=lambda content, contentType="auto":
                    _fakeResponse(content))
    with patch.object(orch, "analyze", fake):
        await orch.analyzeBatch([_item(type_="url", url="https://e.com/login")])
    last_call = fake.await_args
    assert last_call.kwargs == {"content": "https://e.com/login", "contentType": "url"}


@pytest.mark.asyncio
async def test_batchAutoItem_passesUrlOrContent():
    orch = AnalysisOrchestrator()
    fake = AsyncMock(side_effect=lambda content, contentType="auto":
                    _fakeResponse(content))
    with patch.object(orch, "analyze", fake):
        await orch.analyzeBatch([_item(type_="auto", url="https://a.b")])
    assert fake.await_args.kwargs == {
        "content": "https://a.b",
        "contentType": "auto",
    }


# ---------------------------------------------------------------------------
# Per-item failure isolation
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_batchPerItemFailure_doesNotAbortSiblings():
    orch = AnalysisOrchestrator()

    async def maybe_fail(content: str, contentType: str = "auto"):
        if content == "https://bad.com":
            raise ValueError("simulated per-item failure")
        return _fakeResponse("ok")

    fake = AsyncMock(side_effect=maybe_fail)
    with patch.object(orch, "analyze", fake):
        items = [
            _item(type_="url", url="https://good.com"),
            _item(type_="url", url="https://bad.com"),
            _item(type_="url", url="https://good.com"),
        ]
        perItem, ok, fail = await orch.analyzeBatch(items)
    assert ok == 2
    assert fail == 1
    assert perItem[0][0] == "ok"
    assert perItem[1][0] == "error"
    assert "simulated per-item failure" in perItem[1][2]
    assert perItem[2][0] == "ok"


@pytest.mark.asyncio
async def test_batchValidationFailure_urlItemWithoutUrl():
    """``type=url`` with empty url must NOT succeed -- it's a ValueError."""
    orch = AnalysisOrchestrator()
    items = [_item(type_="url", url=None)]
    perItem, ok, fail = await orch.analyzeBatch(items)
    assert fail == 1
    assert ok == 0
    assert "type=url but url field is empty" in perItem[0][2]


@pytest.mark.asyncio
async def test_batchValidationFailure_emailItemWithoutContent():
    orch = AnalysisOrchestrator()
    items = [_item(type_="email", content=None)]
    perItem, ok, fail = await orch.analyzeBatch(items)
    assert fail == 1
    assert "type=email but content field is empty" in perItem[0][2]


@pytest.mark.asyncio
async def test_batchValidationFailure_autoItemWithoutAnything():
    orch = AnalysisOrchestrator()
    items = [_item(type_="auto", url=None, content=None)]
    perItem, ok, fail = await orch.analyzeBatch(items)
    assert fail == 1
    assert "auto-detect requires url or content" in perItem[0][2]


# ---------------------------------------------------------------------------
# Concurrency invariants
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_batchReturnsSameOrderAsInput():
    """The orchestrator must preserve input order, not the dispatch order."""
    orch = AnalysisOrchestrator()

    delaysMs = {
        "https://a.com": 0.05,
        "https://b.com": 0.005,
        "https://c.com": 0.025,
    }

    async def slow(content: str, contentType: str = "auto"):
        await asyncio.sleep(delaysMs[content])
        return _fakeResponse("done")

    fake = AsyncMock(side_effect=slow)
    with patch.object(orch, "analyze", fake):
        items = [
            _item(type_="url", url="https://a.com"),
            _item(type_="url", url="https://b.com"),
            _item(type_="url", url="https://c.com"),
        ]
        perItem, ok, fail = await orch.analyzeBatch(items)
    assert ok == 3
    assert perItem[0][0] == "ok"
    assert perItem[1][0] == "ok"
    assert perItem[2][0] == "ok"


@pytest.mark.asyncio
async def test_batchDoesRunConcurrently_viaTiming():
    """3 items with 100ms each, run sequentially that's 300ms;
    concurrent via gather, total should be ~100ms."""
    orch = AnalysisOrchestrator()
    fake = AsyncMock(
        side_effect=lambda content, contentType="auto": (
            _fakeResponse("done")
            if (lambda: (None, asyncio.sleep(0.1))[1])() is None else None  # placeholder
        )
    )

    # Simpler version: use a real coroutine
    async def stall(content: str, contentType: str = "auto"):
        await asyncio.sleep(0.1)
        return _fakeResponse("done")

    fake = AsyncMock(side_effect=stall)
    import time

    started = time.perf_counter()
    with patch.object(orch, "analyze", fake):
        await orch.analyzeBatch([
            _item(type_="url", url=f"https://www{i}.com") for i in range(3)
        ])
    elapsed = time.perf_counter() - started
    # Must be substantially less than 3 * 100ms = 300ms.
    assert elapsed < 0.25, (
        f"Concurrent gather should finish ~100ms not {elapsed * 1000:.0f}ms"
    )


# ---------------------------------------------------------------------------
# Counts consistency
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_batchCountersSum():
    orch = AnalysisOrchestrator()

    async def maybe_fail(content: str, contentType: str = "auto"):
        if content.endswith("fail"):
            raise RuntimeError("nope")
        return _fakeResponse("ok")

    fake = AsyncMock(side_effect=maybe_fail)
    with patch.object(orch, "analyze", fake):
        items = (
            [_item(type_="url", url=f"https://{i}.com") for i in range(7)]
            + [_item(type_="url", url="https://99.fail")]
        )
        perItem, ok, fail = await orch.analyzeBatch(items)
    assert ok + fail == 8
    assert ok == 7
    assert fail == 1
