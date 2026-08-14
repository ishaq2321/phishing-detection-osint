"""
API Router Module
=================

FastAPI router with phishing detection endpoints.

This module defines all REST API endpoints for the phishing detection system,
including URL analysis, email analysis, and health checks.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import time
from datetime import datetime
from types import SimpleNamespace

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from backend.config import getSettings
from .historyStore import HistoryEntry, HistoryListResponse
# Import the *module* (not the value) so every call site resolves the
# current global at request time: ``backend.main`` swaps the store at
# startup via ``set_store`` (in-memory deque by default, SQLite when
# PHISHGUARD_PERSIST_HISTORY=1).  A ``from .historyStore import
# historyStore`` binding would freeze the default instance at import
# time and silently keep writing to memory even when persistence is
# enabled -- a bug that defeats the opt-in entirely.
from . import historyStore as historyStoreModule
from .emlIngest import buildEmailContent, parseEmails
from .orchestrator import AnalysisOrchestrator
from .rate_limiting import ANALYZE_LIMIT, STATUS_LIMIT, limiter
from .schemas import (
    AnalysisResponse,
    AnalyzeRequest,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
    BatchItemRequest,
    BatchItemResult,
    EmailIngestResponse,
    EmailRequest,
    EmIngestSummary,
    HealthResponse,
    ModelStatusResponse,
    UrlRequest,
)

from backend.health import (
    runDeepChecks,
    servicesFromChecks,
    shouldReturn503,
    uptimeSeconds,
)
from backend.ml.predictor import PhishingPredictor

# Create router
router = APIRouter(prefix="/api", tags=["phishing-detection"])

# Initialize orchestrator
orchestrator = AnalysisOrchestrator()


# =============================================================================
# Health Check Endpoint
# =============================================================================

@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health Check",
    description=(
        "Deep health check that actively probes DNS, the XGBoost model, "
        "and analyzer/orchestrator imports.  Returns 503 only when truly "
        "unhealthy."
    ),
)
async def healthCheck(response: Response) -> HealthResponse:
    """
    Health check endpoint (Tier 1.5 deep check).

    Actively probes each dependency in parallel:

    * DNS -- resolve ``example.com`` via ``backend.osint``.
    * ML -- verify ``PhishingPredictor`` is loaded.
    * Imports -- ``NlpAnalyzer`` + ``AnalysisOrchestrator`` importable.

    Backward-compatible keys::

        status, version, timestamp, services

    New keys::

        checks         -- per-dependency deep report
        uptimeSeconds  -- seconds since application start
        ready          -- True once probes have completed at least once

    Returns the standard 200 even when ``status='degraded'`` -- the
    HTTP layer maps only ``unhealthy`` to a 503 so uptime monitors
    can flag real outages.
    """
    checks = await runDeepChecks()

    # Import the aggregator locally to avoid the symbol-resolution
    # cost on each call -- hot path.
    from backend.health import _aggregateStatus

    status_value = _aggregateStatus(checks)
    services = servicesFromChecks(checks)

    if shouldReturn503(status_value):
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return HealthResponse(
        status=status_value,
        version="1.0.0",
        timestamp=datetime.now(),
        services=services,
        checks=checks,
        uptimeSeconds=round(uptimeSeconds(), 2),
        ready=True,
    )


# =============================================================================
# Model Status Endpoint
# =============================================================================

@router.get(
    "/model/status",
    response_model=ModelStatusResponse,
    summary="ML Model Status",
    description="Return metadata about the loaded XGBoost phishing model",
)
@limiter.limit(STATUS_LIMIT)
async def modelStatus(request: Request, response: Response) -> ModelStatusResponse:
    """
    Return the ML model's availability and metadata.

    Useful for the frontend's methodology page and health indicators.
    """
    predictor = PhishingPredictor()
    return ModelStatusResponse(
        loaded=predictor.isLoaded,
        featureCount=predictor._featureCount if predictor.isLoaded else 0,
        featureNames=predictor.featureNames,
    )


# =============================================================================
# Analysis Endpoints
# =============================================================================

@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    summary="Analyze Content",
    description="Analyze URL or email content for phishing indicators",
    status_code=status.HTTP_200_OK
)
@limiter.limit(ANALYZE_LIMIT)
async def analyzeContent(
    request: Request,
    payload: AnalyzeRequest,
    response: Response,
) -> AnalysisResponse:
    """
    Analyze content for phishing indicators.
    
    This endpoint accepts any type of content (URL, email, or text) and
    performs comprehensive phishing detection using OSINT, ML, and NLP.
    
    Args:
        request: Analysis request with content and type
        
    Returns:
        AnalysisResponse: Complete analysis results
        
    Raises:
        HTTPException: If analysis fails
        
    Example:
        POST /api/analyze
        {
            "content": "https://suspicious-paypal.com/verify",
            "contentType": "url"
        }
        
        Response:
        {
            "success": true,
            "verdict": {
                "isPhishing": true,
                "confidenceScore": 0.87,
                "threatLevel": "dangerous",
                "reasons": [...],
                "recommendation": "Do not interact..."
            },
            ...
        }
    """
    try:
        response = await orchestrator.analyze(
            content=payload.content,
            contentType=payload.contentType
        )
        historyStoreModule.historyStore.add(
            content=payload.content,
            contentType=payload.contentType,
            response=response,
        )
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@router.post(
    "/analyze/url",
    response_model=AnalysisResponse,
    summary="Analyze URL",
    description="Analyze a URL for phishing indicators",
    status_code=status.HTTP_200_OK
)
@limiter.limit(ANALYZE_LIMIT)
async def analyzeUrl(
    request: Request,
    payload: UrlRequest,
    response: Response,
) -> AnalysisResponse:
    """
    Analyze a URL for phishing indicators.
    
    This endpoint specifically handles URL analysis with OSINT data collection
    and URL-based feature extraction.
    
    Args:
        request: URL analysis request
        
    Returns:
        AnalysisResponse: Complete analysis results
        
    Raises:
        HTTPException: If analysis fails
        
    Example:
        POST /api/analyze/url
        {
            "url": "https://example.com/verify"
        }
    """
    try:
        response = await orchestrator.analyze(
            content=payload.url,
            contentType="url"
        )
        historyStoreModule.historyStore.add(
            content=payload.url,
            contentType="url",
            response=response,
        )
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"URL analysis failed: {str(e)}"
        )


@router.post(
    "/analyze/email",
    response_model=AnalysisResponse,
    summary="Analyze Email",
    description="Analyze email content for phishing indicators",
    status_code=status.HTTP_200_OK
)
@limiter.limit(ANALYZE_LIMIT)
async def analyzeEmail(
    request: Request,
    payload: EmailRequest,
    response: Response,
) -> AnalysisResponse:
    """
    Analyze email content for phishing indicators.
    
    This endpoint handles email-specific analysis including subject line,
    sender validation, and content analysis.
    
    Args:
        request: Email analysis request
        
    Returns:
        AnalysisResponse: Complete analysis results
        
    Raises:
        HTTPException: If analysis fails
        
    Example:
        POST /api/analyze/email
        {
            "content": "Urgent! Your account...",
            "subject": "Security Alert",
            "sender": "security@example.com"
        }
    """
    try:
        # Combine subject and sender info with content
        fullContent = payload.content
        if payload.subject:
            fullContent = f"Subject: {payload.subject}\n\n{fullContent}"
        if payload.sender:
            fullContent = f"From: {payload.sender}\n{fullContent}"

        response = await orchestrator.analyze(
            content=fullContent,
            contentType="email"
        )
        historyStoreModule.historyStore.add(
            content=payload.content,
            contentType="email",
            response=response,
        )
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Email analysis failed: {str(e)}"
        )


# =============================================================================
# History Endpoints
# =============================================================================

@router.get(
    "/history",
    response_model=HistoryListResponse,
    summary="List History",
    description="Return the most recent analyses (newest first)",
)
async def listHistory(
    limit: int = Query(default=100, ge=1, le=100, description="Max entries to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
) -> HistoryListResponse:
    """Return paginated history entries."""
    return historyStoreModule.historyStore.list(limit=limit, offset=offset)


@router.get(
    "/history/{entryId}",
    response_model=HistoryEntry,
    summary="Get History Entry",
    description="Retrieve a single history entry by ID",
)
async def getHistoryEntry(entryId: str) -> HistoryEntry:
    """Get a single history entry by UUID."""
    entry = historyStoreModule.historyStore.get(entryId)
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"History entry {entryId} not found",
        )
    return entry


@router.delete(
    "/history/{entryId}",
    summary="Delete History Entry",
    description="Delete a single history entry by ID",
)
async def deleteHistoryEntry(entryId: str) -> dict:
    """Delete a single history entry."""
    deleted = historyStoreModule.historyStore.delete(entryId)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"History entry {entryId} not found",
        )
    return {"deleted": True, "id": entryId}


@router.delete(
    "/history",
    summary="Clear History",
    description="Delete all history entries",
)
async def clearHistoryEndpoint() -> dict:
    """Delete all history entries."""
    count = historyStoreModule.historyStore.clear()
    return {"deleted": True, "count": count}


# =============================================================================
# Root Endpoint
# =============================================================================

@router.get(
    "/",
    summary="API Root",
    description="Get API information",
    include_in_schema=True
)
async def root() -> dict:
    """
    API root endpoint.
    
    Returns basic information about the API.
    
    Returns:
        dict: API information
        
    Example:
        GET /api/
        
        Response:
        {
            "name": "Phishing Detection API",
            "version": "1.0.0",
            "docs": "/docs",
            "health": "/api/health"
        }
    """
    return {
        "name": "Phishing Detection API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/health",
        "endpoints": {
            "analyze": "/api/analyze",
            "analyzeUrl": "/api/analyze/url",
            "analyzeEmail": "/api/analyze/email",
            "history": "/api/history"
        }
    }


# =============================================================================
# Tier 3: Batch analysis
# =============================================================================
@router.post(
    "/analyze/batch",
    response_model=BatchAnalyzeResponse,
    summary="Analyse up to 50 items in one round trip",
    description=(
        "Accepts 1-50 items; each item is a discriminated union by "
        "``type`` (``url`` | ``email`` | ``auto``). The orchestrator "
        "runs them concurrently via ``asyncio.gather``; per-item "
        "failures are returned in the same payload as ``status=error`` "
        "entries. The top-level HTTP status is **always 200** when the "
        "batch itself was accepted and processed -- callers must "
        "inspect ``results[i].status`` for per-entry outcomes."
    ),
)
@limiter.limit(ANALYZE_LIMIT)
async def analyzeBatch(
    request: Request,
    response: Response,
    body: BatchAnalyzeRequest,
) -> BatchAnalyzeResponse:
    """Run a multi-item batch and return aggregated results.

    Args:
        request: FastAPI Request (required for slowapi to extract the
            rate-limit key from ``x-forwarded-for`` / ``X-Api-Key``).
        response: FastAPI Response (slowapi mutates this for ``x-ratelimit-*``).
        body: Pydantic batch payload (length-checked at the schema layer).

    Returns:
        BatchAnalyzeResponse with per-item result list, success counts,
        and total wall-clock latency.

    Example::

        POST /api/analyze/batch
        {
          "items": [
            {"type": "url", "url": "https://example.com/login"},
            {"type": "email", "content": "...", "subject": "Hi"}
          ]
        }
    """
    started = time.perf_counter()

    # Translate the Pydantic batch items into simple objects so the
    # orchestrator's analyzeBatch() stays decoupled from the schema.
    items = [
        SimpleNamespace(
            type=item.type,
            url=item.url,
            content=item.content,
            subject=item.subject,
            sender=item.sender,
        )
        for item in body.items
    ]

    perItem, succeeded, failed = await orchestrator.analyzeBatch(items)

    results: list[BatchItemResult] = []
    for idx, (outcome, resp, err) in enumerate(perItem):
        if outcome == "ok":
            results.append(
                BatchItemResult(index=idx, status="ok", response=resp)
            )
            # Mirror the single-route behaviour: persist successes in the
            # history store under their original content-bearing key.
            try:
                historyStoreModule.historyStore.add(
                    content=items[idx].url or items[idx].content or "",
                    contentType=(
                        items[idx].type
                        if items[idx].type in {"url", "email"}
                        else "auto"
                    ),
                    response=resp,
                )
            except Exception:  # noqa: BLE001
                # History persistence is best-effort; analysis success is
                # what the caller cares about.
                pass
        else:
            results.append(
                BatchItemResult(index=idx, status="error", error=err)
            )

    elapsed = (time.perf_counter() - started) * 1000.0

    return BatchAnalyzeResponse(
        success=True,
        total=len(body.items),
        succeeded=succeeded,
        failed=failed,
        analysisTime=elapsed,
        results=results,
    )


@router.post(
    "/ingest/email",
    response_model=EmailIngestResponse,
    summary="Ingest and analyse a raw .eml file",
    description=(
        "Accepts a raw RFC 822 / MIME ``.eml`` file (Content-Type ``message/rfc822`` "
        "or ``text/plain``) and runs it through the same email-analysis "
        "pipeline as ``/api/analyze/email``.  The response carries the "
        "full analysis result plus a ``parsed`` summary of the fields "
        "extracted from the message (subject, sender, recipients, "
        "attachments).  Payloads larger than the configured cap are "
        "rejected with HTTP 413; a message with no readable text body "
        "is rejected with HTTP 422."
    ),
    status_code=status.HTTP_200_OK,
)
@limiter.limit(ANALYZE_LIMIT)
async def ingestEmail(
    request: Request,
    response: Response,
) -> EmailIngestResponse:
    """Parse and analyse a raw ``.eml`` payload.

    Args:
        request: FastAPI Request -- the raw body bytes are read from it
            (no JSON schema applies; the client uploads the file bytes
            directly).
        response: FastAPI Response (slowapi mutates this for ``x-ratelimit-*``).

    Returns:
        EmailIngestResponse: full analysis plus the ``parsed`` summary.

    Raises:
        HTTPException 413: raw payload exceeds the configured size cap.
        HTTPException 422: the message has no readable text body.
        HTTPException 500: the underlying analysis pipeline failed.

    Example::

        POST /api/ingest/email
        Content-Type: message/rfc822

        <raw .eml bytes>
    """
    raw = await request.body()

    # Resolve at request time so operators can change the cap without
    # restarting and tests can override it via EML_MAX_BYTES.
    maxBytes = getSettings().emlMaxBytes
    if len(raw) > maxBytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"EML payload of {len(raw)} bytes exceeds the "
                f"configured cap of {maxBytes} bytes"
            ),
        )

    parsed = parseEmails(raw)
    # A body that parses to no readable text (pure binary garbage,
    # empty payload, header-only message) is not analysable -- the
    # NLP pipeline needs at least one alphanumeric character.
    if not any(c.isalnum() for c in parsed.body):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "No readable text body found in the .eml payload "
                "(empty body or unsupported encoding)"
            ),
        )

    try:
        fullContent = buildEmailContent(parsed)
        result = await orchestrator.analyze(
            content=fullContent,
            contentType="email",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"EML analysis failed: {str(e)}",
        )

    # Mirror the single-route behaviour: persist the analysis in the
    # history store so the feedback loop can reference it later.
    try:
        historyStoreModule.historyStore.add(
            content=parsed.body,
            contentType="email",
            response=result,
        )
    except Exception:  # noqa: BLE001
        pass  # history persistence is best-effort

    return EmailIngestResponse(
        **result.model_dump(),
        parsed=EmIngestSummary(
            subject=parsed.subject,
            senderName=parsed.senderName,
            senderAddress=parsed.senderAddress,
            recipients=parsed.recipients,
            bodyPreview=parsed.body[:200],
            hasAttachments=parsed.hasAttachments,
            attachmentNames=parsed.attachmentNames,
            sizeBytes=parsed.sizeBytes,
        ),
    )
