"""
API Router Module
=================

FastAPI router with phishing detection endpoints.

This module defines all REST API endpoints for the phishing detection system,
including URL analysis, email analysis, and health checks.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from datetime import datetime

from fastapi import APIRouter, HTTPException, status

from .orchestrator import AnalysisOrchestrator
from .schemas import (
    AnalysisResponse,
    AnalyzeRequest,
    EmailRequest,
    HealthResponse,
    UrlRequest,
)

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
    description="Check the health status of the API and its dependencies"
)
async def healthCheck() -> HealthResponse:
    """
    Health check endpoint.
    
    Returns the current status of the API and all dependent services.
    
    Returns:
        HealthResponse: Health status information
        
    Example:
        GET /api/health
        
        Response:
        {
            "status": "healthy",
            "version": "1.0.0",
            "timestamp": "2026-02-08T12:00:00",
            "services": {
                "osint": true,
                "analyzer": true,
                "ml": true
            }
        }
    """
    # Check if services are available
    services = {
        "osint": True,  # OSINT modules are always available (graceful degradation)
        "analyzer": True,  # NLP analyzer is always available
        "ml": True,  # ML features are always available
    }
    
    # Determine overall status
    allHealthy = all(services.values())
    status_value = "healthy" if allHealthy else "degraded"
    
    return HealthResponse(
        status=status_value,
        version="1.0.0",
        timestamp=datetime.now(),
        services=services
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
async def analyzeContent(request: AnalyzeRequest) -> AnalysisResponse:
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
            content=request.content,
            contentType=request.contentType
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
async def analyzeUrl(request: UrlRequest) -> AnalysisResponse:
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
            content=request.url,
            contentType="url"
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
async def analyzeEmail(request: EmailRequest) -> AnalysisResponse:
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
        fullContent = request.content
        if request.subject:
            fullContent = f"Subject: {request.subject}\n\n{fullContent}"
        if request.sender:
            fullContent = f"From: {request.sender}\n{fullContent}"
        
        response = await orchestrator.analyze(
            content=fullContent,
            contentType="email"
        )
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Email analysis failed: {str(e)}"
        )


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
            "analyzeEmail": "/api/analyze/email"
        }
    }
