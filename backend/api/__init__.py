"""
API Module
==========

FastAPI endpoints for phishing detection analysis.

This module provides RESTful API endpoints for analyzing URLs and email
content for phishing indicators. It orchestrates OSINT, ML, and NLP
analysis modules to provide comprehensive phishing detection.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from .orchestrator import AnalysisOrchestrator
from .router import router
from .schemas import (
    AnalysisResponse,
    AnalyzeRequest,
    EmailRequest,
    FeatureSummary,
    HealthResponse,
    OsintSummary,
    UrlRequest,
    VerdictResult,
)

__all__ = [
    # Router
    "router",
    
    # Orchestrator
    "AnalysisOrchestrator",
    
    # Request schemas
    "AnalyzeRequest",
    "UrlRequest",
    "EmailRequest",
    
    # Response schemas
    "AnalysisResponse",
    "VerdictResult",
    "OsintSummary",
    "FeatureSummary",
    "HealthResponse",
]
