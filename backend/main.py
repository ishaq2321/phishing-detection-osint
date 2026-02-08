"""
Phishing Detection API
======================

FastAPI application for phishing detection using OSINT and NLP.

This is the main entry point for the phishing detection API. It provides
RESTful endpoints for analyzing URLs and email content for phishing indicators.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api import router
from backend.config import settings


# =============================================================================
# Lifespan Management
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application lifespan events.
    
    Handles startup and shutdown tasks like loading models,
    initializing connections, etc.
    """
    # Startup
    print(f"🚀 Starting {settings.APP_NAME} v{settings.API_VERSION}")
    print(f"📊 Analyzer Engine: {settings.ANALYZER_ENGINE}")
    print(f"🌍 Environment: {settings.ENVIRONMENT}")
    
    yield
    
    # Shutdown
    print(f"👋 Shutting down {settings.APP_NAME}")


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title=settings.APP_NAME,
    description="""
    # Phishing Detection API
    
    A comprehensive phishing detection system that combines:
    - **OSINT** (WHOIS, DNS, Reputation checking)
    - **Machine Learning** (Feature extraction and scoring)
    - **NLP Analysis** (Text-based phishing indicator detection)
    
    ## Features
    - Analyze URLs for phishing indicators
    - Analyze email content for phishing tactics
    - Real-time OSINT data collection
    - Multi-layered detection approach
    - Explainable results with confidence scores
    
    ## Author
    Ishaq Muhammad (PXPRGK)  
    BSc Thesis - ELTE Faculty of Informatics  
    Academic Year: 2025/2026
    """,
    version=settings.API_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)


# =============================================================================
# CORS Middleware
# =============================================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.corsOriginsList,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Exception Handlers
# =============================================================================

@app.exception_handler(ValueError)
async def valueErrorHandler(request, exc: ValueError):
    """Handle validation errors."""
    return JSONResponse(
        status_code=400,
        content={"detail": str(exc)}
    )


@app.exception_handler(Exception)
async def genericExceptionHandler(request, exc: Exception):
    """Handle unexpected errors."""
    if settings.DEBUG:
        # Show full error in debug mode
        return JSONResponse(
            status_code=500,
            content={"detail": str(exc), "type": type(exc).__name__}
        )
    else:
        # Generic error in production
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"}
        )


# =============================================================================
# Include Routers
# =============================================================================

app.include_router(router)


# =============================================================================
# Root Endpoint
# =============================================================================

@app.get("/", include_in_schema=False)
async def root():
    """
    Root endpoint - redirect to docs.
    
    Returns basic API information and links to documentation.
    """
    return {
        "name": settings.APP_NAME,
        "version": settings.API_VERSION,
        "status": "running",
        "docs": "/docs",
        "redoc": "/redoc",
        "openapi": "/openapi.json",
        "health": "/api/health",
        "api": "/api"
    }


# =============================================================================
# Run Application
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )

