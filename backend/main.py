"""
Phishing Detection API - Main Entry Point
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Phishing Detection API",
    description="OSINT-Enhanced Phishing Detection System",
    version="0.1.0"
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    """Health check endpoint."""
    return {"status": "ok", "message": "Phishing Detection API is running"}


@app.get("/api/health")
def healthCheck():
    """API health check."""
    return {"status": "healthy", "version": "0.1.0"}
