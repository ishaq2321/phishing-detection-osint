"""
Unit Tests for API Router
=========================

Tests for FastAPI endpoints using TestClient.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app


@pytest.fixture
def client():
    """Create FastAPI TestClient."""
    return TestClient(app)


class TestRootEndpoint:
    """Test root endpoint."""

    def test_rootReturnsInfo(self, client):
        """Root endpoint should return API information."""
        response = client.get("/")
        assert response.status_code == 200
        
        data = response.json()
        assert "name" in data
        assert "version" in data


class TestApiRootEndpoint:
    """Test /api/ endpoint."""

    def test_apiRootReturnsInfo(self, client):
        """API root should return endpoint information."""
        response = client.get("/api/")
        assert response.status_code == 200
        
        data = response.json()
        assert "name" in data
        assert "version" in data


class TestHealthEndpoint:
    """Test /api/health endpoint."""

    def test_healthReturnsStatus(self, client):
        """Health endpoint should return service status."""
        response = client.get("/api/health")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert "version" in data
        assert "services" in data


class TestAnalyzeEndpoint:
    """Test POST /api/analyze endpoint."""

    def test_analyzeUrl(self, client):
        """Should analyze URL content."""
        response = client.post(
            "/api/analyze",
            json={
                "content": "https://example.com",
                "contentType": "url"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Check response structure
        assert "success" in data
        assert "verdict" in data
        assert "features" in data
        assert "analysisTime" in data

    def test_analyzeEmptyContent(self, client):
        """Should reject empty content."""
        response = client.post(
            "/api/analyze",
            json={
                "content": "",
                "contentType": "url"
            }
        )
        
        assert response.status_code == 422  # Validation error


class TestAnalyzeUrlEndpoint:
    """Test POST /api/analyze/url endpoint."""

    def test_analyzeValidUrl(self, client):
        """Should analyze valid URL."""
        response = client.post(
            "/api/analyze/url",
            json={
                "url": "https://example.com"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "verdict" in data

    def test_analyzeEmptyUrl(self, client):
        """Should reject empty URL."""
        response = client.post(
            "/api/analyze/url",
            json={
                "url": ""
            }
        )
        
        assert response.status_code == 422


class TestAnalyzeEmailEndpoint:
    """Test POST /api/analyze/email endpoint."""

    def test_analyzeValidEmail(self, client):
        """Should analyze valid email content."""
        response = client.post(
            "/api/analyze/email",
            json={
                "content": "Please review the attached document.",
                "subject": "Quarterly Report"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "verdict" in data

    def test_analyzeEmptyEmailContent(self, client):
        """Should reject empty email content."""
        response = client.post(
            "/api/analyze/email",
            json={
                "content": ""
            }
        )
        
        assert response.status_code == 422


class TestResponseFormat:
    """Test response format consistency."""

    def test_responseHasRequiredFields(self, client):
        """All analyze responses should have required fields."""
        response = client.post(
            "/api/analyze",
            json={
                "content": "https://example.com",
                "contentType": "url"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Top-level fields
        assert "success" in data
        assert "verdict" in data
        assert "features" in data
        assert "analysisTime" in data
        
        # Verdict fields
        verdict = data["verdict"]
        assert "isPhishing" in verdict
        assert "confidenceScore" in verdict
        assert "threatLevel" in verdict


class TestOpenApiDocs:
    """Test OpenAPI documentation."""

    def test_openapiSchemaAvailable(self, client):
        """OpenAPI schema should be available."""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        
        schema = response.json()
        assert "openapi" in schema
        assert "info" in schema

    def test_docsPageAvailable(self, client):
        """Swagger docs should be available."""
        response = client.get("/docs")
        assert response.status_code == 200
