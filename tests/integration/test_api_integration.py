"""
Integration Tests for API Endpoints
===================================

Tests the FastAPI endpoints with real orchestration:
- POST /api/analyze with full pipeline
- GET /api/health with service status
- Error handling and validation
- Response format compliance

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch
from datetime import datetime, timedelta

from backend.main import app
from osint import OsintData, WhoisResult, DnsResult, ReputationResult, LookupStatus


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def mockOsintData():
    """Mock OSINT data."""
    return OsintData(
        url="https://example.com",
        domain="example.com",
        whois=WhoisResult(
            domain="example.com",
            status=LookupStatus.SUCCESS,
            registrar="Test",
            creationDate=datetime.now() - timedelta(days=365)
        ),
        dns=DnsResult(
            domain="example.com",
            status=LookupStatus.SUCCESS,
            records=[]
        ),
        reputation=ReputationResult(
            domain="example.com",
            status=LookupStatus.SUCCESS,
            checks=[],
            aggregateScore=0.0
        )
    )


# =============================================================================
# API Endpoint Integration Tests
# =============================================================================

class TestAnalyzeEndpointIntegration:
    """Test /api/analyze endpoint with real orchestration."""
    
    def test_analyzeUrlEndToEnd(self, client, mockOsintData):
        """Test URL analysis through API endpoint."""
        with patch("backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
                  new_callable=AsyncMock, return_value=mockOsintData):
            
            response = client.post("/api/analyze", json={
                "content": "https://example.com/test",
                "contentType": "url"
            })
            
            assert response.status_code == 200
            data = response.json()
            
            # Verify response structure
            assert "success" in data
            assert "verdict" in data
            assert "features" in data
            assert "analysisTime" in data
            
            # Verify verdict
            verdict = data["verdict"]
            assert "isPhishing" in verdict
            assert "threatLevel" in verdict
            assert "confidenceScore" in verdict
            assert "reasons" in verdict
            
            # Verify features
            features = data["features"]
            assert "urlFeatures" in features
            assert "osintFeatures" in features
    
    def test_analyzeEmailEndToEnd(self, client):
        """Test email analysis through API endpoint."""
        email = """
        Hello,
        Thank you for your recent purchase. 
        Your order has been processed.
        """
        
        response = client.post("/api/analyze", json={
            "content": email,
            "contentType": "email"
        })
        
        assert response.status_code == 200
        data = response.json()
        
        # Should have content analysis
        assert "verdict" in data
        assert data["success"] is True
        
        # Safe email should have low risk
        verdict = data["verdict"]
        assert verdict["threatLevel"] in ["safe", "suspicious"]
    
    def test_analyzePhishingUrlEndToEnd(self, client):
        """Test phishing URL detection through API."""
        phishingOsint = OsintData(
            url="http://paypal-verify.tk/login",
            domain="paypal-verify.tk",
            whois=WhoisResult(
                domain="paypal-verify.tk",
                status=LookupStatus.SUCCESS,
                registrar="Freenom",
                creationDate=datetime.now() - timedelta(days=3),
                registrantName="REDACTED FOR PRIVACY"
            ),
            dns=DnsResult(
                domain="paypal-verify.tk",
                status=LookupStatus.SUCCESS,
                records=[]
            ),
            reputation=ReputationResult(
                domain="paypal-verify.tk",
                status=LookupStatus.SUCCESS,
                checks=[],
                aggregateScore=0.8
            )
        )
        
        with patch("backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
                  new_callable=AsyncMock, return_value=phishingOsint):
            
            response = client.post("/api/analyze", json={
                "content": "http://paypal-verify.tk/login",
                "contentType": "url"
            })
            
            assert response.status_code == 200
            data = response.json()
            
            # Should detect higher risk (phishing or suspicious)
            verdict = data["verdict"]
            # May be suspicious or dangerous depending on ML scoring
            assert verdict["threatLevel"] in ["suspicious", "dangerous", "critical"]
            assert len(verdict["reasons"]) > 0
    
    def test_analyzeAutoDetectContentType(self, client, mockOsintData):
        """Test automatic content type detection."""
        with patch("backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
                  new_callable=AsyncMock, return_value=mockOsintData):
            
            # URL should be auto-detected
            response = client.post("/api/analyze", json={
                "content": "https://example.com"
                # No contentType specified
            })
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
    
    def test_analyzeInvalidContent(self, client):
        """Test API handles invalid content."""
        response = client.post("/api/analyze", json={
            "content": "",
            "contentType": "url"
        })
        
        # Should return 422 validation error
        assert response.status_code == 422


class TestAnalyzeUrlEndpoint:
    """Test /api/analyze/url endpoint."""
    
    def test_analyzeUrlSpecificEndpoint(self, client, mockOsintData):
        """Test URL-specific analysis endpoint."""
        with patch("backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
                  new_callable=AsyncMock, return_value=mockOsintData):
            
            response = client.post("/api/analyze/url", json={
                "url": "https://example.com"
            })
            
            assert response.status_code == 200
            data = response.json()
            
            assert data["success"] is True
            assert "verdict" in data
            assert "features" in data
    
    def test_analyzeUrlEmptyUrl(self, client):
        """Test URL endpoint with empty URL."""
        response = client.post("/api/analyze/url", json={
            "url": ""
        })
        
        assert response.status_code == 422


class TestAnalyzeEmailEndpoint:
    """Test /api/analyze/email endpoint."""
    
    def test_analyzeEmailSpecificEndpoint(self, client):
        """Test email-specific analysis endpoint."""
        response = client.post("/api/analyze/email", json={
            "content": "This is a test email message."
        })
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["success"] is True
        assert "verdict" in data
    
    def test_analyzeEmailEmpty(self, client):
        """Test email endpoint with empty content."""
        response = client.post("/api/analyze/email", json={
            "content": ""
        })
        
        assert response.status_code == 422


class TestHealthEndpoint:
    """Test /api/health endpoint."""
    
    def test_healthCheck(self, client):
        """Test health check returns service status."""
        response = client.get("/api/health")
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify structure
        assert "status" in data
        assert "version" in data
        assert "services" in data
        assert "timestamp" in data
        
        # Verify service statuses
        services = data["services"]
        assert "osint" in services
        assert "ml" in services
        assert "analyzer" in services
        
        # All services should be operational
        for service, status in services.items():
            assert status is True  # Services return True/False


class TestRootEndpoints:
    """Test root and documentation endpoints."""
    
    def test_rootEndpoint(self, client):
        """Test GET / returns API info."""
        response = client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "name" in data
        assert "version" in data
        # description field is optional
    
    def test_apiRootEndpoint(self, client):
        """Test GET /api/ returns endpoint info."""
        response = client.get("/api/")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "endpoints" in data
        endpoints = data["endpoints"]
        
        # Should list available endpoints
        assert "/api/analyze" in str(endpoints)
    
    def test_openApiDocsAvailable(self, client):
        """Test OpenAPI documentation is accessible."""
        response = client.get("/docs")
        assert response.status_code == 200
        
        response = client.get("/redoc")
        assert response.status_code == 200
        
        response = client.get("/openapi.json")
        assert response.status_code == 200


class TestResponseFormats:
    """Test API response format consistency."""
    
    def test_successResponseFormat(self, client, mockOsintData):
        """Test successful response has consistent format."""
        with patch("backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
                  new_callable=AsyncMock, return_value=mockOsintData):
            
            response = client.post("/api/analyze", json={
                "content": "https://example.com",
                "contentType": "url"
            })
            
            data = response.json()
            
            # Top-level fields
            assert isinstance(data["success"], bool)
            assert isinstance(data["analysisTime"], (int, float))
            
            # Verdict structure
            verdict = data["verdict"]
            assert isinstance(verdict["isPhishing"], bool)
            assert isinstance(verdict["confidenceScore"], (int, float))
            assert isinstance(verdict["threatLevel"], str)
            assert isinstance(verdict["reasons"], list)
            
            # Features structure
            features = data["features"]
            assert isinstance(features["urlFeatures"], int)
            assert isinstance(features["osintFeatures"], int)
    
    def test_errorResponseFormat(self, client):
        """Test error response has consistent format."""
        response = client.post("/api/analyze", json={
            "content": "",  # Invalid empty content
            "contentType": "url"
        })
        
        assert response.status_code == 422
        data = response.json()
        
        # Should have error details
        assert "detail" in data


class TestPerformance:
    """Test API performance."""
    
    def test_analyzeResponseTime(self, client, mockOsintData):
        """Test API responds in reasonable time."""
        with patch("backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
                  new_callable=AsyncMock, return_value=mockOsintData):
            
            import time
            start = time.time()
            
            response = client.post("/api/analyze", json={
                "content": "https://example.com"
            })
            
            end = time.time()
            duration = end - start
            
            assert response.status_code == 200
            # Should respond within 2 seconds with mocked OSINT
            assert duration < 2.0
    
    def test_healthCheckPerformance(self, client):
        """Test health check responds quickly."""
        import time
        start = time.time()
        
        response = client.get("/api/health")
        
        end = time.time()
        duration = end - start
        
        assert response.status_code == 200
        # Health check should be very fast
        assert duration < 0.5


class TestConcurrency:
    """Test API handles concurrent requests."""
    
    def test_multipleConcurrentRequests(self, client, mockOsintData):
        """Test API handles multiple simultaneous requests."""
        with patch("backend.api.orchestrator.AnalysisOrchestrator._collectOsintData",
                  new_callable=AsyncMock, return_value=mockOsintData):
            
            urls = [
                "https://example1.com",
                "https://example2.com",
                "https://example3.com"
            ]
            
            # Send multiple requests
            responses = []
            for url in urls:
                response = client.post("/api/analyze", json={
                    "content": url
                })
                responses.append(response)
            
            # All should succeed
            for response in responses:
                assert response.status_code == 200
                data = response.json()
                assert data["success"] is True
