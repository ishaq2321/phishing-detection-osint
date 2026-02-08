"""
Pytest Configuration and Shared Fixtures
=========================================

Centralized test configuration with reusable fixtures for:
- Mock data generation
- Async test support
- Environment isolation
- OSINT service mocking

Usage:
    All fixtures are automatically available in test modules.
    
    def test_something(mockWhoisClient):
        # Use fixture...

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta
from typing import Any, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Add backend to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))


# =============================================================================
# Async Configuration
# =============================================================================

@pytest.fixture(scope="session")
def eventLoop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# =============================================================================
# Environment Fixtures
# =============================================================================

@pytest.fixture(autouse=True)
def isolatedEnvironment(monkeypatch):
    """
    Ensure tests run with isolated environment variables.
    
    Prevents tests from affecting each other through env vars.
    """
    # Set testing environment
    monkeypatch.setenv("ENVIRONMENT", "testing")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    
    # Clear any cached settings
    from config import getSettings
    getSettings.cache_clear()
    
    yield
    
    # Clear cache after test
    getSettings.cache_clear()


@pytest.fixture
def testSettings():
    """Get settings configured for testing."""
    from config import Settings, Environment
    
    return Settings(
        environment=Environment.TESTING,
        whoisTimeout=5,
        dnsTimeout=3,
        maxRetries=1,
        retryDelaySeconds=0.1,
    )


# =============================================================================
# WHOIS Mock Data
# =============================================================================

@pytest.fixture
def sampleWhoisData() -> dict[str, Any]:
    """Sample WHOIS data for a legitimate domain."""
    return {
        "domain_name": "example.com",
        "registrar": "MarkMonitor Inc.",
        "creation_date": datetime(2015, 8, 14),
        "expiration_date": datetime(2026, 8, 14),
        "updated_date": datetime(2024, 1, 15),
        "name_servers": ["ns1.example.com", "ns2.example.com"],
        "name": "Example Inc.",
        "org": "Example Corporation",
        "country": "US",
        "state": "California",
        "city": "San Francisco",
        "emails": "admin@example.com",
    }


@pytest.fixture
def suspiciousWhoisData() -> dict[str, Any]:
    """Sample WHOIS data for a suspicious/recently registered domain."""
    return {
        "domain_name": "paypal-secure-login.com",
        "registrar": "Cheap Domains Ltd",
        "creation_date": datetime.utcnow() - timedelta(days=5),
        "expiration_date": datetime.utcnow() + timedelta(days=90),  # 90 days = short lifespan
        "updated_date": datetime.utcnow() - timedelta(days=5),
        "name_servers": ["ns1.freedns.com"],
        "name": "REDACTED FOR PRIVACY",
        "org": "WhoisGuard Protected",
        "country": None,
        "emails": None,
    }


@pytest.fixture
def privacyProtectedWhoisData() -> dict[str, Any]:
    """Sample WHOIS data with privacy protection."""
    return {
        "domain_name": "privacy-example.com",
        "registrar": "GoDaddy.com LLC",
        "creation_date": datetime(2020, 3, 10),
        "expiration_date": datetime(2025, 3, 10),
        "updated_date": datetime(2024, 3, 10),
        "name_servers": ["ns1.godaddy.com", "ns2.godaddy.com"],
        "name": "Domains By Proxy, LLC",
        "org": "Domains By Proxy, LLC",
        "country": "US",
        "emails": "privacy@domainsbyproxy.com",
    }


@pytest.fixture
def emptyWhoisData() -> dict[str, Any]:
    """Empty/not found WHOIS data."""
    return {}


@pytest.fixture
def whoisDataWithLists() -> dict[str, Any]:
    """WHOIS data with fields as lists (some registrars return this)."""
    return {
        "domain_name": ["EXAMPLE.COM", "example.com"],
        "registrar": "Test Registrar",
        "creation_date": [datetime(2018, 5, 20), datetime(2018, 5, 20)],
        "expiration_date": [datetime(2028, 5, 20)],
        "name_servers": ["ns1.test.com", "ns2.test.com", "ns3.test.com"],
        "emails": ["admin@example.com", "tech@example.com"],
    }


# =============================================================================
# Mock Clients
# =============================================================================

@pytest.fixture
def mockWhoisClient():
    """
    Create a mock WHOIS client for testing.
    
    Returns:
        MagicMock that can be configured to return specific data
    """
    mock = MagicMock()
    return mock


@pytest.fixture
def mockWhoisClientSuccess(mockWhoisClient, sampleWhoisData):
    """Mock WHOIS client that returns successful data."""
    mockWhoisClient.query.return_value = sampleWhoisData
    return mockWhoisClient


@pytest.fixture
def mockWhoisClientSuspicious(mockWhoisClient, suspiciousWhoisData):
    """Mock WHOIS client that returns suspicious domain data."""
    mockWhoisClient.query.return_value = suspiciousWhoisData
    return mockWhoisClient


@pytest.fixture
def mockWhoisClientNotFound(mockWhoisClient, emptyWhoisData):
    """Mock WHOIS client that returns empty/not found data."""
    mockWhoisClient.query.return_value = emptyWhoisData
    return mockWhoisClient


@pytest.fixture
def mockWhoisClientTimeout(mockWhoisClient):
    """Mock WHOIS client that simulates timeout."""
    async def slowQuery(*args):
        await asyncio.sleep(100)  # Will timeout
    
    mockWhoisClient.query.side_effect = asyncio.TimeoutError()
    return mockWhoisClient


@pytest.fixture
def mockWhoisClientError(mockWhoisClient):
    """Mock WHOIS client that raises an error."""
    mockWhoisClient.query.side_effect = Exception("WHOIS server unavailable")
    return mockWhoisClient


# =============================================================================
# Domain Fixtures
# =============================================================================

@pytest.fixture
def legitimateDomains() -> list[str]:
    """List of known legitimate domains for testing."""
    return [
        "google.com",
        "microsoft.com",
        "github.com",
        "python.org",
        "amazon.com",
    ]


@pytest.fixture
def suspiciousDomains() -> list[str]:
    """List of suspicious-looking domains for testing."""
    return [
        "paypal-secure-login.com",
        "microsoft-support-help.tk",
        "secure-banking-update.xyz",
        "account-verification.ml",
        "login-amazon-verify.ga",
    ]


@pytest.fixture
def invalidDomains() -> list[str]:
    """List of invalid domain inputs for testing."""
    return [
        "",
        "   ",
        "not-a-domain",
        "http://",
        ".com",
    ]


# =============================================================================
# URL Fixtures
# =============================================================================

@pytest.fixture
def samplePhishingUrls() -> list[str]:
    """Sample phishing URLs for testing."""
    return [
        "http://paypal-secure-login.com/signin",
        "https://microsoft-support.tk/account/verify",
        "http://apple-id-verify.ml/login.php",
        "https://amazon-order-update.ga/track",
        "http://bank-secure-update.xyz/login",
    ]


@pytest.fixture
def sampleLegitimateUrls() -> list[str]:
    """Sample legitimate URLs for testing."""
    return [
        "https://www.paypal.com/signin",
        "https://login.microsoftonline.com/",
        "https://appleid.apple.com/",
        "https://www.amazon.com/",
        "https://www.bankofamerica.com/",
    ]


# =============================================================================
# Utility Fixtures
# =============================================================================

@pytest.fixture
def assertApproxEqual():
    """Helper to assert approximate equality for floats."""
    def _assert(actual: float, expected: float, tolerance: float = 0.01):
        assert abs(actual - expected) <= tolerance, \
            f"Expected {expected} ± {tolerance}, got {actual}"
    return _assert


@pytest.fixture
def createMockResponse():
    """Factory for creating mock HTTP responses."""
    def _create(status: int = 200, json: dict = None, text: str = None):
        mock = MagicMock()
        mock.status_code = status
        mock.json.return_value = json or {}
        mock.text = text or ""
        return mock
    return _create
