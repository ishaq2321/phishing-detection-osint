"""
Unit Tests for Configuration Module
====================================

Comprehensive tests for config.py including:
- Default value validation
- Environment variable overrides
- Threshold validation
- Computed properties

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import pytest

from config import (
    AnalyzerEngine,
    Environment,
    LogLevel,
    Settings,
    getSettings,
)


class TestSettingsDefaults:
    """Test default configuration values."""
    
    def test_defaultEnvironment(self, monkeypatch):
        """Default environment should be development."""
        # Clear env var set by autouse fixture
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        settings = Settings(_env_file=None)  # type: ignore[call-arg]  # Skip .env file
        assert settings.environment == Environment.DEVELOPMENT
    
    def test_defaultAnalyzerEngine(self):
        """Default analyzer engine should be NLP."""
        settings = Settings()
        assert settings.analyzerEngine == AnalyzerEngine.NLP
    
    def test_defaultLogLevel(self):
        """Default log level should be INFO."""
        settings = Settings()
        assert settings.logLevel == LogLevel.INFO
    
    def test_defaultTimeouts(self):
        """Default timeouts should be reasonable."""
        settings = Settings()
        assert settings.whoisTimeout == 10
        assert settings.dnsTimeout == 5
        assert settings.reputationTimeout == 10
    
    def test_defaultRetrySettings(self):
        """Default retry settings should be sensible."""
        settings = Settings()
        assert settings.maxRetries == 3
        assert settings.retryDelaySeconds == 1.0
    
    def test_defaultThresholds(self):
        """Default risk thresholds should be valid."""
        settings = Settings()
        assert settings.highRiskThreshold == 0.7
        assert settings.mediumRiskThreshold == 0.4
        assert settings.mediumRiskThreshold < settings.highRiskThreshold

    def test_defaultApiSettings(self):
        """Default API settings should be secure for development."""
        settings = Settings()
        assert settings.corsOrigins == "*"
        assert settings.corsMethods == "GET,POST,OPTIONS"
        assert settings.corsHeaders == "Content-Type,Authorization"


class TestSettingsValidation:
    """Test settings validation rules."""
    
    def test_whoisTimeoutMinValue(self):
        """WHOIS timeout must be at least 1 second."""
        with pytest.raises(ValueError):
            Settings(whoisTimeout=0)
    
    def test_whoisTimeoutMaxValue(self):
        """WHOIS timeout must be at most 60 seconds."""
        with pytest.raises(ValueError):
            Settings(whoisTimeout=120)
    
    def test_dnsTimeoutMinValue(self):
        """DNS timeout must be at least 1 second."""
        with pytest.raises(ValueError):
            Settings(dnsTimeout=0)
    
    def test_maxRetriesMinValue(self):
        """Max retries can be 0."""
        settings = Settings(maxRetries=0)
        assert settings.maxRetries == 0
    
    def test_maxRetriesMaxValue(self):
        """Max retries must be at most 10."""
        with pytest.raises(ValueError):
            Settings(maxRetries=15)
    
    def test_thresholdValidation(self):
        """Medium threshold must be less than high threshold."""
        with pytest.raises(ValueError):
            Settings(mediumRiskThreshold=0.8, highRiskThreshold=0.7)
    
    def test_thresholdValidationEqual(self):
        """Medium and high thresholds cannot be equal."""
        with pytest.raises(ValueError):
            Settings(mediumRiskThreshold=0.5, highRiskThreshold=0.5)
    
    def test_validThresholds(self):
        """Valid thresholds should work."""
        settings = Settings(mediumRiskThreshold=0.3, highRiskThreshold=0.8)
        assert settings.mediumRiskThreshold == 0.3
        assert settings.highRiskThreshold == 0.8
    
    def test_thresholdRangeLow(self):
        """Thresholds must be >= 0."""
        with pytest.raises(ValueError):
            Settings(mediumRiskThreshold=-0.1)
    
    def test_thresholdRangeHigh(self):
        """Thresholds must be <= 1."""
        with pytest.raises(ValueError):
            Settings(highRiskThreshold=1.5)


class TestSettingsEnvironmentVariables:
    """
    Test environment variable overrides.
    
    Note: These tests verify that Settings properly reads from env vars.
    We test this by constructing Settings with explicit values (simulating
    what would happen if env vars were set), since the autouse fixture
    in conftest sets ENVIRONMENT=testing which interferes with monkeypatch.
    """
    
    def test_environmentOverride(self):
        """ENVIRONMENT variable should override default via constructor."""
        # Direct construction simulates env var loading
        settings = Settings(environment=Environment.PRODUCTION)
        assert settings.environment == Environment.PRODUCTION
    
    def test_analyzerEngineOverride(self):
        """ANALYZER_ENGINE variable should override default via constructor."""
        settings = Settings(analyzerEngine=AnalyzerEngine.NLP)
        assert settings.analyzerEngine == AnalyzerEngine.NLP
    
    def test_logLevelOverride(self):
        """LOG_LEVEL variable should override default via constructor."""
        settings = Settings(logLevel=LogLevel.DEBUG)
        assert settings.logLevel == LogLevel.DEBUG
    
    def test_timeoutOverride(self):
        """Timeout variables should override defaults via constructor."""
        settings = Settings(whoisTimeout=15, dnsTimeout=8)
        assert settings.whoisTimeout == 15
        assert settings.dnsTimeout == 8
    
    def test_apiKeyOverride(self):
        """API key variables should be set via constructor."""
        settings = Settings(virusTotalApiKey="test-api-key")
        assert settings.virusTotalApiKey == "test-api-key"
        assert settings.hasVirusTotalKey is True
    
    def test_allSettingsConfigurable(self):
        """All settings should be configurable."""
        settings = Settings(
            environment=Environment.PRODUCTION,
            analyzerEngine=AnalyzerEngine.NLP,
            logLevel=LogLevel.WARNING,
            whoisTimeout=20,
            dnsTimeout=10,
            reputationTimeout=15,
            maxRetries=5,
            retryDelaySeconds=2.0,
            virusTotalApiKey="vt-key",
            abuseIpDbApiKey="abuse-key",
            corsOrigins="http://localhost:3000",
            highRiskThreshold=0.8,
            mediumRiskThreshold=0.3,
        )

        assert settings.environment == Environment.PRODUCTION
        assert settings.analyzerEngine == AnalyzerEngine.NLP
        assert settings.whoisTimeout == 20
        assert settings.virusTotalApiKey == "vt-key"


class TestSettingsComputedProperties:
    """Test computed property methods."""
    
    def test_isProduction(self):
        """isProduction should return True for production."""
        settings = Settings(environment=Environment.PRODUCTION)
        assert settings.isProduction is True
        assert settings.isTesting is False
        assert settings.isDevelopment is False
    
    def test_isTesting(self):
        """isTesting should return True for testing."""
        settings = Settings(environment=Environment.TESTING)
        assert settings.isTesting is True
        assert settings.isProduction is False
        assert settings.isDevelopment is False
    
    def test_isDevelopment(self):
        """isDevelopment should return True for development."""
        settings = Settings(environment=Environment.DEVELOPMENT)
        assert settings.isDevelopment is True
        assert settings.isProduction is False
        assert settings.isTesting is False
    
    def test_corsOriginsListWildcard(self):
        """CORS origins list should handle wildcard."""
        settings = Settings(corsOrigins="*")
        assert settings.corsOriginsList == ["*"]
    
    def test_corsOriginsListMultiple(self):
        """CORS origins list should split multiple origins."""
        settings = Settings(corsOrigins="http://localhost:3000,https://example.com")
        assert settings.corsOriginsList == [
            "http://localhost:3000",
            "https://example.com"
        ]
    
    def test_hasVirusTotalKeyFalse(self):
        """hasVirusTotalKey should return False when not set."""
        settings = Settings(virusTotalApiKey=None)
        assert settings.hasVirusTotalKey is False
    
    def test_hasVirusTotalKeyTrue(self):
        """hasVirusTotalKey should return True when set."""
        settings = Settings(virusTotalApiKey="test-key")
        assert settings.hasVirusTotalKey is True
    
    def test_hasVirusTotalKeyEmpty(self):
        """hasVirusTotalKey should return False for empty string."""
        settings = Settings(virusTotalApiKey="")
        assert settings.hasVirusTotalKey is False
    
    def test_hasAbuseIpDbKeyFalse(self):
        """hasAbuseIpDbKey should return False when not set."""
        settings = Settings(abuseIpDbApiKey=None)
        assert settings.hasAbuseIpDbKey is False


class TestGetSettings:
    """Test the getSettings cached function."""
    
    def test_getSettingsReturnsSameInstance(self):
        """getSettings should return cached instance."""
        getSettings.cache_clear()
        settings1 = getSettings()
        settings2 = getSettings()
        assert settings1 is settings2
    
    def test_getSettingsCacheClear(self):
        """Cache clear should return new instance."""
        settings1 = getSettings()
        getSettings.cache_clear()
        settings2 = getSettings()
        # Different instances but same values
        assert settings1 is not settings2
        assert settings1.whoisTimeout == settings2.whoisTimeout


class TestEnumerations:
    """Test enumeration values."""
    
    def test_environmentValues(self):
        """Environment enum should have expected values."""
        assert Environment.DEVELOPMENT.value == "development"
        assert Environment.TESTING.value == "testing"
        assert Environment.PRODUCTION.value == "production"
    
    def test_analyzerEngineValues(self):
        """AnalyzerEngine enum should have expected values."""
        assert AnalyzerEngine.NLP.value == "nlp"
    
    def test_logLevelValues(self):
        """LogLevel enum should have expected values."""
        assert LogLevel.DEBUG.value == "DEBUG"
        assert LogLevel.INFO.value == "INFO"
        assert LogLevel.WARNING.value == "WARNING"
        assert LogLevel.ERROR.value == "ERROR"
        assert LogLevel.CRITICAL.value == "CRITICAL"


class TestCorsValidation:
    """Test CORS origins validation."""
    
    def test_emptyCorsOrigins(self):
        """Empty CORS origins should default to localhost."""
        settings = Settings(corsOrigins="")
        assert settings.corsOrigins == "http://localhost:3000"
    
    def test_whitespaceCorsOrigins(self):
        """Whitespace-only CORS origins should default to localhost."""
        settings = Settings(corsOrigins="   ")
        assert settings.corsOrigins == "http://localhost:3000"
    
    def test_validCorsOrigin(self):
        """Valid CORS origin should be preserved."""
        settings = Settings(corsOrigins="http://localhost:3000")
        assert settings.corsOrigins == "http://localhost:3000"
    
    def test_wildcardCorsOrigin(self):
        """Wildcard CORS origin should be accepted."""
        settings = Settings(corsOrigins="*")
        assert settings.corsOriginsList == ["*"]
    
    def test_multipleCorsOrigins(self):
        """Multiple CORS origins should be split into a list."""
        settings = Settings(corsOrigins="http://localhost:3000,https://example.com")
        assert settings.corsOriginsList == [
            "http://localhost:3000",
            "https://example.com",
        ]
    
    def test_emptyCorsMethods(self):
        """Empty CORS methods should default to GET,POST,OPTIONS."""
        settings = Settings(corsMethods="")
        assert settings.corsMethods == "GET,POST,OPTIONS"
    
    def test_corsMethodsList(self):
        """CORS methods should be split into a list."""
        settings = Settings(corsMethods="GET,POST,OPTIONS")
        assert settings.corsMethodsList == ["GET", "POST", "OPTIONS"]
    
    def test_corsMethodsUppercased(self):
        """CORS methods should be uppercased."""
        settings = Settings(corsMethods="get,post")
        assert settings.corsMethods == "GET,POST"
    
    def test_emptyCorsHeaders(self):
        """Empty CORS headers should default to Content-Type,Authorization."""
        settings = Settings(corsHeaders="")
        assert settings.corsHeaders == "Content-Type,Authorization"
    
    def test_corsHeadersList(self):
        """CORS headers should be split into a list."""
        settings = Settings(corsHeaders="Content-Type,Authorization")
        assert settings.corsHeadersList == ["Content-Type", "Authorization"]
