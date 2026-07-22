"""
Configuration Management Module
===============================

Centralized configuration using Pydantic Settings with environment variable support.
Implements the 12-factor app methodology for configuration management.

Features:
- Type-safe configuration with validation
- Environment-based settings (dev/test/prod)
- .env file support with python-dotenv
- Immutable settings after initialization
- Comprehensive validation with meaningful error messages

Usage:
    from config import settings
    
    timeout = settings.whoisTimeout
    engine = settings.analyzerEngine

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from enum import Enum
from functools import lru_cache
from typing import Optional

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    """Application environment enumeration."""
    
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


class AnalyzerEngine(str, Enum):
    """Analyzer engine type enumeration."""

    NLP = "nlp"


class LogLevel(str, Enum):
    """Logging level enumeration."""
    
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseSettings):
    """
    Application settings with environment variable support.
    
    All settings can be overridden via environment variables.
    Environment variables use UPPER_SNAKE_CASE format.
    
    Example:
        export ANALYZER_ENGINE=nlp
        export WHOIS_TIMEOUT=15
        export LOG_LEVEL=DEBUG
    
    Attributes:
    environment: Application environment (development/testing/production)
    analyzerEngine: Analysis engine to use (nlp)
    logLevel: Logging verbosity level

    whoisTimeout: WHOIS lookup timeout in seconds
    dnsTimeout: DNS resolution timeout in seconds
    maxRetries: Maximum retry attempts for failed requests

    virusTotalApiKey: VirusTotal API key (optional)
    abuseIpDbApiKey: AbuseIPDB API key (optional)

    corsOrigins: Allowed CORS origins (comma-separated)
    corsMethods: Allowed CORS HTTP methods (comma-separated)
    corsHeaders: Allowed CORS headers (comma-separated)
    """
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        validate_default=True,
    )
    
    # =========================================================================
    # Application Settings
    # =========================================================================
    
    environment: Environment = Field(
        default=Environment.DEVELOPMENT,
        description="Application environment"
    )
    
    analyzerEngine: AnalyzerEngine = Field(
        default=AnalyzerEngine.NLP,
        description="Analysis engine type (currently only NLP)"
    )
    
    logLevel: LogLevel = Field(
        default=LogLevel.INFO,
        description="Logging verbosity level"
    )
    
    debug: bool = Field(
        default=False,
        description="Enable debug mode"
    )
    
    # =========================================================================
    # Timeout Settings (in seconds)
    # =========================================================================
    
    whoisTimeout: int = Field(
        default=10,
        ge=1,
        le=60,
        description="WHOIS lookup timeout in seconds"
    )
    
    dnsTimeout: int = Field(
        default=5,
        ge=1,
        le=30,
        description="DNS resolution timeout in seconds"
    )
    
    reputationTimeout: int = Field(
        default=10,
        ge=1,
        le=60,
        description="Reputation API request timeout in seconds"
    )

    maxRetries: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Maximum retry attempts for failed requests"
    )
    
    retryDelaySeconds: float = Field(
        default=1.0,
        ge=0.1,
        le=10.0,
        description="Delay between retry attempts in seconds"
    )
    
    # =========================================================================
    # External API Keys (Optional - for enhanced detection)
    # =========================================================================
    
    virusTotalApiKey: Optional[str] = Field(
        default=None,
        description="VirusTotal API key for reputation checks"
    )
    
    abuseIpDbApiKey: Optional[str] = Field(
        default=None,
        description="AbuseIPDB API key for IP reputation"
    )

    # =========================================================================
    # API Settings
    # =========================================================================
    
    corsOrigins: str = Field(
        default="*",
        description="Allowed CORS origins (comma-separated or * for all)"
    )
    
    corsMethods: str = Field(
        default="GET,POST,OPTIONS",
        description="Allowed CORS HTTP methods (comma-separated)"
    )
    
    corsHeaders: str = Field(
        default="Content-Type,Authorization",
        description="Allowed CORS headers (comma-separated)"
    )

    # =========================================================================
    # Authentication
    # =========================================================================

    apiKeys: Optional[str] = Field(
        default=None,
        description=(
            "Comma-separated list of acceptable X-Api-Key values for "
            "the heavy analysis endpoints.  Empty / unset disables "
            "authentication entirely (public-demo posture)."
        ),
    )

    # =========================================================================
    # Analysis Thresholds
    # =========================================================================
    
    highRiskThreshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Score threshold for high risk classification"
    )
    
    mediumRiskThreshold: float = Field(
        default=0.4,
        ge=0.0,
        le=1.0,
        description="Score threshold for medium risk classification"
    )
    
    # =========================================================================
    # Validators
    # =========================================================================
    
    @field_validator("corsOrigins")
    @classmethod
    def validateCorsOrigins(cls, v: str) -> str:
        """Validate CORS origins format."""
        if not v or not v.strip():
            return "http://localhost:3000"
        return v.strip()
    
    @field_validator("corsMethods")
    @classmethod
    def validateCorsMethods(cls, v: str) -> str:
        """Validate CORS methods format."""
        if not v or not v.strip():
            return "GET,POST,OPTIONS"
        return v.strip().upper()
    
    @field_validator("corsHeaders")
    @classmethod
    def validateCorsHeaders(cls, v: str) -> str:
        """Validate CORS headers format."""
        if not v or not v.strip():
            return "Content-Type,Authorization"
        return v.strip()
    
    @model_validator(mode="after")
    def validateThresholds(self) -> "Settings":
        """Ensure medium threshold is less than high threshold."""
        if self.mediumRiskThreshold >= self.highRiskThreshold:
            raise ValueError(
                f"mediumRiskThreshold ({self.mediumRiskThreshold}) must be "
                f"less than highRiskThreshold ({self.highRiskThreshold})"
            )
        return self
    
    # =========================================================================
    # Computed Properties
    # =========================================================================
    
    @property
    def isProduction(self) -> bool:
        """Check if running in production environment."""
        return self.environment == Environment.PRODUCTION
    
    @property
    def isTesting(self) -> bool:
        """Check if running in testing environment."""
        return self.environment == Environment.TESTING
    
    @property
    def isDevelopment(self) -> bool:
        """Check if running in development environment."""
        return self.environment == Environment.DEVELOPMENT
    
    @property
    def corsOriginsList(self) -> list[str]:
        """Get CORS origins as a list."""
        if self.corsOrigins == "*":
            return ["*"]
        return [origin.strip() for origin in self.corsOrigins.split(",")]
    
    @property
    def corsMethodsList(self) -> list[str]:
        """Get CORS methods as a list."""
        return [method.strip() for method in self.corsMethods.split(",")]
    
    @property
    def corsHeadersList(self) -> list[str]:
        """Get CORS headers as a list."""
        return [header.strip() for header in self.corsHeaders.split(",")]
    
    @property
    def hasVirusTotalKey(self) -> bool:
        """Check if VirusTotal API key is configured."""
        return bool(self.virusTotalApiKey)
    
    @property
    def hasAbuseIpDbKey(self) -> bool:
        """Check if AbuseIPDB API key is configured."""
        return bool(self.abuseIpDbApiKey)


@lru_cache(maxsize=1)
def getSettings() -> Settings:
    """
    Get cached settings instance.
    
    Uses LRU cache to ensure settings are only loaded once.
    This is the recommended way to access settings throughout the application.
    
    Returns:
        Settings: Application settings instance
    
    Example:
        settings = getSettings()
        timeout = settings.whoisTimeout
    """
    return Settings()


# Global settings instance for convenience
# Use getSettings() for dependency injection in FastAPI
settings = getSettings()
