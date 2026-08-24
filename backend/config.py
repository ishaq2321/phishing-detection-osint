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

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _envAlias(fieldName: str, envName: str) -> AliasChoices:
    """Accept BOTH the camelCase field name and the UPPER_SNAKE env var.

    pydantic-settings < 2.2 matches env names case-insensitively but
    does NOT ignore underscores: a field ``corsOrigins`` only matched
    ``CORSORIGINS``, silently ignoring the documented ``CORS_ORIGINS``.
    This explicit alias restores the operator-facing contract without
    a dependency upgrade.
    """
    return AliasChoices(fieldName, envName)


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
        # The per-field ``validation_alias`` replaces the field name as
        # the accepted init key; keep ``Settings(whoisTimeout=0)``
        # (used across tests) working.
        populate_by_name=True,
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
        validation_alias=_envAlias("analyzerEngine", "ANALYZER_ENGINE"),
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
        validation_alias=_envAlias("whoisTimeout", "WHOIS_TIMEOUT"),
        description="WHOIS lookup timeout in seconds"
    )
    
    dnsTimeout: int = Field(
        default=5,
        ge=1,
        le=30,
        validation_alias=_envAlias("dnsTimeout", "DNS_TIMEOUT"),
        description="DNS resolution timeout in seconds"
    )
    
    reputationTimeout: int = Field(
        default=10,
        ge=1,
        le=60,
        validation_alias=_envAlias("reputationTimeout", "REPUTATION_TIMEOUT"),
        description="Reputation API request timeout in seconds"
    )

    osintTimeout: int = Field(
        default=25,
        ge=5,
        le=60,
        validation_alias=_envAlias("osintTimeout", "OSINT_TIMEOUT"),
        description=(
            "Global budget for the parallel OSINT collection phase. "
            "Sources that finish within the budget are kept even when a "
            "sibling source is slow — only the slow source is discarded."
        )
    )

    maxRetries: int = Field(
        default=3,
        ge=0,
        le=10,
        validation_alias=_envAlias("maxRetries", "MAX_RETRIES"),
        description="Maximum retry attempts for failed requests"
    )
    
    retryDelaySeconds: float = Field(
        default=1.0,
        ge=0.1,
        le=10.0,
        validation_alias=_envAlias("retryDelaySeconds", "RETRY_DELAY_SECONDS"),
        description="Delay between retry attempts in seconds"
    )
    
    # =========================================================================
    # External API Keys (Optional - for enhanced detection)
    # =========================================================================
    
    virusTotalApiKey: Optional[str] = Field(
        default=None,
        validation_alias=_envAlias("virusTotalApiKey", "VIRUSTOTAL_API_KEY"),
        description="VirusTotal API key for reputation checks"
    )
    
    abuseIpDbApiKey: Optional[str] = Field(
        default=None,
        validation_alias=_envAlias("abuseIpDbApiKey", "ABUSEIPDB_API_KEY"),
        description="AbuseIPDB API key for IP reputation"
    )

    # =========================================================================
    # API Settings
    # =========================================================================
    
    corsOrigins: str = Field(
        default="*",
        validation_alias=_envAlias("corsOrigins", "CORS_ORIGINS"),
        description="Allowed CORS origins (comma-separated or * for all)"
    )
    
    corsMethods: str = Field(
        default="GET,POST,OPTIONS",
        validation_alias=_envAlias("corsMethods", "CORS_METHODS"),
        description="Allowed CORS HTTP methods (comma-separated)"
    )
    
    corsHeaders: str = Field(
        default="Content-Type,Authorization",
        validation_alias=_envAlias("corsHeaders", "CORS_HEADERS"),
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
    # EML Ingestion (Tier 4 E)
    # =========================================================================

    emlMaxBytes: int = Field(
        default=1_000_000,
        ge=1_024,
        le=50_000_000,
        validation_alias=_envAlias("emlMaxBytes", "EML_MAX_BYTES"),
        description=(
            "Maximum accepted raw .eml payload size in bytes "
            "(EML_MAX_BYTES).  Larger uploads are rejected with HTTP "
            "413 before any parsing happens."
        ),
    )

    # =========================================================================
    # Analysis Thresholds
    # =========================================================================
    
    highRiskThreshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        validation_alias=_envAlias("highRiskThreshold", "HIGH_RISK_THRESHOLD"),
        description="Score threshold for high risk classification"
    )
    
    mediumRiskThreshold: float = Field(
        default=0.4,
        ge=0.0,
        le=1.0,
        validation_alias=_envAlias("mediumRiskThreshold", "MEDIUM_RISK_THRESHOLD"),
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
