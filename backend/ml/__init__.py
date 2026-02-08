"""
ML Module - Machine Learning Feature Extraction and Scoring
============================================================

This module provides URL analysis, feature extraction, and phishing
risk scoring capabilities for the phishing detection system.

Components:
- schemas: Pydantic models for ML data structures
- featureExtractor: URL and OSINT feature extraction
- urlAnalyzer: Deep URL structural analysis
- scorer: Phishing risk scoring with explainability

Usage:
    from ml import scoreUrl, extractFeatures, analyzeUrl
    
    # Quick scoring
    result = scoreUrl("https://suspicious-site.tk/login")
    print(result.riskLevel)  # RiskLevel.HIGH
    
    # Feature extraction
    features = extractFeatures("https://example.com")
    print(features.urlFeatures.isHttps)  # True
    
    # URL analysis
    analysis = analyzeUrl("https://paypal-verify.example.tk")
    print(len(analysis.suspiciousPatterns))  # 2

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

# =============================================================================
# Schema Exports
# =============================================================================

from .schemas import (
    # Enumerations
    FeatureCategory,
    RiskLevel,
    # URL Features
    UrlFeatures,
    # OSINT Features
    OsintFeatures,
    # Combined Features
    FeatureSet,
    # Scoring Models
    ScoreComponent,
    RiskScore,
    # URL Analysis Models
    SuspiciousPattern,
    UrlAnalysisResult,
)

# =============================================================================
# Feature Extractor Exports
# =============================================================================

from .featureExtractor import (
    # Main class
    FeatureExtractor,
    # Convenience function
    extractFeatures,
    # Low-level functions
    extractUrlFeatures,
    extractOsintFeatures,
    # Constants
    SUSPICIOUS_TLDS,
    SUSPICIOUS_KEYWORDS,
)

# =============================================================================
# URL Analyzer Exports
# =============================================================================

from .urlAnalyzer import (
    # Main class
    UrlAnalyzer,
    # Convenience functions
    analyzeUrl,
    detectBrandImpersonation,
    detectUrlObfuscation,
    getUrlRiskLevel,
    # Pattern definitions (for extension)
    BRAND_PATTERNS,
    OBFUSCATION_PATTERNS,
    CREDENTIAL_PATTERNS,
    STRUCTURE_PATTERNS,
    URGENCY_PATTERNS,
    SUSPICIOUS_TLD_PATTERNS,
    ALL_PATTERNS,
    # Legitimate domains
    LEGITIMATE_BRAND_DOMAINS,
)

# =============================================================================
# Scorer Exports
# =============================================================================

from .scorer import (
    # Main class
    PhishingScorer,
    # Configuration
    ScoringWeights,
    RISK_THRESHOLDS,
    # Convenience functions
    scoreUrl,
    quickScore,
    isPhishing,
    getRiskLevel,
    # Component calculators (for testing)
    calculateUrlStructureScore,
    calculateOsintScore,
    calculateFeatureScore,
    determineRiskLevel,
    calculateConfidence,
)

# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # --- Enumerations ---
    "FeatureCategory",
    "RiskLevel",
    # --- Feature Models ---
    "UrlFeatures",
    "OsintFeatures",
    "FeatureSet",
    # --- Scoring Models ---
    "ScoreComponent",
    "RiskScore",
    # --- URL Analysis Models ---
    "SuspiciousPattern",
    "UrlAnalysisResult",
    # --- Feature Extractor ---
    "FeatureExtractor",
    "extractFeatures",
    "extractUrlFeatures",
    "extractOsintFeatures",
    "SUSPICIOUS_TLDS",
    "SUSPICIOUS_KEYWORDS",
    # --- URL Analyzer ---
    "UrlAnalyzer",
    "analyzeUrl",
    "detectBrandImpersonation",
    "detectUrlObfuscation",
    "getUrlRiskLevel",
    "BRAND_PATTERNS",
    "OBFUSCATION_PATTERNS",
    "CREDENTIAL_PATTERNS",
    "STRUCTURE_PATTERNS",
    "URGENCY_PATTERNS",
    "SUSPICIOUS_TLD_PATTERNS",
    "ALL_PATTERNS",
    "LEGITIMATE_BRAND_DOMAINS",
    # --- Scorer ---
    "PhishingScorer",
    "ScoringWeights",
    "RISK_THRESHOLDS",
    "scoreUrl",
    "quickScore",
    "isPhishing",
    "getRiskLevel",
    "calculateUrlStructureScore",
    "calculateOsintScore",
    "calculateFeatureScore",
    "determineRiskLevel",
    "calculateConfidence",
]
