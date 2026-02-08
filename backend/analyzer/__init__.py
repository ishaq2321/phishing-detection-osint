"""
Analyzer Module
===============

Content analysis and phishing detection using NLP and pattern matching.

This module provides abstract interfaces and concrete implementations for
analyzing text, emails, and URLs to detect phishing attempts.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from .base import (
    AnalysisResult,
    BaseAnalyzer,
    ContentType,
    DetectedIndicator,
    PhishingTactic,
    ThreatLevel,
    detectContentType,
    determineThreatLevel,
)
from .nlpAnalyzer import NlpAnalyzer

__all__ = [
    # Base classes and models
    "BaseAnalyzer",
    "AnalysisResult",
    "DetectedIndicator",
    
    # Enums
    "ContentType",
    "ThreatLevel",
    "PhishingTactic",
    
    # Helper functions
    "detectContentType",
    "determineThreatLevel",
    
    # Concrete implementations
    "NlpAnalyzer",
]
