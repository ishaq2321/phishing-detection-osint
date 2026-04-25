"""
NLP Analyzer Module
===================

NLP-based phishing content analyzer using spaCy.

This analyzer uses rule-based pattern matching with spaCy's modern
components to detect phishing indicators without requiring ML training.
It's designed to be fast, explainable, and effective for common phishing tactics.

Components:
- EntityRuler: Brand/authority impersonation detection
- PhraseMatcher: Urgency and threat phrase detection
- Token patterns: Suspicious request patterns
- URL analysis: Link manipulation detection

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

import re
import time
from urllib.parse import urlparse

import spacy
from spacy.language import Language
from spacy.matcher import PhraseMatcher
from spacy.tokens import Doc

from .base import (
    AnalysisResult,
    BaseAnalyzer,
    ContentType,
    DetectedIndicator,
    PhishingTactic,
    detectContentType,
    determineThreatLevel,
)


# =============================================================================
# Pattern Definitions
# =============================================================================

# Urgency keywords that create time pressure
URGENCY_PHRASES = [
    "act now",
    "immediately",
    "urgent",
    "expires today",
    "within 24 hours",
    "limited time",
    "hurry",
    "last chance",
    "don't wait",
    "time sensitive",
    "expires soon",
    "act fast",
    "right now",
    "before it's too late",
]

# Threat and fear phrases
THREAT_PHRASES = [
    "account suspended",
    "account closed",
    "unauthorized access",
    "security alert",
    "suspicious activity",
    "unusual activity",
    "compromised",
    "locked out",
    "terminated",
    "restricted access",
    "account blocked",
    "legal action",
    "your account will be closed",
    "permanently deleted",
]

# Authority and brand impersonation indicators
AUTHORITY_TERMS = [
    "IT department",
    "IT support",
    "security team",
    "technical support",
    "customer service",
    "billing department",
    "account department",
    "system administrator",
    "help desk",
]

# Known brands commonly impersonated
COMMON_BRANDS = [
    "PayPal", "Microsoft", "Apple", "Amazon", "Google",
    "Facebook", "Instagram", "Netflix", "LinkedIn", "Dropbox",
    "Bank of America", "Wells Fargo", "Chase",
    "IRS", "FedEx", "DHL", "USPS",
]

# Credential and sensitive info requests
CREDENTIAL_PHRASES = [
    "verify your account",
    "confirm your identity",
    "update your password",
    "verify your email",
    "confirm your information",
    "validate your account",
    "re-enter your password",
    "provide your password",
    "enter your password",
    "enter your PIN",
    "confirm your SSN",
    "verify your card",
    "update payment information",
]

# Suspicious action requests
SUSPICIOUS_ACTIONS = [
    "click here",
    "click the link",
    "download the attachment",
    "open the attachment",
    "follow this link",
    "visit this page",
]

# Emotional manipulation phrases
EMOTIONAL_PHRASES = [
    "you have been selected",
    "congratulations",
    "you are a winner",
    "once in a lifetime",
    "don't miss out",
    "exclusive offer",
    "special deal just for you",
    "you deserve",
    "limited spots",
    "act now or lose",
]

# Monetary request phrases
MONETARY_PHRASES = [
    "wire transfer",
    "send money",
    "payment required",
    "processing fee",
    "advance fee",
    "transfer funds",
    "pay now",
    "send payment",
    "outstanding balance",
    "overdue payment",
    "claim your prize",
    "lottery winnings",
    "inheritance",
    "unclaimed funds",
    "beneficiary",
]

# Social proof / trust signals
SOCIAL_PROOF_PHRASES = [
    "millions of users",
    "trusted by",
    "as seen on",
    "verified by",
    "certified",
    "award-winning",
    "number one",
    "most popular",
    "everyone is using",
    "join millions",
]


# =============================================================================
# NLP Analyzer Implementation
# =============================================================================

class NlpAnalyzer(BaseAnalyzer):
    """
    NLP-based phishing analyzer using spaCy.
    
    Uses rule-based pattern matching with spaCy's EntityRuler and
    PhraseMatcher for fast, explainable phishing detection.
    
    Example:
        >>> analyzer = NlpAnalyzer()
        >>> result = await analyzer.analyze(
        ...     "Urgent! Your PayPal account will be suspended. Click here.",
        ...     ContentType.EMAIL
        ... )
        >>> result.isPhishing
        True
        >>> result.detectedTactics
        [PhishingTactic.URGENCY, PhishingTactic.BRAND_IMPERSONATION, ...]
    """
    
    def __init__(self, model: str = "en_core_web_sm") -> None:
        """
        Initialize the NLP analyzer.
        
        Args:
            model: spaCy model name to load (default: en_core_web_sm)
        """
        try:
            self.nlp: Language = spacy.load(model)
        except OSError:
            raise RuntimeError(
                f"spaCy model '{model}' not found. "
                f"Install it with: python -m spacy download {model}"
            )
        
        # Initialize matchers
        self._setupMatchers()
    
    def _setupMatchers(self) -> None:
        """Set up phrase matchers for pattern detection."""
        # Urgency matcher
        self.urgencyMatcher = PhraseMatcher(self.nlp.vocab, attr="LOWER")
        urgencyPatterns = [self.nlp.make_doc(text) for text in URGENCY_PHRASES]
        self.urgencyMatcher.add("URGENCY", urgencyPatterns)
        
        # Threat matcher
        self.threatMatcher = PhraseMatcher(self.nlp.vocab, attr="LOWER")
        threatPatterns = [self.nlp.make_doc(text) for text in THREAT_PHRASES]
        self.threatMatcher.add("THREAT", threatPatterns)
        
        # Authority matcher
        self.authorityMatcher = PhraseMatcher(self.nlp.vocab, attr="LOWER")
        authorityPatterns = [self.nlp.make_doc(text) for text in AUTHORITY_TERMS]
        self.authorityMatcher.add("AUTHORITY", authorityPatterns)
        
        # Brand matcher
        self.brandMatcher = PhraseMatcher(self.nlp.vocab)
        brandPatterns = [self.nlp.make_doc(text) for text in COMMON_BRANDS]
        self.brandMatcher.add("BRAND", brandPatterns)
        
        # Credential request matcher
        self.credentialMatcher = PhraseMatcher(self.nlp.vocab, attr="LOWER")
        credentialPatterns = [self.nlp.make_doc(text) for text in CREDENTIAL_PHRASES]
        self.credentialMatcher.add("CREDENTIAL", credentialPatterns)
        
        # Suspicious action matcher
        self.actionMatcher = PhraseMatcher(self.nlp.vocab, attr="LOWER")
        actionPatterns = [self.nlp.make_doc(text) for text in SUSPICIOUS_ACTIONS]
        self.actionMatcher.add("ACTION", actionPatterns)

        # Emotional manipulation matcher
        self.emotionalMatcher = PhraseMatcher(self.nlp.vocab, attr="LOWER")
        emotionalPatterns = [self.nlp.make_doc(text) for text in EMOTIONAL_PHRASES]
        self.emotionalMatcher.add("EMOTIONAL", emotionalPatterns)

        # Monetary request matcher
        self.monetaryMatcher = PhraseMatcher(self.nlp.vocab, attr="LOWER")
        monetaryPatterns = [self.nlp.make_doc(text) for text in MONETARY_PHRASES]
        self.monetaryMatcher.add("MONETARY", monetaryPatterns)

        # Social proof matcher
        self.socialProofMatcher = PhraseMatcher(self.nlp.vocab, attr="LOWER")
        socialProofPatterns = [self.nlp.make_doc(text) for text in SOCIAL_PROOF_PHRASES]
        self.socialProofMatcher.add("SOCIAL_PROOF", socialProofPatterns)
    
    async def analyze(
        self,
        content: str,
        contentType: ContentType = ContentType.AUTO
    ) -> AnalysisResult:
        """
        Analyze content for phishing indicators using NLP.
        
        Args:
            content: Text to analyze
            contentType: Type of content (auto-detected if AUTO)
            
        Returns:
            AnalysisResult: Analysis with detected indicators and verdict
            
        Raises:
            ValueError: If content is empty
        """
        startTime = time.time()
        
        # Validate input
        if not content or not content.strip():
            raise ValueError("Content cannot be empty")
        
        # Auto-detect content type if needed
        if contentType == ContentType.AUTO:
            contentType = detectContentType(content)
        
        # Process with spaCy
        doc: Doc = self.nlp(content)
        
        # Collect indicators
        indicators: list[DetectedIndicator] = []
        detectedTactics: set[PhishingTactic] = set()
        
        # Detect urgency
        urgencyIndicators = self._detectUrgency(doc)
        indicators.extend(urgencyIndicators)
        if urgencyIndicators:
            detectedTactics.add(PhishingTactic.URGENCY)
        
        # Detect threats
        threatIndicators = self._detectThreats(doc)
        indicators.extend(threatIndicators)
        if threatIndicators:
            detectedTactics.add(PhishingTactic.THREAT_WARNING)
        
        # Detect authority impersonation
        authorityIndicators = self._detectAuthority(doc)
        indicators.extend(authorityIndicators)
        if authorityIndicators:
            detectedTactics.add(PhishingTactic.AUTHORITY_IMPERSONATION)
        
        # Detect brand impersonation
        brandIndicators = self._detectBrands(doc)
        indicators.extend(brandIndicators)
        if brandIndicators:
            detectedTactics.add(PhishingTactic.BRAND_IMPERSONATION)
        
        # Detect credential requests
        credentialIndicators = self._detectCredentialRequests(doc)
        indicators.extend(credentialIndicators)
        if credentialIndicators:
            detectedTactics.add(PhishingTactic.CREDENTIAL_REQUEST)
        
        # Detect suspicious actions
        actionIndicators = self._detectSuspiciousActions(doc)
        indicators.extend(actionIndicators)
        if actionIndicators:
            detectedTactics.add(PhishingTactic.LINK_MANIPULATION)

        # Detect emotional manipulation
        emotionalIndicators = self._detectEmotionalManipulation(doc)
        indicators.extend(emotionalIndicators)
        if emotionalIndicators:
            detectedTactics.add(PhishingTactic.EMOTIONAL_MANIPULATION)

        # Detect monetary requests
        monetaryIndicators = self._detectMonetaryRequests(doc)
        indicators.extend(monetaryIndicators)
        if monetaryIndicators:
            detectedTactics.add(PhishingTactic.MONETARY_REQUEST)

        # Detect social proof
        socialProofIndicators = self._detectSocialProof(doc)
        indicators.extend(socialProofIndicators)
        if socialProofIndicators:
            detectedTactics.add(PhishingTactic.SOCIAL_PROOF)

        # Detect links (URL-specific)
        if contentType in [ContentType.EMAIL, ContentType.TEXT]:
            linkIndicators = self._detectLinkManipulation(content)
            indicators.extend(linkIndicators)
            if linkIndicators:
                detectedTactics.add(PhishingTactic.LINK_MANIPULATION)

            # Detect attachment malware indicators
            attachmentIndicators = self._detectAttachmentMalware(content, doc)
            indicators.extend(attachmentIndicators)
            if attachmentIndicators:
                detectedTactics.add(PhishingTactic.ATTACHMENT_MALWARE)
        
        # Calculate confidence score
        confidenceScore = self._calculateConfidence(indicators, detectedTactics)
        
        # Determine verdict
        isPhishing = confidenceScore >= 0.5
        threatLevel = determineThreatLevel(confidenceScore)
        
        # Generate reasons
        reasons = self._generateReasons(indicators, detectedTactics)
        
        # Calculate analysis time
        analysisTime = (time.time() - startTime) * 1000  # milliseconds
        
        return AnalysisResult(
            isPhishing=isPhishing,
            confidenceScore=confidenceScore,
            threatLevel=threatLevel,
            reasons=reasons,
            detectedTactics=list(detectedTactics),
            indicators=indicators,
            analysisTime=analysisTime,
        )
    
    def _detectUrgency(self, doc: Doc) -> list[DetectedIndicator]:
        """Detect urgency and time-pressure phrases."""
        indicators: list[DetectedIndicator] = []
        matches = self.urgencyMatcher(doc)
        
        for matchId, start, end in matches:
            span = doc[start:end]
            indicators.append(
                DetectedIndicator(
                    category="urgency",
                    description=f"Urgency phrase detected: '{span.text}'",
                    severity=0.7,
                    evidence=span.text,
                    position=span.start_char,
                )
            )
        
        return indicators
    
    def _detectThreats(self, doc: Doc) -> list[DetectedIndicator]:
        """Detect threat and fear-inducing phrases."""
        indicators: list[DetectedIndicator] = []
        matches = self.threatMatcher(doc)
        
        for matchId, start, end in matches:
            span = doc[start:end]
            indicators.append(
                DetectedIndicator(
                    category="threat",
                    description=f"Threat phrase detected: '{span.text}'",
                    severity=0.8,
                    evidence=span.text,
                    position=span.start_char,
                )
            )
        
        return indicators
    
    def _detectAuthority(self, doc: Doc) -> list[DetectedIndicator]:
        """Detect authority impersonation."""
        indicators: list[DetectedIndicator] = []
        matches = self.authorityMatcher(doc)
        
        for matchId, start, end in matches:
            span = doc[start:end]
            indicators.append(
                DetectedIndicator(
                    category="authority_impersonation",
                    description=f"Authority term detected: '{span.text}'",
                    severity=0.6,
                    evidence=span.text,
                    position=span.start_char,
                )
            )
        
        return indicators
    
    def _detectBrands(self, doc: Doc) -> list[DetectedIndicator]:
        """Detect brand mentions (potential impersonation)."""
        indicators: list[DetectedIndicator] = []
        matches = self.brandMatcher(doc)
        
        for matchId, start, end in matches:
            span = doc[start:end]
            indicators.append(
                DetectedIndicator(
                    category="brand_mention",
                    description=f"Brand mentioned: '{span.text}' (potential impersonation)",
                    severity=0.5,  # Lower severity - brand mention is suspicious but not definitive
                    evidence=span.text,
                    position=span.start_char,
                )
            )
        
        return indicators
    
    def _detectCredentialRequests(self, doc: Doc) -> list[DetectedIndicator]:
        """Detect credential/sensitive info requests."""
        indicators: list[DetectedIndicator] = []
        matches = self.credentialMatcher(doc)
        
        for matchId, start, end in matches:
            span = doc[start:end]
            indicators.append(
                DetectedIndicator(
                    category="credential_request",
                    description=f"Credential request detected: '{span.text}'",
                    severity=0.85,
                    evidence=span.text,
                    position=span.start_char,
                )
            )
        
        return indicators
    
    def _detectSuspiciousActions(self, doc: Doc) -> list[DetectedIndicator]:
        """Detect suspicious action requests."""
        indicators: list[DetectedIndicator] = []
        matches = self.actionMatcher(doc)

        for matchId, start, end in matches:
            span = doc[start:end]
            indicators.append(
                DetectedIndicator(
                    category="suspicious_action",
                    description=f"Suspicious action request: '{span.text}'",
                    severity=0.6,
                    evidence=span.text,
                    position=span.start_char,
                )
            )

        return indicators

    def _detectEmotionalManipulation(self, doc: Doc) -> list[DetectedIndicator]:
        """Detect emotional manipulation and appeal phrases."""
        indicators: list[DetectedIndicator] = []
        matches = self.emotionalMatcher(doc)

        for matchId, start, end in matches:
            span = doc[start:end]
            indicators.append(
                DetectedIndicator(
                    category="emotional_manipulation",
                    description=f"Emotional manipulation detected: '{span.text}'",
                    severity=0.5,
                    evidence=span.text,
                    position=span.start_char,
                )
            )

        return indicators

    def _detectMonetaryRequests(self, doc: Doc) -> list[DetectedIndicator]:
        """Detect monetary request and financial lure phrases."""
        indicators: list[DetectedIndicator] = []
        matches = self.monetaryMatcher(doc)

        for matchId, start, end in matches:
            span = doc[start:end]
            indicators.append(
                DetectedIndicator(
                    category="monetary_request",
                    description=f"Monetary request detected: '{span.text}'",
                    severity=0.7,
                    evidence=span.text,
                    position=span.start_char,
                )
            )

        return indicators

    def _detectSocialProof(self, doc: Doc) -> list[DetectedIndicator]:
        """Detect fake social proof and trust signals."""
        indicators: list[DetectedIndicator] = []
        matches = self.socialProofMatcher(doc)

        for matchId, start, end in matches:
            span = doc[start:end]
            indicators.append(
                DetectedIndicator(
                    category="social_proof",
                    description=f"Social proof / trust signal detected: '{span.text}'",
                    severity=0.4,
                    evidence=span.text,
                    position=span.start_char,
                )
            )

        return indicators

    def _detectAttachmentMalware(
        self, content: str, doc: Doc
    ) -> list[DetectedIndicator]:
        """Detect attachment-related malware indicators."""
        indicators: list[DetectedIndicator] = []
        suspiciousExtensions = [
            ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js",
            ".zip", ".rar", ".7z", ".docm", ".xlsm", ".pptm",
        ]
        contentLower = content.lower()
        for ext in suspiciousExtensions:
            if ext in contentLower:
                indicators.append(
                    DetectedIndicator(
                        category="attachment_malware",
                        description=f"Suspicious attachment extension detected: '{ext}'",
                        severity=0.8,
                        evidence=ext,
                    )
                )

        # Check for attachment-related phrases with action context
        attachmentActionPhrases = [
            "download the attachment",
            "open the attachment",
            "see attached",
            "find attached",
            "attached file",
        ]
        for phrase in attachmentActionPhrases:
            if phrase in contentLower:
                indicators.append(
                    DetectedIndicator(
                        category="attachment_malware",
                        description=f"Attachment action request: '{phrase}'",
                        severity=0.65,
                        evidence=phrase,
                    )
                )

        return indicators
    
    def _detectLinkManipulation(self, content: str) -> list[DetectedIndicator]:
        """Detect URL patterns that suggest link manipulation."""
        indicators: list[DetectedIndicator] = []
        
        # Find URLs in content
        urlPattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        urls = urlPattern.findall(content)
        
        for url in urls:
            # Check for IP addresses in URLs
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                indicators.append(
                    DetectedIndicator(
                        category="link_manipulation",
                        description="URL uses IP address instead of domain name",
                        severity=0.75,
                        evidence=url,
                    )
                )
            
            # Check for suspicious TLDs
            parsed = urlparse(url)
            if parsed.netloc:
                domain = parsed.netloc.lower()
                suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
                if any(domain.endswith(tld) for tld in suspiciousTlds):
                    indicators.append(
                        DetectedIndicator(
                            category="link_manipulation",
                            description=f"URL uses suspicious TLD: {domain}",
                            severity=0.7,
                            evidence=url,
                        )
                    )
        
        return indicators
    
    def _calculateConfidence(
        self,
        indicators: list[DetectedIndicator],
        tactics: set[PhishingTactic]
    ) -> float:
        """
        Calculate overall confidence score.
        
        Score is based on:
        - Number and severity of indicators
        - Diversity of tactics detected
        - Combinations of high-risk patterns
        """
        if not indicators:
            return 0.0
        
        # Base score from indicators
        indicatorScore = sum(ind.severity for ind in indicators) / max(len(indicators), 1)
        
        # Bonus for multiple tactics (indicates sophisticated phishing)
        tacticBonus = min(len(tactics) * 0.1, 0.3)
        
        # Combine scores
        confidence = min(indicatorScore + tacticBonus, 1.0)
        
        return round(confidence, 3)
    
    def _generateReasons(
        self,
        indicators: list[DetectedIndicator],
        tactics: set[PhishingTactic]
    ) -> list[str]:
        """Generate human-readable reasons for the verdict."""
        reasons: list[str] = []
        
        # Summarize by tactic
        if PhishingTactic.URGENCY in tactics:
            reasons.append("Creates artificial time pressure with urgency language")
        
        if PhishingTactic.THREAT_WARNING in tactics:
            reasons.append("Uses fear tactics and account suspension threats")
        
        if PhishingTactic.CREDENTIAL_REQUEST in tactics:
            reasons.append("Requests sensitive information or credentials")
        
        if PhishingTactic.BRAND_IMPERSONATION in tactics:
            reasons.append("Mentions known brands (potential impersonation)")
        
        if PhishingTactic.AUTHORITY_IMPERSONATION in tactics:
            reasons.append("Claims to be from official department or support")
        
        if PhishingTactic.LINK_MANIPULATION in tactics:
            reasons.append("Contains suspicious links or URLs")

        if PhishingTactic.EMOTIONAL_MANIPULATION in tactics:
            reasons.append("Uses emotional manipulation or appeal to greed")

        if PhishingTactic.MONETARY_REQUEST in tactics:
            reasons.append("Requests money transfer or mentions financial lure")

        if PhishingTactic.ATTACHMENT_MALWARE in tactics:
            reasons.append("References suspicious attachments or file types")

        if PhishingTactic.SOCIAL_PROOF in tactics:
            reasons.append("Uses fake social proof or trust signals")
        
        # Add high-severity indicator details
        highSeverity = [ind for ind in indicators if ind.severity > 0.7]
        if highSeverity:
            reasons.append(f"Contains {len(highSeverity)} high-severity indicators")
        
        return reasons[:10]  # Limit to top 10 reasons
    
    def getCapabilities(self) -> list[str]:
        """Get supported content types."""
        return ["url", "email", "text"]
    
    def getName(self) -> str:
        """Get analyzer name."""
        return "NLP Analyzer"
    
    def getVersion(self) -> str:
        """Get analyzer version."""
        return "1.0.0"
