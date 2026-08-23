"""Template-Based Explanation Engine
====================================

Deterministic natural-language explanations for URL verdicts.

Unlike an LLM, every sentence is derived from a concrete feature value or
OSINT signal, so explanations are reproducible, auditable, and require no
API key.  Feature ranking is informed by the *global signed-mean SHAP
values* computed at training time (``data/evaluation/
shap_signed_mean_report.json``): signals on features that historically
push predictions towards ``phishing`` are surfaced first.

Usage
-----
>>> from backend.ml.explainer import getExplainer
>>> report = getExplainer().explain(featureSet, osintData)
>>> report.summary
'Flagged primarily because the domain was registered 6 days ago ...'
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Optional

__all__ = ["PhishingExplainer", "getExplainer"]

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _item(
    signal: str,
    severity: str,
    weight: float,
    detail: str,
) -> tuple[tuple[int, float], dict[str, str]]:
    """Create a severity-sorted entry: (sort key, plain-dict item)."""
    return (
        (_SEVERITY_RANK[severity], -weight),
        {"signal": signal, "severity": severity, "detail": detail},
    )

_MODEL_DIR = Path(__file__).resolve().parent / "models"
_PROJECT_EVAL_DIR = _MODEL_DIR.parents[1].parent / "data" / "evaluation"


def _loadShapWeights() -> dict[str, float]:
    """Load absolute global SHAP weights (feature -> importance)."""
    candidates = [
        _MODEL_DIR / "explanationWeights.json",
        _PROJECT_EVAL_DIR / "shap_signed_mean_report.json",
    ]
    for path in candidates:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            raw = doc.get(
                "feature_signed_mean_shap", doc.get("weights", {})
            )
            if isinstance(raw, dict) and raw:
                return {k: abs(float(v)) for k, v in raw.items()}
        except (OSError, ValueError, TypeError):
            continue
    return {}


class PhishingExplainer:
    """Rule-based explanation generator over the raw feature vector.

    Items are plain dicts (``signal``/``severity``/``detail``) so they can
    be assigned directly to the Pydantic ``ExplanationReport`` response
    field.
    """

    def __init__(self, weights: Optional[dict[str, float]] = None) -> None:
        self._weights = weights if weights is not None else _loadShapWeights()

    # -- helpers -------------------------------------------------------

    def _w(self, feature: str) -> float:
        return self._weights.get(feature, 0.01)

    # -- public API ----------------------------------------------------

    def explain(
        self,
        featureSet: Any,
        osintData: Any = None,
    ) -> dict[str, Any]:
        """Build a severity-ordered explanation report for one analysis."""
        urlF = featureSet.urlFeatures
        entries: list[tuple[tuple[int, float], dict[str, str]]] = []

        # --- URL structural signals ---------------------------------
        if urlF.urlLength > 100:
            sev = "critical"
        elif urlF.urlLength > 75:
            sev = "high"
        elif urlF.urlLength > 60:
            sev = "medium"
        else:
            sev = ""
        if sev:
            entries.append(_item(
                "urlLength", sev, self._w("urlLength"),
                f"The URL is unusually long ({urlF.urlLength} characters); "
                "length is a common obfuscation tactic.",
            ))

        if urlF.hasIpAddress:
            entries.append(_item(
                "hasIpAddress", "high", self._w("hasIpAddress"),
                "The link uses a raw IP address instead of a domain name.",
            ))

        if urlF.hasAtSymbol:
            entries.append(_item(
                "hasAtSymbol", "high", self._w("hasAtSymbol"),
                "The URL contains an '@' symbol, which can hide the real "
                "destination from users.",
            ))

        if not urlF.isHttps:
            entries.append(_item(
                "isHttps", "medium", self._w("isHttps"),
                "The connection does not use HTTPS, so it lacks transport "
                "encryption.",
            ))

        if urlF.hasSuspiciousTld:
            entries.append(_item(
                "hasSuspiciousTld", "high", self._w("hasSuspiciousTld"),
                "The domain uses a TLD frequently abused in phishing "
                "campaigns (.tk, .ml, .xyz, etc.).",
            ))

        if urlF.hasSuspiciousKeywords:
            entries.append(_item(
                "hasSuspiciousKeywords", "high", self._w("hasSuspiciousKeywords"),
                "The URL contains keywords typical of phishing lures such as "
                "'login', 'verify', or 'secure'.",
            ))

        if urlF.subdomainCount >= 3:
            entries.append(_item(
                "subdomainCount", "high", self._w("subdomainCount"),
                f"The URL nests {urlF.subdomainCount} subdomain levels, a "
                "technique used to imitate trusted brands.",
            ))
        elif urlF.subdomainCount == 2:
            entries.append(_item(
                "subdomainCount", "low", self._w("subdomainCount"),
                f"The URL contains {urlF.subdomainCount} nested subdomains.",
            ))

        if urlF.hasEncodedChars:
            entries.append(_item(
                "hasEncodedChars", "medium", self._w("hasEncodedChars"),
                "The URL contains percent-encoded characters that may hide "
                "its true destination.",
            ))

        if urlF.digitRatio > 0.5:
            entries.append(_item(
                "digitRatio", "high", self._w("digitRatio"),
                f"{round(urlF.digitRatio * 100)}% of the domain consists of "
                "digits, which is atypical for legitimate domains.",
            ))
        elif urlF.digitRatio > 0.3:
            entries.append(_item(
                "digitRatio", "medium", self._w("digitRatio"),
                f"{round(urlF.digitRatio * 100)}% of the domain consists of "
                "digits.",
            ))

        if urlF.specialCharCount > 10:
            entries.append(_item(
                "specialCharCount", "medium", self._w("specialCharCount"),
                f"The URL contains {urlF.specialCharCount} special "
                "characters, more than usual.",
            ))

        if urlF.hasPortNumber:
            entries.append(_item(
                "hasPortNumber", "medium", self._w("hasPortNumber"),
                "An explicit port number appears in the URL, which is rare "
                "for legitimate sites.",
            ))

        if urlF.domainLength > 30:
            entries.append(_item(
                "domainLength", "medium", self._w("domainLength"),
                f"The domain name is very long ({urlF.domainLength} "
                "characters).",
            ))

        if urlF.pathDepth > 4:
            entries.append(_item(
                "pathDepth", "low", self._w("pathDepth"),
                f"The URL path is {urlF.pathDepth} levels deep.",
            ))

        # --- OSINT signals -------------------------------------------
        if osintData is not None:
            whois = getattr(osintData, "whois", None)
            if whois is not None:
                age = getattr(whois, "domainAgeDays", None)
                if age is not None and age < 30:
                    entries.append(_item(
                        "newlyRegisteredDomain", "critical",
                        max(self._w("domainAgeDays"), 0.05),
                        f"The domain was registered only {age} days ago; "
                        "fresh domains are a strong phishing indicator.",
                    ))
                elif age is not None and age < 365:
                    entries.append(_item(
                        "youngDomain", "medium",
                        max(self._w("domainAgeDays"), 0.02),
                        f"The domain is less than a year old ({age} days).",
                    ))
                if getattr(whois, "isPrivacyProtected", False):
                    entries.append(_item(
                        "whoisPrivacy", "low", 0.02,
                        "The domain owner hides behind WHOIS privacy "
                        "protection.",
                    ))

            reputation = getattr(osintData, "reputation", None)
            if reputation is not None:
                malicious = getattr(reputation, "maliciousCount", 0) or 0
                if malicious > 0:
                    entries.append(_item(
                        "blacklisted", "critical",
                        0.20,
                        f"The domain is flagged by {malicious} blacklist "
                        "source(s).",
                    ))
                score = getattr(reputation, "aggregateScore", 0.0) or 0.0
                if score >= 0.5:
                    entries.append(_item(
                        "poorReputation", "high",
                        0.08,
                        f"Aggregate reputation score is {score:.2f} "
                        "(higher means worse).",
                    ))

            dns = getattr(osintData, "dns", None)
            if dns is not None:
                resolved = any(
                    getattr(dns, field, None)
                    for field in ("aRecords", "aaaaRecords", "nsRecords", "cnameRecords")
                )
                if not resolved:
                    entries.append(_item(
                        "noDnsRecords", "medium", 0.03,
                        "No DNS records could be resolved for the domain.",
                    ))

        # --- assemble -------------------------------------------------
        entries.sort(key=lambda pair: pair[0])
        items = [entry[1] for entry in entries]

        if not items:
            summary = (
                "No individual risk signals stand out; the verdict follows "
                "from the overall pattern of the analysed content."
            )
        else:
            lead = items[0]
            connectors = {
                "critical": "Flagged primarily because ",
                "high": "A major factor is that ",
                "medium": "One contributing factor: ",
                "low": "Minor note: ",
            }
            extra = len(items) - 1
            tail = (
                f" {extra} additional signal(s) were detected."
                if extra > 0 else ""
            )
            detail = lead["detail"]
            summary = (
                connectors[lead["severity"]]
                + detail[0].lower() + detail[1:]
                + tail
            )

        return {"summary": summary, "items": items}


# ---------------------------------------------------------------------------
# Process-wide singleton (lazy; swappable in tests)
# ---------------------------------------------------------------------------

_explainer: Optional[PhishingExplainer] = None
_explainerLock = threading.Lock()


def getExplainer() -> PhishingExplainer:
    """Return the process-wide explainer, creating it on first use."""
    global _explainer
    with _explainerLock:
        if _explainer is None:
            _explainer = PhishingExplainer()
        return _explainer


def setExplainer(explainer: Optional[PhishingExplainer]) -> None:
    """Replace the process-wide explainer (used by tests)."""
    global _explainer
    with _explainerLock:
        _explainer = explainer
