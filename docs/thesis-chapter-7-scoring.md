# Chapter 7: Scoring and Classification

## 7.1 The Orchestration of Intelligence

A primary challenge in engineering a multi-modal threat detection platform is the synthesis of disparate analytical signals into a unified, actionable verdict. PhishGuard achieves this through a sophisticated scoring and classification engine that seamlessly bridges the continuous probabilistic output of the XGBoost machine learning model with discrete, rule-based heuristic indicators.

This architecture ensures that the system is not only highly accurate but also highly transparent, providing Security Operations Center (SOC) analysts and end-users with explicit, human-readable explanations for every classification.

## 7.2 The ML Predictor Architecture

The core inference engine is housed within the `backend/ml/predictor.py` module. To guarantee high-throughput and sub-millisecond inference times during production deployment, the `PhishingPredictor` class is implemented utilizing a thread-safe Singleton design pattern. 

### 7.1.1 Thread-Safe Initialization
During the FastAPI application startup sequence, the `PhishingPredictor` invokes its `__new__` method, locking the execution thread (`threading.Lock()`) to instantiate the XGBoost model exactly once. The model weights are loaded into memory from `models/phishingModel.json`, alongside the strict 21-dimensional feature schema defined in `modelMetadata.json`. Once initialized, the model state becomes immutable, allowing the asynchronous web server to process concurrent inference requests across multiple threads without encountering race conditions or requiring continuous disk I/O operations.

### 7.1.2 Inference Execution
When a URL analysis request is routed to the predictor, the 21-dimensional `FeatureSet` is cast into a strongly typed `numpy.ndarray` (`dtype=np.float64`). The `predict()` method invokes the XGBoost `predict_proba` function, returning a continuous probability bounded between 0.0 and 1.0, representing the mathematical likelihood that the input belongs to the malicious class.

---

## 7.3 The Phishing Scorer Module

While the XGBoost probability serves as the primary ground truth for URL inputs, it operates as an opaque numerical value. To resolve the black-box interpretability crisis, the `backend/ml/scorer.py` module introduces a parallel heuristic scoring engine that reverse-engineers the threat context.

### 7.3.1 Explanatory Heuristics
Regardless of whether the XGBoost model is active, the `PhishingScorer` executes three discrete heuristic calculators to generate the human-readable `factors` array that will be presented to the user:
1.  **`calculateUrlStructureScore`:** Applies deterministic penalty weights to structural anomalies. For example, a URL length exceeding 75 characters generates a scaling penalty (`min((urlLength - 75) / 100, 0.3)`), while the presence of raw IP addresses or Suspicious TLDs adds fixed penalties.
2.  **`calculateOsintScore`:** Evaluates the infrastructure context. If `isNewlyRegistered` is true (domain age < 30 days), a 0.35 penalty is recorded. Detection in third-party blacklists adds up to a 0.5 penalty.
3.  **`calculateFeatureScore`:** Analyzes holistic combinations that indicate sophisticated evasion, such as a newly registered domain combined with the presence of suspicious keywords in the URI string (`score += 0.3`).

### 7.3.2 Graceful Heuristic Fallback
In the event of a catastrophic failure where the compiled XGBoost model cannot be loaded into memory, the `PhishingScorer` implements a graceful degradation protocol. Instead of halting the application, it relies entirely on the heuristic calculators, combining their raw outputs using the strict constants defined in the `ScoringWeights` dataclass:
-   **URL Structure:** 25% weight
-   **OSINT Derived:** 35% weight
-   **Feature Based:** 40% weight

This fallback mechanism ensures the platform remains operational and capable of identifying overt threats even during degraded system states.

---

## 7.4 Risk Level Determination

The final continuous score (whether derived from the XGBoost probability or the heuristic fallback) is mapped to discrete, actionable categories using the strict boundaries defined in the `RISK_THRESHOLDS` dictionary:

-   **Safe (Score < 0.20):** The domain exhibits normal structural characteristics, extensive DNS history, and clean reputation metrics.
-   **Low Risk (Score < 0.40):** Minor anomalies detected, often typical of newly registered legitimate businesses or non-standard tracking URLs.
-   **Medium Risk / Suspicious (Score < 0.60):** The domain exhibits multiple characteristics commonly associated with phishing infrastructure, requiring explicit user verification.
-   **High Risk (Score < 0.80):** Strong indications of malicious intent, such as obscured IPs, known bad TLDs, or missing MX records on a young domain.
-   **Critical (Score $\ge$ 0.80):** Definitive malicious classification. The XGBoost model expresses supreme confidence in the threat, or the domain has been explicitly flagged by external threat intelligence APIs.

### 7.4.1 Reason Prioritization
To prevent alert fatigue and ensure the user interface remains uncluttered, the `_prioritizeReasons` method deduplicates and sorts the aggregated heuristic factors. It employs a keyword-based sorting algorithm, ensuring that highly critical warnings (e.g., "malicious," "ip address," "newly registered") are prioritized at the top of the array, while lower-severity structural warnings are pushed down or truncated. The final output is strictly limited to the top 10 most relevant reasons.

---

**End of Chapter 7**