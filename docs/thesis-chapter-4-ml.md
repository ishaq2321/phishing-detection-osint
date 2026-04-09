# Chapter 4: Feature Engineering and ML Model

## 4.1 Dataset Collection and Preprocessing

The efficacy of any supervised machine learning classifier is fundamentally constrained by the quality and representativeness of its training data. For the PhishGuard project, curating a highly reliable dataset was a primary objective to ensure the model's generalization capabilities against zero-day phishing infrastructure.

### 4.1.1 Data Aggregation
The initial dataset comprised an aggregation of 150,391 raw URLs. This corpus was constructed by combining verified malicious URLs sourced from community-driven threat intelligence feeds (such as PhishTank and OpenPhish) with legitimate, benign URLs sampled from the Alexa Top 1 Million and Tranco ranking lists. This massive initial pool ensured a diverse representation of both typical corporate domains and highly obfuscated phishing links.

### 4.1.2 Cleaning and Balancing
Raw, crowd-sourced data inherently contains noise, dead links, and class imbalances. To establish a pristine baseline for the classifier, a rigorous data engineering pipeline was executed:
1.  **Deduplication:** Identical URLs and redundant subdomains resolving to the same infrastructure were purged to prevent data leakage between training splits.
2.  **Zero-Variance Filtering:** Features that provided no discriminative value across the dataset were algorithmically removed.
3.  **Majority Undersampling:** Real-world phishing datasets often suffer from severe class imbalance (e.g., significantly more benign sites than active phishing sites). To prevent the classifier from developing a bias toward the majority class (which artificially inflates accuracy at the expense of recall), the dataset underwent strict majority undersampling. 

The culmination of this preprocessing pipeline yielded a highly curated, perfectly balanced dataset containing exactly 33,392 feature-engineered URLs. This dataset was subsequently partitioned using a strict 70/15/15 stratified split (Training, Validation, and Testing sets) to ensure the target variable distribution remained consistent across all folds.

---

## 4.2 Feature Engineering Pipeline

The architectural philosophy of PhishGuard explicitly rejects the "black-box" deep learning approach of raw character sequence ingestion in favor of explicit, mathematically formulated feature engineering. The system extracts a highly discriminative, 21-dimensional feature vector (`FeatureSet`) partitioned into two distinct categories.

### 4.2.1 Lexical and Structural Features (17 Dimensions)
The `extractFeatures.py` module parses the raw URL string to extract 17 deterministic structural indicators. These heuristics capture the traditional syntactic anomalies favored by attackers:
-   **Length Metrics:** `urlLength`, `domainLength`, `pathDepth`.
-   **Character Composition:** `digitRatio`, `specialCharCount`, `hasEncodedChars`.
-   **Structural Anomalies:** `subdomainCount`, `hasIpAddress` (attackers bypassing DNS), `hasAtSymbol` (credential spoofing in the URI), `hasDoubleSlash`, `hasDashInDomain`, `hasUnderscoreInDomain`.
-   **Protocol and Routing:** `isHttps`, `hasPortNumber`, `queryParamCount`.
-   **Domain Categorization:** `hasSuspiciousTld` (e.g., matching against known high-abuse generic Top-Level Domains like `.tk`, `.ml`), `hasSuspiciousKeywords` (e.g., 'login', 'secure', 'verify').

### 4.2.2 OSINT Infrastructure Features (4 Dimensions)
To resolve the contextual blindness inherent in purely lexical models, the feature vector is augmented with 4 dynamically retrieved Open-Source Intelligence indicators via the asynchronous OSINT pipeline:
1.  **`hasValidMx` (Boolean):** Indicates the presence of valid Mail Exchange records. Phishing domains rarely configure legitimate email routing infrastructure.
2.  **`usesCdn` (Boolean):** Detects if the domain is hidden behind a Content Delivery Network (e.g., Cloudflare) via CNAME analysis.
3.  **`dnsRecordCount` (Integer):** A volumetric metric of the domain's overall DNS footprint. Legitimate enterprise domains typically possess extensive, complex DNS configurations.
4.  **`hasValidDns` (Boolean):** Verifies if the domain successfully resolves to an A/AAAA record, confirming the infrastructure is currently active.

---

## 4.3 Model Selection and Optimization

### 4.3.1 The XGBoost Algorithm
Following the extraction of the 21-dimensional feature vector, the system employs the eXtreme Gradient Boosting (`XGBClassifier`) algorithm. XGBoost was selected over deep neural networks due to its supreme performance on structured tabular data, robust handling of non-linear feature interactions, and computational efficiency (allowing for sub-millisecond CPU inference in a production environment). The model utilizes a `binary:logistic` objective function, outputting a continuous probability score bounded between 0.0 and 1.0.

### 4.3.2 Bayesian Hyperparameter Optimization (Optuna)
To maximize predictive performance, the model's hyperparameters were not manually tuned but rather rigorously optimized using the Optuna framework. The optimization pipeline executed 50 independent trials (`nTrials = 50`) utilizing 5-fold Stratified Cross-Validation (`nCvFolds = 5`). 

The optimization search space targeted critical tree structural parameters. The mathematically proven best configuration (Trial 43) yielded the following hyperparameters:
-   `n_estimators`: 700 (Number of boosting rounds)
-   `max_depth`: 7 (Maximum tree depth, controlling interaction complexity)
-   `learning_rate`: ~0.177 (Step size shrinkage)
-   `subsample`: ~0.945 (Row sampling ratio to prevent overfitting)
-   `colsample_bytree`: ~0.873 (Column sampling ratio per tree)
-   `gamma`: ~0.198 (Minimum loss reduction required for partitioning)
-   `min_child_weight`: 1
-   L1/L2 Regularization: `reg_alpha` = ~0.00027, `reg_lambda` = ~0.397

This exhaustive 222-second optimization process ensured the model was perfectly calibrated to the specific variance of the 33,392 URL dataset.

---

## 4.4 Model Explainability via SHAP

A cornerstone objective of the PhishGuard architecture is resolving the "black-box" interpretability crisis common in machine learning cybersecurity tools. To achieve this, the system implements a mathematically rigorous explainability framework using SHAP (SHapley Additive exPlanations).

The `shapAnalysis.py` module integrates the `shap.TreeExplainer`, which utilizes cooperative game theory to calculate the exact marginal contribution of every single feature to the final prediction. Because XGBoost 3.x utilizes a bracketed format for its `base_score` (e.g., `[5E-1]`), a custom monkey-patch (`_patchShapXgboostCompat`) was engineered to ensure seamless compatibility with the SHAP explainer.

**[FIGURE 4-1: SHAP Feature Importance (Beeswarm Plot)]**
*Description: A plot displaying the global impact distribution of the 21 features.*
*How to create:*
1. Run the `backend/ml/training/shapAnalysis.py` script.
2. The script will automatically generate the beeswarm plot using `matplotlib` and `seaborn`.
3. Locate the output image at `data/evaluation/shap_summary.png`.
4. Insert the generated PNG here.

This SHAP integration allows the backend to decompose a 96% phishing probability into human-readable insights (e.g., exactly how much the `hasValidMx` feature influenced the score), which the Next.js frontend dynamically renders as interactive waterfall charts for the end-user.

---

## 4.5 Performance Evaluation

The optimized XGBoost model underwent rigorous evaluation against the held-out test split. The empirical results definitively validate the efficacy of the 21-dimensional feature engineering pipeline:

-   **Test Accuracy:** 96.45%
-   **Test F1-Score:** 96.39%
-   **Test Precision:** 97.86%
-   **Test Recall:** 94.97%
-   **Test ROC-AUC:** 99.41%

These metrics indicate an exceptionally high-performing classifier. The 97.86% precision rate is particularly critical in a cybersecurity context, as it minimizes "false positives" (flagging legitimate corporate domains as malicious), thereby reducing alert fatigue for Security Operations Center (SOC) analysts. The 99.41% Area Under the Receiver Operating Characteristic Curve (ROC-AUC) proves the model's supreme capability in distinctly separating the Phishing and Legitimate classes based on the synthesized lexical and OSINT features.

---

**End of Chapter 4**