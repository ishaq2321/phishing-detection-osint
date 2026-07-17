# Data Directory

## Overview

This directory contains the **evaluation artefacts and trained model** used
in the PhishGuard BSc thesis. Large raw datasets, intermediate processing
outputs, and live OSINT caches are **not** committed to this repository for
the reasons explained in the [Reproducibility Notes](#reproducibility-notes)
section below.

## Structure

```
data/
├── evaluation/                     # Committed to repo
│   ├── evaluation_report.json      # Test/val/train metrics (accuracy, F1,
│   │                               # AUC-ROC, PR-AUC) plus a ranked
│   │                               # gain-based feature importance list
│   ├── ablation_report.json        # OSINT ablation study results
│   ├── confusion_matrix.png        # Confusion matrix visualisation
│   ├── roc_curve.png               # ROC curve plot
│   ├── precision_recall_curve.png  # Precision-recall curve
│   ├── feature_importance.png      # XGBoost gain-based importance bar chart
│   ├── ablation_comparison.png     # With/without OSINT comparison
│   ├── shap_summary.png            # SHAP beeswarm summary plot
│   ├── shap_bar.png                # SHAP mean absolute bar chart
│   ├── shap_waterfall.png          # SHAP waterfall for a single prediction
│   └── shap_values.npy             # raw SHAP values array
└── README.md
```

The trained XGBoost model itself lives in
`backend/ml/models/phishingModel.json`.

## Reproducibility Notes

**The raw URL corpora and intermediate processed datasets are intentionally
not committed.** To reproduce the reported results from scratch, the
following pipeline must be executed locally:

```bash
# 1) Collect raw URLs (requires network access to PhishTank, OpenPhish,
#    and the Tranco top-sites list)
python -m backend.ml.training.collectPhishingUrls
python -m backend.ml.training.collectLegitimateUrls

# 2) Extract the 21-dimensional feature vector for every URL
python -m backend.ml.training.extractFeatures

# 3) Clean, deduplicate, balance, and split
python -m backend.ml.training.prepareDataset

# 4) Train the XGBoost classifier with Optuna hyperparameter search
python -m backend.ml.training.trainModel

# 5) Produce all evaluation artefacts (metrics, ablation, plots, SHAP)
python -m backend.ml.training.evaluateModel
python -m backend.ml.training.shapAnalysis
```

### Why the raw data is not in the repo

| Reason | Detail |
|---|---|
| **Size** | `features_raw.csv` exceeded ~150 MB and contained hundreds of thousands of rows. |
| **Licensing** | PhishTank data is for non-commercial research use and is dynamically updated; we do not redistribute verified phishing URLs verbatim. |
| **OSINT volatility** | WHOIS, DNS, and reputation data change over time. Cached snapshots become stale within weeks and would invalidate reproducibility guarantees. |
| **API-key sensitivity** | VirusTotal and AbuseIPDB lookups require paid API keys; embedding them in processed data would be a security risk. |

### What **is** reproducible from this repository

- The **trained model** (`backend/ml/models/phishingModel.json`) and its
  metadata (`modelMetadata.json`)
- The **evaluation reports** with exact numbers reported in the thesis
- The **SHAP analysis artefacts** (raw values + visualisations)
- All **ablation study results**
- The full **test suite** (600 backend pytest tests + 133 frontend Jest
  tests + 28 Playwright E2E browser tests) exercising every published
  metric

### Exact numbers recorded in `data/evaluation/evaluation_report.json`

The thesis reports these on page **Chapter 4 / Chapter 7** and they match
the committed JSON exactly:

| Metric   | Train   | Val     | **Test** |
|----------|---------|---------|----------|
| Accuracy | 98.14 % | 96.41 % | **96.45 %** |
| Precision| 99.22 % | 97.51 % | **97.86 %** |
| Recall   | 97.04 % | 95.25 % | **94.97 %** |
| F1-Score | 98.12 % | 96.37 % | **96.39 %** |
| ROC AUC  | 99.88 % | 99.50 % | **99.41 %** |
| PR AUC   |  —       —       | —       | **99.48 %** |

Test set: 5,009 samples (2,505 legitimate + 2,504 phishing – perfectly
balanced). Confusion matrix: TN=2,453, FP=52, FN=126, TP=2,378.

## Evaluation Outputs

The `evaluation/` directory contains the following artefact types:

- **Metrics** — `evaluation_report.json` classifies accuracy, F1, AUC-ROC,
  and PR-AUC for train/val/test sets.
- **Ablation** — `ablation_report.json` compares model performance with
  and without OSINT features and reports per-feature mean absolute SHAP
  values.
- **SHAP** — `shap_values.npy` plus visualisation PNGs provide feature
  importance and explainability analysis.
- **Plots** — Confusion matrix, ROC curve, precision-recall curve,
  gain-based feature importance charts.

## Notes

- All training and evaluation is fully deterministic (random seed fixed
  via `randomSeed: 42` in `modelMetadata.json`); running the full
  pipeline on the same raw data produces the same metrics.
- The 21-dimensional feature vector is documented in
  `backend/ml/models/modelMetadata.json`.
- The classification threshold and threat-level boundaries are declared
  in the orchestrator code at `backend/api/orchestrator.py`.
