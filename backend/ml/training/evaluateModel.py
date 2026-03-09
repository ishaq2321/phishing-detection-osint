"""Comprehensive model evaluation with metrics tables and publication-quality charts.

Loads the trained model and test data, computes classification metrics,
and generates evaluation visualisations for the thesis.

Outputs
-------
data/evaluation/confusion_matrix.png
data/evaluation/roc_curve.png
data/evaluation/precision_recall_curve.png
data/evaluation/feature_importance.png
data/evaluation/evaluation_report.json
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score,
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODEL_DIR = PROJECT_ROOT / "backend" / "ml" / "models"
EVAL_DIR = PROJECT_ROOT / "data" / "evaluation"

LABEL_COLUMN = "label"
CLASS_NAMES = ["Legitimate", "Phishing"]

DPI = 300
FIGURE_WIDTH = 8
FIGURE_HEIGHT = 6

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-5s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Plotting style
# ------------------------------------------------------------------

def _configureStyle() -> None:
    """Apply a consistent, publication-ready matplotlib style."""
    sns.set_theme(style="whitegrid", font_scale=1.2)
    plt.rcParams.update({
        "figure.dpi": DPI,
        "savefig.dpi": DPI,
        "savefig.bbox": "tight",
        "font.family": "sans-serif",
        "axes.titleweight": "bold",
    })


# ------------------------------------------------------------------
# Loaders
# ------------------------------------------------------------------

def _loadModel() -> xgb.XGBClassifier:
    """Load the trained XGBoost model from disk."""
    modelPath = MODEL_DIR / "phishingModel.json"
    if not modelPath.exists():
        logger.error("Model file not found: %s  — run trainModel.py first", modelPath)
        sys.exit(1)

    model = xgb.XGBClassifier()
    model.load_model(str(modelPath))
    logger.info("Loaded model from %s", modelPath)
    return model


def _loadTestData() -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Load the test split and separate features/labels."""
    testPath = DATA_DIR / "test.csv"
    if not testPath.exists():
        logger.error("Test data not found: %s", testPath)
        sys.exit(1)

    testDf = pd.read_csv(testPath)
    featureNames = [c for c in testDf.columns if c != LABEL_COLUMN]
    xTest = testDf[featureNames].values
    yTest = testDf[LABEL_COLUMN].values

    logger.info("Loaded test set: %d samples, %d features", len(yTest), len(featureNames))
    return xTest, yTest, featureNames


# ------------------------------------------------------------------
# Charts
# ------------------------------------------------------------------

def _plotConfusionMatrix(yTrue: np.ndarray, yPred: np.ndarray) -> None:
    """Generate and save a confusion matrix heatmap."""
    cm = confusion_matrix(yTrue, yPred)

    fig, ax = plt.subplots(figsize=(FIGURE_WIDTH, FIGURE_HEIGHT))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=CLASS_NAMES,
        yticklabels=CLASS_NAMES,
        ax=ax,
        linewidths=0.5,
        cbar_kws={"label": "Count"},
    )
    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("True Label")
    ax.set_title("Confusion Matrix — XGBoost Phishing Classifier")

    outPath = EVAL_DIR / "confusion_matrix.png"
    fig.savefig(outPath)
    plt.close(fig)
    logger.info("Saved %s", outPath)


def _plotRocCurve(yTrue: np.ndarray, yProba: np.ndarray) -> None:
    """Generate and save the ROC curve."""
    fpr, tpr, _ = roc_curve(yTrue, yProba)
    rocAuc = auc(fpr, tpr)

    fig, ax = plt.subplots(figsize=(FIGURE_WIDTH, FIGURE_HEIGHT))
    ax.plot(fpr, tpr, color="#2563eb", lw=2, label=f"XGBoost (AUC = {rocAuc:.4f})")
    ax.plot([0, 1], [0, 1], color="#94a3b8", lw=1, linestyle="--", label="Random Baseline")
    ax.fill_between(fpr, tpr, alpha=0.1, color="#2563eb")

    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve — XGBoost Phishing Classifier")
    ax.legend(loc="lower right")
    ax.set_xlim([-0.01, 1.01])
    ax.set_ylim([-0.01, 1.01])

    outPath = EVAL_DIR / "roc_curve.png"
    fig.savefig(outPath)
    plt.close(fig)
    logger.info("Saved %s", outPath)


def _plotPrecisionRecallCurve(yTrue: np.ndarray, yProba: np.ndarray) -> None:
    """Generate and save the Precision-Recall curve."""
    precision, recall, _ = precision_recall_curve(yTrue, yProba)
    prAuc = auc(recall, precision)

    fig, ax = plt.subplots(figsize=(FIGURE_WIDTH, FIGURE_HEIGHT))
    ax.plot(recall, precision, color="#dc2626", lw=2, label=f"XGBoost (PR-AUC = {prAuc:.4f})")
    ax.fill_between(recall, precision, alpha=0.1, color="#dc2626")

    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curve — XGBoost Phishing Classifier")
    ax.legend(loc="lower left")
    ax.set_xlim([-0.01, 1.01])
    ax.set_ylim([-0.01, 1.01])

    outPath = EVAL_DIR / "precision_recall_curve.png"
    fig.savefig(outPath)
    plt.close(fig)
    logger.info("Saved %s", outPath)


def _plotFeatureImportance(model: xgb.XGBClassifier, featureNames: list[str]) -> None:
    """Generate and save a horizontal bar chart of feature importance."""
    importances = model.feature_importances_
    sortedIdx = np.argsort(importances)

    fig, ax = plt.subplots(figsize=(FIGURE_WIDTH, max(FIGURE_HEIGHT, len(featureNames) * 0.4)))

    colors = ["#16a34a" if featureNames[i] in {
        "hasValidMx", "usesCdn", "dnsRecordCount", "hasValidDns",
    } else "#2563eb" for i in sortedIdx]

    ax.barh(
        range(len(sortedIdx)),
        importances[sortedIdx],
        color=colors,
        edgecolor="white",
        linewidth=0.5,
    )
    ax.set_yticks(range(len(sortedIdx)))
    ax.set_yticklabels([featureNames[i] for i in sortedIdx])
    ax.set_xlabel("Feature Importance (Gain)")
    ax.set_title("Feature Importance — XGBoost Phishing Classifier")

    urlPatch = plt.Rectangle((0, 0), 1, 1, fc="#2563eb", label="URL Structural")
    osintPatch = plt.Rectangle((0, 0), 1, 1, fc="#16a34a", label="OSINT-Derived")
    ax.legend(handles=[urlPatch, osintPatch], loc="lower right")

    outPath = EVAL_DIR / "feature_importance.png"
    fig.savefig(outPath)
    plt.close(fig)
    logger.info("Saved %s", outPath)


# ------------------------------------------------------------------
# Report
# ------------------------------------------------------------------

def _generateReport(
    yTrue: np.ndarray,
    yPred: np.ndarray,
    yProba: np.ndarray,
    featureNames: list[str],
    model: xgb.XGBClassifier,
) -> dict:
    """Generate a comprehensive evaluation report."""
    cm = confusion_matrix(yTrue, yPred)
    tn, fp, fn, tp = cm.ravel()

    fpr, tpr, _ = roc_curve(yTrue, yProba)
    precisionCurve, recallCurve, _ = precision_recall_curve(yTrue, yProba)

    importances = model.feature_importances_
    sortedIdx = np.argsort(importances)[::-1]

    report = {
        "testSetSize": int(len(yTrue)),
        "classDistribution": {
            "legitimate": int((yTrue == 0).sum()),
            "phishing": int((yTrue == 1).sum()),
        },
        "metrics": {
            "accuracy": float(accuracy_score(yTrue, yPred)),
            "precision": float(precision_score(yTrue, yPred)),
            "recall": float(recall_score(yTrue, yPred)),
            "f1": float(f1_score(yTrue, yPred)),
            "rocAuc": float(roc_auc_score(yTrue, yProba)),
            "prAuc": float(auc(recallCurve, precisionCurve)),
        },
        "confusionMatrix": {
            "trueNegatives": int(tn),
            "falsePositives": int(fp),
            "falseNegatives": int(fn),
            "truePositives": int(tp),
        },
        "classificationReport": classification_report(
            yTrue, yPred, target_names=CLASS_NAMES, output_dict=True,
        ),
        "featureImportanceRanking": [
            {"rank": rank + 1, "feature": featureNames[i], "importance": float(importances[i])}
            for rank, i in enumerate(sortedIdx)
        ],
        "charts": [
            "confusion_matrix.png",
            "roc_curve.png",
            "precision_recall_curve.png",
            "feature_importance.png",
        ],
    }
    return report


# ------------------------------------------------------------------
# Main pipeline
# ------------------------------------------------------------------

def evaluateModel() -> None:
    """Execute the full evaluation pipeline."""
    logger.info("=" * 60)
    logger.info("MODEL EVALUATION PIPELINE")
    logger.info("=" * 60)

    _configureStyle()

    model = _loadModel()
    xTest, yTest, featureNames = _loadTestData()

    yPred = model.predict(xTest)
    yProba = model.predict_proba(xTest)[:, 1]

    EVAL_DIR.mkdir(parents=True, exist_ok=True)

    _plotConfusionMatrix(yTest, yPred)
    _plotRocCurve(yTest, yProba)
    _plotPrecisionRecallCurve(yTest, yProba)
    _plotFeatureImportance(model, featureNames)

    report = _generateReport(yTest, yPred, yProba, featureNames, model)

    reportPath = EVAL_DIR / "evaluation_report.json"
    with open(reportPath, "w", encoding="utf-8") as reportFile:
        json.dump(report, reportFile, indent=2, default=str)
    logger.info("Saved evaluation report → %s", reportPath)

    logger.info("=" * 60)
    logger.info("EVALUATION COMPLETE")
    logger.info(
        "Test: Acc=%.4f  F1=%.4f  AUC=%.4f  PR-AUC=%.4f",
        report["metrics"]["accuracy"],
        report["metrics"]["f1"],
        report["metrics"]["rocAuc"],
        report["metrics"]["prAuc"],
    )
    logger.info(
        "Confusion: TP=%d  TN=%d  FP=%d  FN=%d",
        report["confusionMatrix"]["truePositives"],
        report["confusionMatrix"]["trueNegatives"],
        report["confusionMatrix"]["falsePositives"],
        report["confusionMatrix"]["falseNegatives"],
    )
    logger.info("=" * 60)


if __name__ == "__main__":
    evaluateModel()
