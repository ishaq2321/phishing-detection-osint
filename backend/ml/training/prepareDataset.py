"""Dataset preparation: clean, balance, and split features into train/val/test.

Reads the raw feature matrix from ``data/processed/features_raw.csv``,
performs quality checks (duplicates, zero-variance columns, outliers),
undersamples the majority class for 1:1 balance, and produces
stratified 70/15/15 train/val/test splits.

Outputs
-------
data/processed/train.csv
data/processed/val.csv
data/processed/test.csv
data/processed/dataset_stats.json   – column stats, split sizes, dropped columns
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[3]
RAW_FEATURES_PATH = PROJECT_ROOT / "data" / "processed" / "features_raw.csv"
OUTPUT_DIR = PROJECT_ROOT / "data" / "processed"

RANDOM_SEED = 42
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15

LABEL_COLUMN = "label"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-5s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _loadRawFeatures(path: Path) -> pd.DataFrame:
    """Load the raw feature CSV and run basic sanity checks."""
    if not path.exists():
        logger.error("Raw features file not found: %s", path)
        sys.exit(1)

    dataFrame = pd.read_csv(path)
    logger.info("Loaded %d rows × %d columns from %s", *dataFrame.shape, path.name)

    if LABEL_COLUMN not in dataFrame.columns:
        logger.error("Missing '%s' column in dataset", LABEL_COLUMN)
        sys.exit(1)

    return dataFrame


def _dropZeroVarianceColumns(dataFrame: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Remove columns that have zero variance (all identical or all NaN).

    These provide no discriminative power and would just add noise.
    """
    featureColumns = [c for c in dataFrame.columns if c != LABEL_COLUMN]
    droppedColumns: list[str] = []

    for column in featureColumns:
        uniqueCount = dataFrame[column].nunique(dropna=True)
        if uniqueCount <= 1:
            droppedColumns.append(column)

    if droppedColumns:
        dataFrame = dataFrame.drop(columns=droppedColumns)
        logger.info(
            "Dropped %d zero-variance columns: %s",
            len(droppedColumns),
            ", ".join(droppedColumns),
        )

    return dataFrame, droppedColumns


def _removeDuplicates(dataFrame: pd.DataFrame) -> pd.DataFrame:
    """Drop exact duplicate rows."""
    before = len(dataFrame)
    dataFrame = dataFrame.drop_duplicates().reset_index(drop=True)
    removed = before - len(dataFrame)
    logger.info("Removed %d duplicate rows (%d → %d)", removed, before, len(dataFrame))
    return dataFrame


def _clipOutliers(dataFrame: pd.DataFrame, zThreshold: float = 5.0) -> pd.DataFrame:
    """Clip extreme outliers beyond ±z_threshold standard deviations.

    Only applies to continuous (non-binary) features.  Binary columns
    with values in {0, 1} are left untouched.
    """
    featureColumns = [c for c in dataFrame.columns if c != LABEL_COLUMN]
    clippedCount = 0

    for column in featureColumns:
        uniqueValues = dataFrame[column].dropna().unique()
        isBinary = set(uniqueValues).issubset({0.0, 1.0})
        if isBinary:
            continue

        mean = dataFrame[column].mean()
        std = dataFrame[column].std()
        if std == 0:
            continue

        lower = mean - zThreshold * std
        upper = mean + zThreshold * std
        outliers = ((dataFrame[column] < lower) | (dataFrame[column] > upper)).sum()
        if outliers > 0:
            dataFrame[column] = dataFrame[column].clip(lower=lower, upper=upper)
            clippedCount += outliers

    logger.info("Clipped %d outlier values (z > %.1f)", clippedCount, zThreshold)
    return dataFrame


def _fillMissingValues(dataFrame: pd.DataFrame) -> pd.DataFrame:
    """Impute remaining NaN values with column median.

    XGBoost can handle NaN natively, but clean data is more robust
    across different model types and enables cleaner analysis.
    """
    missingBefore = dataFrame.isnull().sum().sum()
    if missingBefore == 0:
        logger.info("No missing values to impute")
        return dataFrame

    featureColumns = [c for c in dataFrame.columns if c != LABEL_COLUMN]
    for column in featureColumns:
        if dataFrame[column].isnull().any():
            median = dataFrame[column].median()
            dataFrame[column] = dataFrame[column].fillna(median)

    logger.info("Imputed %d missing values with column medians", missingBefore)
    return dataFrame


def _balanceClasses(dataFrame: pd.DataFrame) -> pd.DataFrame:
    """Undersample the majority class to achieve 1:1 class balance.

    Random undersampling with a fixed seed ensures reproducibility.
    """
    classCounts = dataFrame[LABEL_COLUMN].value_counts()
    majorityLabel = classCounts.idxmax()
    minorityLabel = classCounts.idxmin()
    minorityCount = classCounts[minorityLabel]

    logger.info(
        "Class distribution before balancing: %s=%d, %s=%d",
        majorityLabel, classCounts[majorityLabel],
        minorityLabel, minorityCount,
    )

    majorityRows = dataFrame[dataFrame[LABEL_COLUMN] == majorityLabel]
    minorityRows = dataFrame[dataFrame[LABEL_COLUMN] == minorityLabel]

    majorityDownsampled = majorityRows.sample(
        n=minorityCount,
        random_state=RANDOM_SEED,
    )

    balanced = pd.concat([majorityDownsampled, minorityRows], ignore_index=True)
    balanced = balanced.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)

    logger.info(
        "Balanced dataset: %d samples (%d per class)",
        len(balanced), minorityCount,
    )
    return balanced


def _stratifiedSplit(
    dataFrame: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split into train/val/test with stratified sampling.

    Split ratios: 70% train, 15% validation, 15% test.
    """
    features = dataFrame.drop(columns=[LABEL_COLUMN])
    labels = dataFrame[LABEL_COLUMN]

    trainFeatures, tempFeatures, trainLabels, tempLabels = train_test_split(
        features,
        labels,
        test_size=(VAL_RATIO + TEST_RATIO),
        stratify=labels,
        random_state=RANDOM_SEED,
    )

    relativeTestRatio = TEST_RATIO / (VAL_RATIO + TEST_RATIO)
    valFeatures, testFeatures, valLabels, testLabels = train_test_split(
        tempFeatures,
        tempLabels,
        test_size=relativeTestRatio,
        stratify=tempLabels,
        random_state=RANDOM_SEED,
    )

    trainSplit = pd.concat([trainFeatures, trainLabels], axis=1)
    valSplit = pd.concat([valFeatures, valLabels], axis=1)
    testSplit = pd.concat([testFeatures, testLabels], axis=1)

    logger.info(
        "Split sizes — train: %d, val: %d, test: %d",
        len(trainSplit), len(valSplit), len(testSplit),
    )
    return trainSplit, valSplit, testSplit


def _computeDatasetStats(
    trainDf: pd.DataFrame,
    valDf: pd.DataFrame,
    testDf: pd.DataFrame,
    droppedColumns: list[str],
) -> dict:
    """Compute and return comprehensive dataset statistics."""
    featureColumns = [c for c in trainDf.columns if c != LABEL_COLUMN]

    featureStats = {}
    for column in featureColumns:
        featureStats[column] = {
            "mean": float(trainDf[column].mean()),
            "std": float(trainDf[column].std()),
            "min": float(trainDf[column].min()),
            "max": float(trainDf[column].max()),
            "median": float(trainDf[column].median()),
        }

    stats = {
        "featureCount": len(featureColumns),
        "featureNames": featureColumns,
        "droppedColumns": droppedColumns,
        "splits": {
            "train": {
                "total": len(trainDf),
                "phishing": int((trainDf[LABEL_COLUMN] == 1).sum()),
                "legitimate": int((trainDf[LABEL_COLUMN] == 0).sum()),
            },
            "val": {
                "total": len(valDf),
                "phishing": int((valDf[LABEL_COLUMN] == 1).sum()),
                "legitimate": int((valDf[LABEL_COLUMN] == 0).sum()),
            },
            "test": {
                "total": len(testDf),
                "phishing": int((testDf[LABEL_COLUMN] == 1).sum()),
                "legitimate": int((testDf[LABEL_COLUMN] == 0).sum()),
            },
        },
        "featureStatistics": featureStats,
        "randomSeed": RANDOM_SEED,
        "splitRatios": {
            "train": TRAIN_RATIO,
            "val": VAL_RATIO,
            "test": TEST_RATIO,
        },
    }
    return stats


# ------------------------------------------------------------------
# Main pipeline
# ------------------------------------------------------------------

def prepareDataset() -> None:
    """Execute the full dataset preparation pipeline."""
    logger.info("=" * 60)
    logger.info("DATASET PREPARATION PIPELINE")
    logger.info("=" * 60)

    dataFrame = _loadRawFeatures(RAW_FEATURES_PATH)

    dataFrame, droppedColumns = _dropZeroVarianceColumns(dataFrame)

    dataFrame = _removeDuplicates(dataFrame)

    dataFrame = _clipOutliers(dataFrame)

    dataFrame = _fillMissingValues(dataFrame)

    dataFrame = _balanceClasses(dataFrame)

    trainDf, valDf, testDf = _stratifiedSplit(dataFrame)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    trainPath = OUTPUT_DIR / "train.csv"
    valPath = OUTPUT_DIR / "val.csv"
    testPath = OUTPUT_DIR / "test.csv"
    statsPath = OUTPUT_DIR / "dataset_stats.json"

    trainDf.to_csv(trainPath, index=False)
    valDf.to_csv(valPath, index=False)
    testDf.to_csv(testPath, index=False)
    logger.info("Saved train → %s", trainPath)
    logger.info("Saved val   → %s", valPath)
    logger.info("Saved test  → %s", testPath)

    stats = _computeDatasetStats(trainDf, valDf, testDf, droppedColumns)
    with open(statsPath, "w", encoding="utf-8") as statsFile:
        json.dump(stats, statsFile, indent=2)
    logger.info("Saved stats → %s", statsPath)

    logger.info("=" * 60)
    logger.info("PIPELINE COMPLETE")
    logger.info(
        "Final dataset: %d features, %d train / %d val / %d test samples",
        stats["featureCount"],
        stats["splits"]["train"]["total"],
        stats["splits"]["val"]["total"],
        stats["splits"]["test"]["total"],
    )
    logger.info("=" * 60)


if __name__ == "__main__":
    prepareDataset()
