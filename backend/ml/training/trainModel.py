"""Train an XGBoost phishing classifier with Optuna hyperparameter search.

Loads the prepared train/val/test splits, runs Bayesian optimisation
via Optuna (50 trials, 5-fold stratified CV), trains the final model
with the best hyperparameters, and serialises everything to disk.

Outputs
-------
backend/ml/models/phishingModel.json    – XGBoost model (portable JSON)
backend/ml/models/modelMetadata.json    – feature names, best params, metrics
backend/ml/models/optuna_study.json     – full Optuna trial history
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import optuna
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODEL_DIR = PROJECT_ROOT / "backend" / "ml" / "models"

RANDOM_SEED = 42
N_OPTUNA_TRIALS = 50
N_CV_FOLDS = 5
LABEL_COLUMN = "label"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-5s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Data loading
# ------------------------------------------------------------------

def _loadSplits() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Load train / val / test CSVs produced by prepareDataset.py."""
    trainPath = DATA_DIR / "train.csv"
    valPath = DATA_DIR / "val.csv"
    testPath = DATA_DIR / "test.csv"

    for path in (trainPath, valPath, testPath):
        if not path.exists():
            logger.error("Missing split file: %s  — run prepareDataset.py first", path)
            sys.exit(1)

    trainDf = pd.read_csv(trainPath)
    valDf = pd.read_csv(valPath)
    testDf = pd.read_csv(testPath)

    logger.info(
        "Loaded splits — train: %d, val: %d, test: %d",
        len(trainDf), len(valDf), len(testDf),
    )
    return trainDf, valDf, testDf


def _splitFeaturesLabels(
    dataFrame: pd.DataFrame,
) -> tuple[np.ndarray, np.ndarray]:
    """Separate feature matrix X and label vector y."""
    featureCols = [c for c in dataFrame.columns if c != LABEL_COLUMN]
    return dataFrame[featureCols].values, dataFrame[LABEL_COLUMN].to_numpy()


# ------------------------------------------------------------------
# Optuna objective
# ------------------------------------------------------------------

def _createObjective(
    xTrain: np.ndarray,
    yTrain: np.ndarray,
) -> optuna.study.Study:
    """Create and run an Optuna study for hyperparameter search."""

    def objective(trial: optuna.Trial) -> float:
        params = {
            "max_depth": trial.suggest_int("max_depth", 3, 10),
            "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.3, log=True),
            "n_estimators": trial.suggest_int("n_estimators", 100, 1000, step=50),
            "subsample": trial.suggest_float("subsample", 0.5, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),
            "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
            "gamma": trial.suggest_float("gamma", 0.0, 5.0),
            "reg_alpha": trial.suggest_float("reg_alpha", 1e-8, 10.0, log=True),
            "reg_lambda": trial.suggest_float("reg_lambda", 1e-8, 10.0, log=True),
        }

        skf = StratifiedKFold(n_splits=N_CV_FOLDS, shuffle=True, random_state=RANDOM_SEED)
        foldScores: list[float] = []

        for trainIdx, valIdx in skf.split(xTrain, yTrain):
            xFold, xVal = xTrain[trainIdx], xTrain[valIdx]
            yFold, yVal = yTrain[trainIdx], yTrain[valIdx]

            model = xgb.XGBClassifier(
                **params,
                objective="binary:logistic",
                eval_metric="logloss",
                random_state=RANDOM_SEED,
                verbosity=0,
                early_stopping_rounds=30,
            )

            model.fit(
                xFold, yFold,
                eval_set=[(xVal, yVal)],
                verbose=False,
            )

            probabilities = model.predict_proba(xVal)[:, 1]
            auc = roc_auc_score(yVal, probabilities)
            foldScores.append(float(auc))

        meanAuc = float(np.mean(foldScores))
        return meanAuc

    optuna.logging.set_verbosity(optuna.logging.WARNING)

    study = optuna.create_study(
        direction="maximize",
        sampler=optuna.samplers.TPESampler(seed=RANDOM_SEED),
        pruner=optuna.pruners.MedianPruner(n_startup_trials=10),
    )

    logger.info("Starting Optuna search: %d trials, %d-fold CV …", N_OPTUNA_TRIALS, N_CV_FOLDS)
    study.optimize(objective, n_trials=N_OPTUNA_TRIALS, show_progress_bar=True)

    logger.info(
        "Best trial #%d — AUC: %.5f",
        study.best_trial.number,
        study.best_trial.value,
    )
    logger.info("Best params: %s", json.dumps(study.best_params, indent=2))

    return study


# ------------------------------------------------------------------
# Final model training
# ------------------------------------------------------------------

def _trainFinalModel(
    xTrain: np.ndarray,
    yTrain: np.ndarray,
    xVal: np.ndarray,
    yVal: np.ndarray,
    bestParams: dict,
) -> xgb.XGBClassifier:
    """Train the final model on full training set with best hyperparameters."""
    model = xgb.XGBClassifier(
        **bestParams,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=RANDOM_SEED,
        verbosity=1,
        early_stopping_rounds=30,
    )

    logger.info("Training final model with best hyperparameters …")
    model.fit(
        xTrain, yTrain,
        eval_set=[(xVal, yVal)],
        verbose=False,
    )

    logger.info(
        "Final model: %d boosting rounds (best iteration: %d)",
        model.n_estimators,
        model.best_iteration,
    )
    return model


# ------------------------------------------------------------------
# Evaluation
# ------------------------------------------------------------------

def _evaluateModel(
    model: xgb.XGBClassifier,
    xData: np.ndarray,
    yData: np.ndarray,
    splitName: str,
) -> dict:
    """Evaluate model on a dataset and return metrics dict."""
    predictions = model.predict(xData)
    probabilities = model.predict_proba(xData)[:, 1]

    metrics = {
        "accuracy": float(accuracy_score(yData, predictions)),
        "precision": float(precision_score(yData, predictions)),
        "recall": float(recall_score(yData, predictions)),
        "f1": float(f1_score(yData, predictions)),
        "rocAuc": float(roc_auc_score(yData, probabilities)),
    }

    logger.info(
        "%s — Acc: %.4f  Prec: %.4f  Rec: %.4f  F1: %.4f  AUC: %.4f",
        splitName,
        metrics["accuracy"],
        metrics["precision"],
        metrics["recall"],
        metrics["f1"],
        metrics["rocAuc"],
    )
    return metrics


# ------------------------------------------------------------------
# Serialisation
# ------------------------------------------------------------------

def _saveArtifacts(
    model: xgb.XGBClassifier,
    featureNames: list[str],
    bestParams: dict,
    trainMetrics: dict,
    valMetrics: dict,
    testMetrics: dict,
    study: optuna.study.Study,
    trainingTimeSeconds: float,
) -> None:
    """Save model, metadata, and Optuna study to disk."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    modelPath = MODEL_DIR / "phishingModel.json"
    model.save_model(str(modelPath))
    logger.info("Saved model → %s", modelPath)

    metadata = {
        "modelType": "XGBClassifier",
        "objective": "binary:logistic",
        "featureCount": len(featureNames),
        "featureNames": featureNames,
        "bestHyperparameters": bestParams,
        "metrics": {
            "train": trainMetrics,
            "val": valMetrics,
            "test": testMetrics,
        },
        "optuna": {
            "nTrials": N_OPTUNA_TRIALS,
            "nCvFolds": N_CV_FOLDS,
            "bestTrialNumber": study.best_trial.number,
            "bestTrialAuc": study.best_trial.value,
        },
        "randomSeed": RANDOM_SEED,
        "trainingTimeSeconds": round(trainingTimeSeconds, 2),
    }

    metadataPath = MODEL_DIR / "modelMetadata.json"
    with open(metadataPath, "w", encoding="utf-8") as metaFile:
        json.dump(metadata, metaFile, indent=2)
    logger.info("Saved metadata → %s", metadataPath)

    trialHistory = []
    for trial in study.trials:
        trialHistory.append({
            "number": trial.number,
            "value": trial.value,
            "params": trial.params,
            "state": trial.state.name,
        })

    studyPath = MODEL_DIR / "optuna_study.json"
    with open(studyPath, "w", encoding="utf-8") as studyFile:
        json.dump(trialHistory, studyFile, indent=2)
    logger.info("Saved Optuna study → %s", studyPath)


# ------------------------------------------------------------------
# Main pipeline
# ------------------------------------------------------------------

def trainModel() -> None:
    """Execute the full training pipeline."""
    logger.info("=" * 60)
    logger.info("XGBOOST TRAINING PIPELINE")
    logger.info("=" * 60)

    startTime = time.time()

    trainDf, valDf, testDf = _loadSplits()

    featureNames = [c for c in trainDf.columns if c != LABEL_COLUMN]
    logger.info("Features (%d): %s", len(featureNames), featureNames)

    xTrain, yTrain = _splitFeaturesLabels(trainDf)
    xVal, yVal = _splitFeaturesLabels(valDf)
    xTest, yTest = _splitFeaturesLabels(testDf)

    study = _createObjective(xTrain, yTrain)

    model = _trainFinalModel(xTrain, yTrain, xVal, yVal, study.best_params)

    logger.info("--- Evaluation ---")
    trainMetrics = _evaluateModel(model, xTrain, yTrain, "Train")
    valMetrics = _evaluateModel(model, xVal, yVal, "Val")
    testMetrics = _evaluateModel(model, xTest, yTest, "Test")

    trainingTime = time.time() - startTime

    _saveArtifacts(
        model=model,
        featureNames=featureNames,
        bestParams=study.best_params,
        trainMetrics=trainMetrics,
        valMetrics=valMetrics,
        testMetrics=testMetrics,
        study=study,
        trainingTimeSeconds=trainingTime,
    )

    logger.info("=" * 60)
    logger.info("TRAINING COMPLETE in %.1f seconds", trainingTime)
    logger.info(
        "Test performance — Acc: %.4f  F1: %.4f  AUC: %.4f",
        testMetrics["accuracy"],
        testMetrics["f1"],
        testMetrics["rocAuc"],
    )
    logger.info("=" * 60)


if __name__ == "__main__":
    trainModel()
