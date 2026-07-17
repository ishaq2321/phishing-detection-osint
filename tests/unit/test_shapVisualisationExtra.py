"""Tests for the SHAP visualisation extras script.

Validates that the script reads the persisted ``shap_values.npy``
and feature-schema metadata without errors, and that the three
artefacts (signed mean, variance, correlation) are produced.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from backend.ml.training.shapVisualisationExtra import (
    _loadArtefacts,
    _plotCorrelation,
    _plotSignedMean,
    _plotVariance,
    main,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]  # tests/unit -> phishguard/
EVAL_DIR = PROJECT_ROOT / "data" / "evaluation"


@pytest.fixture(scope="module")
def shapArtefacts():
    return _loadArtefacts()


def test_loadArtefacts_returnsCorrectShape(shapArtefacts):
    shap_values, feature_names = shapArtefacts
    assert shap_values.ndim == 2
    assert shap_values.shape[0] > 0
    assert shap_values.shape[1] == len(feature_names)
    assert all(isinstance(name, str) for name in feature_names)


def test_signedMeanPlotAndReport(shapArtefacts):
    """End-to-end smoke test: render the plot and JSON report."""
    originalCwd = EVAL_DIR
    saved = []
    fileList = [
        "shap_signed_mean.png",
        "shap_signed_mean_report.json",
    ]
    for f in fileList:
        p = originalCwd / f
        if p.exists():
            saved.append((f, p.read_bytes()))
    try:
        shap_values, feature_names = shapArtefacts
        report = _plotSignedMean(shap_values, feature_names)
        assert "feature_signed_mean_shap" in report
        assert "interpretation" in report
        assert "pushing_toward_phishing" in report["interpretation"]
        assert "pushing_toward_legitimate" in report["interpretation"]
        for f in fileList:
            assert (originalCwd / f).exists(), f"{f} was not created"
    finally:
        for f, data in saved:
            (originalCwd / f).write_bytes(data)


def test_variancePlot(shapArtefacts):
    shap_values, feature_names = shapArtefacts
    _plotVariance(shap_values, feature_names)
    p = EVAL_DIR / "shap_variance.png"
    assert p.exists()


def test_correlationPlotHandlesConstantColumns(shapArtefacts):
    """Constant SHAP columns must not produce NaN fields in the saved figure."""
    shap_values, feature_names = shapArtefacts
    _plotCorrelation(shap_values, feature_names)
    p = EVAL_DIR / "shap_correlation.png"
    assert p.exists()


def test_main_endToEnd():
    """Running main() reproduces the three artefacts."""
    rc = main()
    assert rc == 0
    for f in (
        "shap_signed_mean.png",
        "shap_signed_mean_report.json",
        "shap_variance.png",
        "shap_correlation.png",
    ):
        assert (EVAL_DIR / f).exists(), f"{f} not produced by main()"
