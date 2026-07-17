"""
Additional SHAP visualisations derived from the saved SHAP value
matrix. Does not require the raw X test data — only the persisted
``shap_values.npy`` plus the trained model's feature schema.

Produces three artefacts in ``data/evaluation/``:

1. ``shap_signed_mean.png`` — bar chart of each feature's *signed*
   mean SHAP contribution. Features with positive mean push
   predictions towards ``phishing``; negative values push towards
   ``legitimate``. Useful for explaining directional effects.

2. ``shap_variance.png`` — std-dev of |SHAP| per feature, which
   captures how *unstable* each feature's effect is across the
   test sample (versus mean |SHAP| which captures overall
   importance).

3. ``shap_correlation.png`` — feature-vs-feature correlation
   matrix of SHAP values. Highly correlated features provide
   redundant signal; understanding this helps explain why
   several URL features (e.g. urlLength, domainLength, pathDepth)
   dominate together.

Run:
    python -m backend.ml.training.shapVisualisationExtra

Outputs:
    data/evaluation/{shap_signed_mean,shap_variance,shap_correlation}.png
    data/evaluation/shap_signed_mean_report.json
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

PROJECT_ROOT = Path(__file__).resolve().parents[3]
EVAL_DIR = PROJECT_ROOT / "data" / "evaluation"
MODEL_DIR = PROJECT_ROOT / "backend" / "ml" / "models"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-5s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("shapVisualisationExtra")


def _loadArtefacts() -> tuple[np.ndarray, list[str]]:
    """Load SHAP values and feature names."""
    shapePath = EVAL_DIR / "shap_values.npy"
    if not shapePath.exists():
        raise SystemExit(
            f"Required artefact not found: {shapePath}. "
            "Run shapAnalysis.py first to generate shap_values.npy."
        )
    shap_values = np.load(shapePath)
    with (MODEL_DIR / "modelMetadata.json").open("r", encoding="utf-8") as fHandle:
        meta = json.load(fHandle)
    feature_names = meta.get("featureNames", [])
    if shap_values.ndim == 3 and shap_values.shape[2] == 2:
        shap_values = shap_values[:, :, 1]
    if shap_values.ndim != 2 or shap_values.shape[1] != len(feature_names):
        raise SystemExit(
            f"shap_values {shap_values.shape} incompatible with "
            f"featureNames ({len(feature_names)})."
        )
    return shap_values, feature_names


def _plotSignedMean(shap_values: np.ndarray, feature_names: list[str]) -> dict:
    """Bar chart of signed mean SHAP per feature.

    Positive => feature's typical effect pushes predictions towards
    phishing class. Negative => towards legitimate class.
    """
    signed_mean = shap_values.mean(axis=0)
    sorted_idx = np.argsort(np.abs(signed_mean))[::-1]
    sorted_names = [feature_names[i] for i in sorted_idx]
    sorted_values = signed_mean[sorted_idx]
    osint_set = {"hasValidMx", "usesCdn", "dnsRecordCount", "hasValidDns"}

    colours = ["#c0392b" if v > 0 else "#27ae60" for v in sorted_values]
    fig, ax = plt.subplots(figsize=(10, 7))
    ax.barh(sorted_names[::-1], sorted_values[::-1], color=colours[::-1])
    ax.axvline(0, color="black", linewidth=0.8)
    ax.set_xlabel("Mean SHAP value (sign-flipped discrimination power)")
    ax.set_title(
        "Per-feature signed mean SHAP contribution\n"
        "(red = pushes towards phishing, green = towards legitimate)",
        fontsize=11,
    )

    for i, name in enumerate(sorted_names):
        if name in osint_set:
            ax.text(
                0.005, len(sorted_names) - 1 - i,
                "OSINT",
                transform=ax.transAxes,
                fontsize=7, va="center", color="#2980b9", fontweight="bold",
            )

    plt.tight_layout()
    out = EVAL_DIR / "shap_signed_mean.png"
    fig.savefig(out, dpi=120, bbox_inches="tight")
    plt.close(fig)
    logger.info("Wrote %s", out)

    report = {
        "feature_signed_mean_shap": {
            name: float(signed_mean[i])
            for i, name in enumerate(feature_names)
        },
        "interpretation": {
            "pushing_toward_phishing": sorted([
                {"feature": feature_names[i],
                 "value": float(signed_mean[i])}
                for i in np.argsort(signed_mean)[::-1][:5]
            ], key=lambda x: -x["value"]),
            "pushing_toward_legitimate": [
                {"feature": feature_names[i],
                 "value": float(signed_mean[i])}
                for i in np.argsort(signed_mean)[:5]
            ],
        },
    }
    out_json = EVAL_DIR / "shap_signed_mean_report.json"
    with out_json.open("w", encoding="utf-8") as fHandle:
        json.dump(report, fHandle, indent=2)
    logger.info("Wrote %s", out_json)
    return report


def _plotVariance(shap_values: np.ndarray, feature_names: list[str]) -> None:
    """Std-dev of |SHAP| per feature — instability / heterogeneity."""
    instab = np.abs(shap_values).std(axis=0)
    sorted_idx = np.argsort(instab)[::-1]
    sorted_names = [feature_names[i] for i in sorted_idx]
    sorted_values = instab[sorted_idx]

    fig, ax = plt.subplots(figsize=(10, 7))
    bars = ax.barh(sorted_names[::-1], sorted_values[::-1],
                    color="#8e44ad", edgecolor="black", linewidth=0.4)
    ax.set_xlabel("Std-dev of |SHAP| values across test samples")
    ax.set_title(
        "Per-feature instability of SHAP contribution\n"
        "(higher std-dev = feature effect varies more across samples)",
        fontsize=11,
    )

    for bar in bars:
        ax.text(
            bar.get_width() + 0.02,
            bar.get_y() + bar.get_height() / 2,
            f"{bar.get_width():.2f}",
            va="center", fontsize=8,
        )

    plt.tight_layout()
    out = EVAL_DIR / "shap_variance.png"
    fig.savefig(out, dpi=120, bbox_inches="tight")
    plt.close(fig)
    logger.info("Wrote %s", out)


def _plotCorrelation(shap_values: np.ndarray, feature_names: list[str]) -> None:
    """Pairwise correlation matrix of SHAP values.

    Reveals which features contribute redundant signal. For
    example, urlLength and pathDepth are expected to correlate
    because longer URLs often correlate with deeper paths.

    Features with zero variance across the test set are
    displayed with grey dots (``r=0``) for legibility.
    """
    n = shap_values.shape[1]
    corr = np.corrcoef(shap_values.T)
    corr = np.nan_to_num(corr, nan=0.0, posinf=0.0, neginf=0.0)

    fig, ax = plt.subplots(figsize=(11, 9))
    im = ax.imshow(
        corr,
        cmap="RdBu_r",
        vmin=-1.0,
        vmax=1.0,
        aspect="equal",
        interpolation="nearest",
    )
    ax.set_xticks(np.arange(n))
    ax.set_yticks(np.arange(n))
    ax.set_xticklabels(feature_names, rotation=90, fontsize=8)
    ax.set_yticklabels(feature_names, fontsize=8)
    plt.colorbar(im, ax=ax, label="Pearson r between SHAP values", shrink=0.8)
    ax.set_title(
        "Cross-feature correlation of SHAP contributions\n"
        "(high |r| = features provide redundant signal to the model)",
        fontsize=11,
    )
    for i in range(n):
        for j in range(n):
            if abs(corr[i, j]) > 0.5 and i != j:
                ax.text(
                    j, i, f"{corr[i, j]:.2f}",
                    ha="center", va="center",
                    color="black" if abs(corr[i, j]) < 0.7 else "white",
                    fontsize=6,
                )
    plt.tight_layout()
    out = EVAL_DIR / "shap_correlation.png"
    fig.savefig(out, dpi=120, bbox_inches="tight")
    plt.close(fig)
    logger.info("Wrote %s", out)


def main() -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-5s %(message)s",
                        datefmt="%H:%M:%S")
    logger.info("=" * 60)
    logger.info("EXTRA SHAP VISUALISATIONS")
    logger.info("=" * 60)

    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    shap_values, feature_names = _loadArtefacts()
    logger.info("Loaded shap_values: shape %s, %d features",
                shap_values.shape, len(feature_names))

    _plotSignedMean(shap_values, feature_names)
    _plotVariance(shap_values, feature_names)
    _plotCorrelation(shap_values, feature_names)

    logger.info("=" * 60)
    logger.info("DONE — artefacts in %s", EVAL_DIR)
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
