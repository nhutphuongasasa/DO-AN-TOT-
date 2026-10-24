"""ml/train_flow.py — Huấn luyện LightGBM per-flow với nested LOSO cross-validation.

Usage:
    python3 -m ml.train_flow                          # dùng dataset mặc định
    python3 -m ml.train_flow --data ml/data/dataset_flow.csv --out ml/models/flow/
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.calibration import calibration_curve
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight

warnings.filterwarnings("ignore", category=UserWarning)

try:
    import lightgbm as lgb
except ImportError:
    raise ImportError("lightgbm not installed. Run: pip install lightgbm")

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_PATH    = Path("ml/data/dataset_flow.csv")
OUT_DIR      = Path("ml/models/flow")
BATCH_COL    = "batch_id"
LABEL_COL    = "label"
DROP_COLS    = [BATCH_COL, LABEL_COL, "flow_key", "mac"]

LGBM_BASE_PARAMS: Dict[str, Any] = {
    "objective":        "multiclass",
    "metric":           "multi_logloss",
    "verbosity":        -1,
    "n_estimators":     400,
    "learning_rate":    0.05,
    "num_leaves":       63,
    "min_child_samples": 20,
    "subsample":        0.8,
    "colsample_bytree": 0.8,
    "class_weight":     "balanced",
    "random_state":     42,
    "n_jobs":           -1,
}

REJECTION_THRESHOLD = 0.50   # Calibrated probability below this → "unknown"

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_data(csv_path: Path) -> Tuple[pd.DataFrame, np.ndarray, np.ndarray, LabelEncoder]:
    """Load dataset, encode labels, return (df, X, y_enc, label_encoder)."""
    df = pd.read_csv(csv_path)
    if LABEL_COL not in df.columns:
        raise ValueError(f"Column '{LABEL_COL}' not found in {csv_path}")
    if BATCH_COL not in df.columns:
        raise ValueError(f"Column '{BATCH_COL}' not found in {csv_path}")

    le = LabelEncoder()
    y = le.fit_transform(df[LABEL_COL])
    feature_cols = [c for c in df.columns if c not in DROP_COLS]
    X = df[feature_cols].fillna(0.0).values.astype(np.float32)
    log.info("Loaded %d samples, %d features, %d classes: %s",
             len(df), X.shape[1], len(le.classes_), list(le.classes_))
    return df, X, y, le


# ---------------------------------------------------------------------------
# Nested LOSO Cross-Validation
# ---------------------------------------------------------------------------

def get_batches(df: pd.DataFrame) -> List[str]:
    return sorted(df[BATCH_COL].unique().tolist())


def nested_loso_cv(
    df: pd.DataFrame,
    X: np.ndarray,
    y: np.ndarray,
    le: LabelEncoder,
    out_dir: Path,
    ablation_no_port: bool = False,
) -> List[Dict[str, Any]]:
    """Outer LOSO: each batch is held out as test. Inner LOSO selects n_estimators.

    Args:
        ablation_no_port: If True, drop dest_port column before training.

    Returns:
        List of per-fold result dicts.
    """
    batches = get_batches(df)
    if len(batches) < 2:
        raise ValueError(f"Need ≥2 batches for LOSO CV, got: {batches}")

    feature_cols = [c for c in df.columns if c not in DROP_COLS]
    if ablation_no_port and "dest_port" in feature_cols:
        feature_cols = [c for c in feature_cols if c != "dest_port"]
        log.info("Ablation: removed dest_port (%d features remaining)", len(feature_cols))

    X_use = df[feature_cols].fillna(0.0).values.astype(np.float32)

    fold_results: List[Dict[str, Any]] = []

    for test_batch in batches:
        log.info("=" * 60)
        log.info("Outer fold — Test batch: %s", test_batch)

        test_mask  = df[BATCH_COL] == test_batch
        train_mask = ~test_mask

        X_trainval, y_trainval = X_use[train_mask], y[train_mask]
        X_test,     y_test     = X_use[test_mask],  y[test_mask]
        df_trainval = df[train_mask]

        # ---- Inner LOSO: choose n_estimators ----
        inner_batches = [b for b in batches if b != test_batch]
        best_n = _inner_loso_select_n_estimators(
            df_trainval, X_trainval, y_trainval, inner_batches, feature_cols
        )
        log.info("Inner CV chose n_estimators=%d", best_n)

        # ---- Train on full train+val with best n ----
        params = {**LGBM_BASE_PARAMS, "n_estimators": best_n}
        model = lgb.LGBMClassifier(**params)
        model.fit(X_trainval, y_trainval)

        # ---- Calibrate probabilities on a val slice (last inner batch) ----
        val_batch = inner_batches[-1]
        val_mask  = df_trainval[BATCH_COL] == val_batch
        X_cal = X_trainval[val_mask.values]
        y_cal = y_trainval[val_mask.values]
        calibrators = _fit_calibrators(model, X_cal, y_cal, len(le.classes_))

        # ---- Evaluate on test batch ----
        raw_probs  = model.predict_proba(X_test)
        cal_probs  = _apply_calibrators(calibrators, raw_probs, len(le.classes_))
        y_pred_cal = np.argmax(cal_probs, axis=1)
        y_conf_cal = np.max(cal_probs, axis=1)

        # Apply rejection threshold
        y_pred_with_unk = np.where(
            y_conf_cal >= REJECTION_THRESHOLD,
            y_pred_cal,
            -1,  # -1 = unknown
        )

        f1_macro = f1_score(y_test, y_pred_cal, average="macro", zero_division=0)
        report = classification_report(
            y_test, y_pred_cal,
            target_names=le.classes_,
            zero_division=0,
            output_dict=True,
        )
        cm = confusion_matrix(y_test, y_pred_cal).tolist()

        result = {
            "test_batch":   test_batch,
            "n_estimators": best_n,
            "n_test":       int(y_test.shape[0]),
            "f1_macro":     round(float(f1_macro), 4),
            "report":       report,
            "confusion_matrix": cm,
            "class_names":  list(le.classes_),
            "ablation_no_port": ablation_no_port,
        }
        fold_results.append(result)

        log.info("Fold %s → F1_macro=%.4f", test_batch, f1_macro)
        print(classification_report(y_test, y_pred_cal, target_names=le.classes_, zero_division=0))

        # Save fold model
        fold_out = out_dir / f"fold_{test_batch}"
        fold_out.mkdir(parents=True, exist_ok=True)
        model.booster_.save_model(str(fold_out / "model.txt"))
        _save_calibrators(calibrators, fold_out / "calibrators.json")

    return fold_results


# ---------------------------------------------------------------------------
# Inner LOSO hyperparameter selection
# ---------------------------------------------------------------------------

def _inner_loso_select_n_estimators(
    df_tv: pd.DataFrame,
    X_tv: np.ndarray,
    y_tv: np.ndarray,
    inner_batches: List[str],
    feature_cols: List[str],
    candidates: List[int] = [100, 200, 300, 400, 500],
) -> int:
    """Choose n_estimators by inner LOSO on train+val split."""
    if len(inner_batches) < 2:
        return 300  # Not enough batches for inner CV — use default

    best_n, best_f1 = candidates[0], -1.0

    for n in candidates:
        f1s = []
        for val_batch in inner_batches:
            val_mask  = df_tv[BATCH_COL] == val_batch
            tr_mask   = ~val_mask
            if val_mask.sum() == 0 or tr_mask.sum() == 0:
                continue
            X_tr, y_tr = X_tv[tr_mask.values], y_tv[tr_mask.values]
            X_vl, y_vl = X_tv[val_mask.values], y_tv[val_mask.values]
            m = lgb.LGBMClassifier(**{**LGBM_BASE_PARAMS, "n_estimators": n})
            m.fit(X_tr, y_tr)
            y_p = m.predict(X_vl)
            f1s.append(f1_score(y_vl, y_p, average="macro", zero_division=0))
        mean_f1 = float(np.mean(f1s)) if f1s else 0.0
        log.debug("  Inner: n_estimators=%d → mean F1=%.4f", n, mean_f1)
        if mean_f1 > best_f1:
            best_f1, best_n = mean_f1, n

    return best_n


# ---------------------------------------------------------------------------
# Probability calibration (isotonic, per-class)
# ---------------------------------------------------------------------------

def _fit_calibrators(
    model: lgb.LGBMClassifier,
    X_cal: np.ndarray,
    y_cal: np.ndarray,
    n_classes: int,
) -> List[IsotonicRegression]:
    """Fit one isotonic calibrator per class on calibration set."""
    raw_probs = model.predict_proba(X_cal)
    calibrators = []
    for c in range(n_classes):
        iso = IsotonicRegression(out_of_bounds="clip")
        binary_y = (y_cal == c).astype(int)
        if binary_y.sum() == 0:
            # No positive examples — identity calibrator
            iso.fit([0.0, 1.0], [0.0, 1.0])
        else:
            iso.fit(raw_probs[:, c], binary_y)
        calibrators.append(iso)
    return calibrators


def _apply_calibrators(
    calibrators: List[IsotonicRegression],
    raw_probs: np.ndarray,
    n_classes: int,
) -> np.ndarray:
    """Apply per-class calibrators, re-normalize rows to sum to 1."""
    cal = np.stack(
        [calibrators[c].predict(raw_probs[:, c]) for c in range(n_classes)],
        axis=1,
    ).astype(np.float64)
    row_sums = cal.sum(axis=1, keepdims=True)
    row_sums = np.where(row_sums == 0, 1.0, row_sums)  # avoid div/0
    return cal / row_sums


def _save_calibrators(calibrators: List[IsotonicRegression], path: Path) -> None:
    """Serialize isotonic calibrators to JSON (X_thresholds_, y_thresholds_ arrays)."""
    data = []
    for iso in calibrators:
        # sklearn 1.x uses X_thresholds_/y_thresholds_ instead of X_/y_
        X = getattr(iso, "X_thresholds_", getattr(iso, "X_", None))
        y = getattr(iso, "y_thresholds_", getattr(iso, "y_", None))
        data.append({"X_": X.tolist(), "y_": y.tolist()})
    path.write_text(json.dumps(data))


def load_calibrators(path: Path, n_classes: int) -> List[IsotonicRegression]:
    """Load calibrators from JSON."""
    data = json.loads(path.read_text())
    calibrators = []
    for d in data:
        iso = IsotonicRegression(out_of_bounds="clip")
        X = np.array(d["X_"])
        y = np.array(d["y_"])
        # Support both sklearn naming conventions
        iso.X_thresholds_ = X
        iso.y_thresholds_ = y
        iso.X_ = X  # legacy compat
        iso.y_ = y
        iso.f_ = y  # required for predict()
        calibrators.append(iso)
    return calibrators


# ---------------------------------------------------------------------------
# Final model (train on all data)
# ---------------------------------------------------------------------------

def train_final_model(
    X: np.ndarray,
    y: np.ndarray,
    best_n: int,
    out_dir: Path,
) -> lgb.LGBMClassifier:
    """Train final model on ALL data with the median n_estimators from CV."""
    params = {**LGBM_BASE_PARAMS, "n_estimators": best_n}
    model = lgb.LGBMClassifier(**params)
    model.fit(X, y)
    model.booster_.save_model(str(out_dir / "model_final.txt"))
    log.info("Final model saved to %s", out_dir / "model_final.txt")
    return model


# ---------------------------------------------------------------------------
# Summary report
# ---------------------------------------------------------------------------

def summarize_folds(fold_results: List[Dict[str, Any]], out_dir: Path) -> None:
    """Print and save summary table across folds."""
    f1s = [r["f1_macro"] for r in fold_results]
    print("\n" + "=" * 60)
    print("CROSS-VALIDATION SUMMARY")
    print("=" * 60)
    print(f"{'Fold':<30} {'N_test':>8} {'F1_macro':>10}")
    print("-" * 60)
    for r in fold_results:
        tag = "*ABLATION*" if r.get("ablation_no_port") else ""
        print(f"{r['test_batch']:<30} {r['n_test']:>8} {r['f1_macro']:>10.4f} {tag}")
    print("-" * 60)
    print(f"{'Mean ± Std':<30} {'':>8} {np.mean(f1s):>6.4f} ± {np.std(f1s):.4f}")
    print("=" * 60 + "\n")

    summary = {
        "f1_mean":  float(np.mean(f1s)),
        "f1_std":   float(np.std(f1s)),
        "f1_min":   float(np.min(f1s)),
        "f1_max":   float(np.max(f1s)),
        "folds":    fold_results,
    }
    (out_dir / "cv_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False)
    )
    log.info("Summary saved to %s", out_dir / "cv_summary.json")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    global REJECTION_THRESHOLD  # must be first before any use
    parser = argparse.ArgumentParser(description="Train LightGBM per-flow classifier.")
    parser.add_argument("--data",      default=str(DATA_PATH), help="Path to dataset_flow.csv")
    parser.add_argument("--out",       default=str(OUT_DIR),   help="Output directory for models")
    parser.add_argument("--threshold", type=float, default=0.50,
                        help="Calibrated probability threshold for rejection (default 0.5)")
    parser.add_argument("--ablation",  action="store_true",
                        help="Also run ablation without dest_port feature")
    parser.add_argument("--n-jobs",    type=int, default=-1,
                        help="CPU threads for LightGBM. -1=all, 4=4 cores (default: -1)")
    parser.add_argument("--verbose",   action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    REJECTION_THRESHOLD = args.threshold
    LGBM_BASE_PARAMS["n_jobs"] = args.n_jobs  # limit CPU threads if requested

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Load data
    df, X, y, le = load_data(Path(args.data))

    # Save label encoder
    (out_dir / "label_encoder.json").write_text(
        json.dumps({"classes": list(le.classes_)}, ensure_ascii=False)
    )

    # Main CV
    print("\n>>> Running nested LOSO cross-validation (full features)...")
    results = nested_loso_cv(df, X, y, le, out_dir)
    summarize_folds(results, out_dir)

    # Ablation without dest_port
    if args.ablation:
        print("\n>>> Running ablation (without dest_port)...")
        abl_dir = out_dir / "ablation_no_port"
        abl_dir.mkdir(exist_ok=True)
        abl_results = nested_loso_cv(df, X, y, le, abl_dir, ablation_no_port=True)
        summarize_folds(abl_results, abl_dir)
        # Compare
        main_f1  = np.mean([r["f1_macro"] for r in results])
        abl_f1   = np.mean([r["f1_macro"] for r in abl_results])
        print(f"\nAblation result: Full={main_f1:.4f} vs No-port={abl_f1:.4f} "
              f"(diff={main_f1-abl_f1:+.4f})")
        if abs(main_f1 - abl_f1) < 0.03:
            print("→ Model learns behavior, not just port numbers ✓")
        else:
            print("→ dest_port contributes significantly — model may rely on port memorization")

    # Final model on all data
    median_n = int(np.median([r["n_estimators"] for r in results]))
    print(f"\n>>> Training final model on ALL data (n_estimators={median_n})...")
    train_final_model(X, y, median_n, out_dir)


if __name__ == "__main__":
    main()
