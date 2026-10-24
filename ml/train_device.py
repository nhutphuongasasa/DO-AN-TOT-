"""ml/train_device.py — Huấn luyện LightGBM per-device-window classifier.

Đơn vị phân loại: (device_mac, time_window_30s) — đầu ra chính của Dashboard.
Không dùng dest_port, is_tcp/udp (thuộc tính flow, không phải device-window).

Usage:
    python3 -m ml.train_device
    python3 -m ml.train_device --data ml/data/dataset_device.csv --out ml/models/device/
"""
from __future__ import annotations

import argparse
import json
import logging
import warnings
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.preprocessing import LabelEncoder

warnings.filterwarnings("ignore", category=UserWarning)

try:
    import lightgbm as lgb
except ImportError:
    raise ImportError("lightgbm not installed. Run: pip install lightgbm")

# Reuse helpers from train_flow
from ml.train_flow import (
    _apply_calibrators,
    _fit_calibrators,
    _inner_loso_select_n_estimators,
    _save_calibrators,
    summarize_folds,
    train_final_model,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_PATH = Path("ml/data/dataset_device.csv")
OUT_DIR   = Path("ml/models/device")
BATCH_COL = "batch_id"
LABEL_COL = "label"

# Per-device features do NOT include flow-level meta
DROP_COLS = [BATCH_COL, LABEL_COL, "flow_key", "mac",
             "dest_port", "is_udp", "is_tcp",    # flow-level attributes
             "tls_record_count"]                  # not computable for QUIC

LGBM_PARAMS: Dict[str, Any] = {
    "objective":         "multiclass",
    "metric":            "multi_logloss",
    "verbosity":         -1,
    "n_estimators":      400,
    "learning_rate":     0.05,
    "num_leaves":        63,
    "min_child_samples": 20,
    "subsample":         0.8,
    "colsample_bytree":  0.8,
    "class_weight":      "balanced",
    "random_state":      42,
    "n_jobs":            -1,
}

REJECTION_THRESHOLD = 0.50


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_data(csv_path: Path) -> Tuple[pd.DataFrame, np.ndarray, np.ndarray, LabelEncoder]:
    """Load device-window dataset, drop flow-level columns, encode labels."""
    df = pd.read_csv(csv_path)
    le = LabelEncoder()
    y  = le.fit_transform(df[LABEL_COL])
    feature_cols = [c for c in df.columns if c not in DROP_COLS]

    # Log dropped columns
    dropped = [c for c in DROP_COLS if c in df.columns]
    if dropped:
        log.info("Dropped flow-level / meta columns: %s", dropped)

    X = df[feature_cols].fillna(0.0).values.astype(np.float32)
    log.info("Device model: %d samples, %d features, %d classes: %s",
             len(df), X.shape[1], len(le.classes_), list(le.classes_))
    return df, X, y, le


# ---------------------------------------------------------------------------
# Nested LOSO CV for device model
# ---------------------------------------------------------------------------

def nested_loso_cv_device(
    df: pd.DataFrame,
    X: np.ndarray,
    y: np.ndarray,
    le: LabelEncoder,
    out_dir: Path,
) -> List[Dict[str, Any]]:
    """Same structure as flow model but uses device-window features."""
    batches = sorted(df[BATCH_COL].unique().tolist())
    if len(batches) < 2:
        raise ValueError(f"Need ≥2 batches, got: {batches}")

    feature_cols = [c for c in df.columns if c not in DROP_COLS]
    X_use = df[feature_cols].fillna(0.0).values.astype(np.float32)

    fold_results: List[Dict[str, Any]] = []

    for test_batch in batches:
        log.info("=" * 60)
        log.info("Device model — Outer fold test: %s", test_batch)

        test_mask  = df[BATCH_COL] == test_batch
        train_mask = ~test_mask

        X_tv, y_tv = X_use[train_mask], y[train_mask]
        X_te, y_te = X_use[test_mask],  y[test_mask]
        df_tv      = df[train_mask]

        inner_batches = [b for b in batches if b != test_batch]
        best_n = _inner_loso_select_n_estimators(
            df_tv, X_tv, y_tv, inner_batches, feature_cols
        )
        log.info("Inner CV chose n_estimators=%d", best_n)

        params = {**LGBM_PARAMS, "n_estimators": best_n}
        model  = lgb.LGBMClassifier(**params)
        model.fit(X_tv, y_tv)

        # Calibrate on last inner batch
        val_batch = inner_batches[-1]
        val_mask  = df_tv[BATCH_COL] == val_batch
        X_cal = X_tv[val_mask.values]
        y_cal = y_tv[val_mask.values]
        calibrators = _fit_calibrators(model, X_cal, y_cal, len(le.classes_))

        raw_probs   = model.predict_proba(X_te)
        cal_probs   = _apply_calibrators(calibrators, raw_probs, len(le.classes_))
        y_pred      = np.argmax(cal_probs, axis=1)

        f1_macro = f1_score(y_te, y_pred, average="macro", zero_division=0)
        report   = classification_report(y_te, y_pred, target_names=le.classes_,
                                         zero_division=0, output_dict=True)
        cm       = confusion_matrix(y_te, y_pred).tolist()

        result = {
            "test_batch":       test_batch,
            "n_estimators":     best_n,
            "n_test":           int(y_te.shape[0]),
            "f1_macro":         round(float(f1_macro), 4),
            "report":           report,
            "confusion_matrix": cm,
            "class_names":      list(le.classes_),
        }
        fold_results.append(result)

        log.info("Fold %s → F1_macro=%.4f", test_batch, f1_macro)
        print(classification_report(y_te, y_pred, target_names=le.classes_, zero_division=0))

        fold_out = out_dir / f"fold_{test_batch}"
        fold_out.mkdir(parents=True, exist_ok=True)
        model.booster_.save_model(str(fold_out / "model.txt"))
        _save_calibrators(calibrators, fold_out / "calibrators.json")

    return fold_results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Train LightGBM per-device-window classifier.")
    parser.add_argument("--data",    default=str(DATA_PATH))
    parser.add_argument("--out",     default=str(OUT_DIR))
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    df, X, y, le = load_data(Path(args.data))

    (out_dir / "label_encoder.json").write_text(
        json.dumps({"classes": list(le.classes_)}, ensure_ascii=False)
    )

    print("\n>>> Running nested LOSO CV for per-device-window model...")
    results = nested_loso_cv_device(df, X, y, le, out_dir)
    summarize_folds(results, out_dir)

    median_n = int(np.median([r["n_estimators"] for r in results]))
    print(f"\n>>> Training final device model (n_estimators={median_n})...")
    train_final_model(X, y, median_n, out_dir)


if __name__ == "__main__":
    main()
