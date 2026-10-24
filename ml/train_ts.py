"""ml/train_ts.py — Huấn luyện 1D-CNN/LSTM trên time-series per-device-window.

Input: Chuỗi (T, 4) — mỗi bước 0.5s = [log1p(bytes_up), log1p(bytes_down),
                                          log1p(pkts_up),  log1p(pkts_down)]
       T = window_s / bin_s = 30 / 0.5 = 60 bước

Output: ONNX model tại ml/models/ts/model.onnx

Usage:
    python3 -m ml.train_ts
    python3 -m ml.train_ts --data ml/data/dataset_timeseries.npz --out ml/models/ts/
    python3 -m ml.train_ts --arch lstm  # Dùng LSTM thay vì CNN
"""
from __future__ import annotations

import argparse
import json
import logging
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.preprocessing import LabelEncoder

warnings.filterwarnings("ignore")

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Try importing deep learning framework (PyTorch preferred, TF fallback)
# ---------------------------------------------------------------------------

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    _BACKEND = "torch"
except ImportError:
    _BACKEND = None

DATA_PATH = Path("ml/data/dataset_timeseries.npz")
OUT_DIR   = Path("ml/models/ts")
BATCH_COL_IDX = -2   # second-to-last column in sequences.npz label array
BATCH_SIZE  = 64
N_EPOCHS    = 40
LR          = 1e-3
PATIENCE    = 8      # Early stopping patience


# ---------------------------------------------------------------------------
# Model Definitions (PyTorch)
# ---------------------------------------------------------------------------

if _BACKEND == "torch":

    class Conv1DClassifier(nn.Module):
        """1D-CNN for time-series traffic classification.

        Input:  (batch, T, 4)  — T=60 time bins, 4 features per bin
        Output: (batch, n_classes) logits
        """

        def __init__(self, n_classes: int, T: int = 60, in_channels: int = 4) -> None:
            super().__init__()
            self.conv_block = nn.Sequential(
                # (B, 4, T) after permute
                nn.Conv1d(in_channels, 32, kernel_size=5, padding=2),
                nn.BatchNorm1d(32),
                nn.ReLU(),
                nn.MaxPool1d(2),          # T/2
                nn.Dropout(0.25),

                nn.Conv1d(32, 64, kernel_size=3, padding=1),
                nn.BatchNorm1d(64),
                nn.ReLU(),
                nn.MaxPool1d(2),          # T/4
                nn.Dropout(0.25),

                nn.Conv1d(64, 128, kernel_size=3, padding=1),
                nn.BatchNorm1d(128),
                nn.ReLU(),
                nn.AdaptiveAvgPool1d(1),  # (B, 128, 1)
            )
            self.classifier = nn.Sequential(
                nn.Flatten(),
                nn.Linear(128, 64),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(64, n_classes),
            )

        def forward(self, x: "torch.Tensor") -> "torch.Tensor":
            # x: (B, T, 4) → permute → (B, 4, T) for Conv1d
            x = x.permute(0, 2, 1)
            x = self.conv_block(x)
            return self.classifier(x)


    class LSTMClassifier(nn.Module):
        """Bidirectional LSTM for time-series traffic classification.

        Input:  (batch, T, 4)
        Output: (batch, n_classes) logits
        """

        def __init__(self, n_classes: int, T: int = 60, in_channels: int = 4,
                     hidden: int = 64, n_layers: int = 2) -> None:
            super().__init__()
            self.lstm = nn.LSTM(
                input_size=in_channels,
                hidden_size=hidden,
                num_layers=n_layers,
                batch_first=True,
                bidirectional=True,
                dropout=0.3 if n_layers > 1 else 0.0,
            )
            self.classifier = nn.Sequential(
                nn.Linear(hidden * 2, 64),   # *2 for bidirectional
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(64, n_classes),
            )

        def forward(self, x: "torch.Tensor") -> "torch.Tensor":
            # Take last hidden state
            out, _ = self.lstm(x)
            return self.classifier(out[:, -1, :])


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_data(npz_path: Path) -> Tuple[np.ndarray, np.ndarray, np.ndarray, LabelEncoder]:
    """Load time-series dataset.

    Returns:
        sequences: (N, T, 4) float32
        y_enc:     (N,) int
        batch_ids: (N,) str
        le:        LabelEncoder
    """
    data = np.load(npz_path, allow_pickle=True)
    X    = data["sequences"].astype(np.float32)   # (N, T, 4)
    raw_labels  = data["labels"]                   # (N,) str
    batch_ids   = data["batch_ids"] if "batch_ids" in data else np.array(["unknown"] * len(X))

    le = LabelEncoder()
    y  = le.fit_transform(raw_labels)

    log.info("Time-series dataset: %d samples, shape %s, %d classes: %s",
             len(X), X.shape, len(le.classes_), list(le.classes_))
    return X, y.astype(np.int64), batch_ids, le


# ---------------------------------------------------------------------------
# Training (PyTorch)
# ---------------------------------------------------------------------------

def _train_one_fold(
    X_train: np.ndarray, y_train: np.ndarray,
    X_val:   np.ndarray, y_val:   np.ndarray,
    n_classes: int,
    arch: str,
    out_fold_dir: Path,
) -> Tuple[Any, float]:
    """Train one fold, return (model, best_val_f1)."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    T = X_train.shape[1]

    if arch == "lstm":
        model = LSTMClassifier(n_classes=n_classes, T=T).to(device)
    else:
        model = Conv1DClassifier(n_classes=n_classes, T=T).to(device)

    # Class weights for imbalanced data
    class_counts = np.bincount(y_train, minlength=n_classes)
    class_counts = np.where(class_counts == 0, 1, class_counts)
    weights = torch.tensor(1.0 / class_counts, dtype=torch.float32).to(device)
    criterion = nn.CrossEntropyLoss(weight=weights)
    optimizer = optim.AdamW(model.parameters(), lr=LR, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=N_EPOCHS)

    # DataLoaders
    X_tr_t = torch.from_numpy(X_train)
    y_tr_t = torch.from_numpy(y_train)
    X_va_t = torch.from_numpy(X_val)
    y_va_t = torch.from_numpy(y_val)

    train_dl = DataLoader(TensorDataset(X_tr_t, y_tr_t),
                          batch_size=BATCH_SIZE, shuffle=True, drop_last=False)
    val_dl   = DataLoader(TensorDataset(X_va_t, y_va_t),
                          batch_size=BATCH_SIZE, shuffle=False)

    best_val_f1   = 0.0
    best_state    = None
    patience_cnt  = 0

    for epoch in range(1, N_EPOCHS + 1):
        model.train()
        total_loss = 0.0
        for xb, yb in train_dl:
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()
            loss = criterion(model(xb), yb)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total_loss += loss.item()
        scheduler.step()

        # Validation
        model.eval()
        all_preds, all_true = [], []
        with torch.no_grad():
            for xb, yb in val_dl:
                preds = model(xb.to(device)).argmax(dim=1).cpu().numpy()
                all_preds.extend(preds)
                all_true.extend(yb.numpy())

        val_f1 = f1_score(all_true, all_preds, average="macro", zero_division=0)

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_state  = {k: v.clone() for k, v in model.state_dict().items()}
            patience_cnt = 0
        else:
            patience_cnt += 1

        if epoch % 5 == 0 or patience_cnt == 0:
            log.info("  Epoch %3d | loss=%.4f | val_F1=%.4f%s",
                     epoch, total_loss / len(train_dl), val_f1,
                     " ← best" if patience_cnt == 0 else "")

        if patience_cnt >= PATIENCE:
            log.info("  Early stop at epoch %d (patience=%d)", epoch, PATIENCE)
            break

    if best_state:
        model.load_state_dict(best_state)

    # Save checkpoint
    out_fold_dir.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), out_fold_dir / "model.pt")
    log.info("  Saved checkpoint → %s", out_fold_dir / "model.pt")

    return model, best_val_f1


# ---------------------------------------------------------------------------
# ONNX Export
# ---------------------------------------------------------------------------

def export_onnx(model: Any, T: int, out_path: Path) -> None:
    """Export PyTorch model to ONNX for inference on Pi via onnxruntime."""
    try:
        import torch
    except ImportError:
        log.warning("PyTorch not found, cannot export ONNX")
        return

    model.eval()
    dummy = torch.zeros(1, T, 4)  # (batch=1, T, 4)
    try:
        torch.onnx.export(
            model, dummy, str(out_path),
            input_names=["timeseries"],
            output_names=["logits"],
            dynamic_axes={"timeseries": {0: "batch_size"}},
            opset_version=17,
        )
        log.info("ONNX exported → %s", out_path)
    except Exception as e:
        log.error("ONNX export failed: %s", e)


# ---------------------------------------------------------------------------
# Nested LOSO CV
# ---------------------------------------------------------------------------

def nested_loso_cv_ts(
    X: np.ndarray,
    y: np.ndarray,
    batch_ids: np.ndarray,
    le: LabelEncoder,
    out_dir: Path,
    arch: str = "cnn",
) -> List[Dict[str, Any]]:
    """Nested LOSO cross-validation for time-series model."""
    if _BACKEND != "torch":
        log.error("PyTorch not installed. Install: pip install torch")
        return []

    batches = sorted(set(batch_ids.tolist()))
    if len(batches) < 2:
        raise ValueError(f"Need ≥2 batches, got: {batches}")

    fold_results: List[Dict[str, Any]] = []

    for test_batch in batches:
        log.info("=" * 60)
        log.info("TS model — Outer fold: %s", test_batch)

        te_mask = batch_ids == test_batch
        tr_mask = ~te_mask

        X_tv, y_tv, bids_tv = X[tr_mask], y[tr_mask], batch_ids[tr_mask]
        X_te, y_te           = X[te_mask], y[te_mask]

        # Inner: use last batch in trainval as val
        inner_batches = [b for b in batches if b != test_batch]
        val_batch     = inner_batches[-1]
        val_mask      = bids_tv == val_batch
        tr_mask_inner = ~val_mask

        X_tr, y_tr = X_tv[tr_mask_inner], y_tv[tr_mask_inner]
        X_va, y_va = X_tv[val_mask],      y_tv[val_mask]

        fold_dir = out_dir / f"fold_{test_batch}"
        model, val_f1 = _train_one_fold(
            X_tr, y_tr, X_va, y_va,
            n_classes=len(le.classes_),
            arch=arch,
            out_fold_dir=fold_dir,
        )
        log.info("  Val F1 (inner) = %.4f", val_f1)

        # Evaluate on test
        import torch
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.eval()
        X_te_t = torch.from_numpy(X_te)
        test_dl = DataLoader(TensorDataset(X_te_t), batch_size=BATCH_SIZE)
        all_preds = []
        with torch.no_grad():
            for (xb,) in test_dl:
                preds = model(xb.to(device)).argmax(dim=1).cpu().numpy()
                all_preds.extend(preds)
        y_pred = np.array(all_preds)

        f1_macro = f1_score(y_te, y_pred, average="macro", zero_division=0)
        report   = classification_report(y_te, y_pred, target_names=le.classes_,
                                         zero_division=0, output_dict=True)
        cm       = confusion_matrix(y_te, y_pred).tolist()

        result = {
            "test_batch":       test_batch,
            "arch":             arch,
            "n_test":           int(y_te.shape[0]),
            "f1_macro":         round(float(f1_macro), 4),
            "val_f1_inner":     round(float(val_f1), 4),
            "report":           report,
            "confusion_matrix": cm,
            "class_names":      list(le.classes_),
        }
        fold_results.append(result)
        log.info("Fold %s → F1_macro=%.4f", test_batch, f1_macro)
        print(classification_report(y_te, y_pred, target_names=le.classes_, zero_division=0))

    # Export final ONNX (retrain on all data using first fold's arch)
    if fold_results and _BACKEND == "torch":
        log.info("Training final model on ALL data for ONNX export...")
        T = X.shape[1]
        all_bids = sorted(set(batch_ids.tolist()))
        last_b   = all_bids[-1]
        val_m    = batch_ids == last_b
        _model, _ = _train_one_fold(
            X[~val_m], y[~val_m], X[val_m], y[val_m],
            n_classes=len(le.classes_),
            arch=arch,
            out_fold_dir=out_dir / "final",
        )
        export_onnx(_model, T, out_dir / "model.onnx")

    return fold_results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Train 1D-CNN/LSTM on time-series data.")
    parser.add_argument("--data",    default=str(DATA_PATH))
    parser.add_argument("--out",     default=str(OUT_DIR))
    parser.add_argument("--arch",    choices=["cnn", "lstm"], default="cnn",
                        help="Model architecture (default: cnn)")
    parser.add_argument("--epochs",  type=int, default=N_EPOCHS)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    global N_EPOCHS
    N_EPOCHS = args.epochs

    if _BACKEND != "torch":
        print("❌ PyTorch not installed. Install with: pip install torch")
        print("   LightGBM models (train_flow.py, train_device.py) don't need PyTorch.")
        return

    if not Path(args.data).exists():
        print(f"❌ Dataset not found: {args.data}")
        print("   Run dataset_builder first: python3 -m ml.dataset_builder")
        return

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    X, y, batch_ids, le = load_data(Path(args.data))
    (out_dir / "label_encoder.json").write_text(
        json.dumps({"classes": list(le.classes_)}, ensure_ascii=False)
    )

    print(f"\n>>> Training {args.arch.upper()} on time-series data ({X.shape})...")
    results = nested_loso_cv_ts(X, y, batch_ids, le, out_dir, arch=args.arch)

    if results:
        f1s = [r["f1_macro"] for r in results]
        print(f"\nTime-series ({args.arch.upper()}) — Mean F1: {np.mean(f1s):.4f} ± {np.std(f1s):.4f}")

        summary = {
            "arch":    args.arch,
            "f1_mean": float(np.mean(f1s)),
            "f1_std":  float(np.std(f1s)),
            "f1_min":  float(np.min(f1s)),
            "f1_max":  float(np.max(f1s)),
            "folds":   results,
        }
        (out_dir / "cv_summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False)
        )

        if (out_dir / "model.onnx").exists():
            print(f"✔ ONNX model: {out_dir / 'model.onnx'}")
            print(f"   Deploy on Pi: python3 -m ml.predictor (CNNONNXPredictor)")


if __name__ == "__main__":
    main()
