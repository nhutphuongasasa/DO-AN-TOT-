import json
from pathlib import Path

import numpy as np
import pandas as pd
from catboost import CatBoostClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)

BASE = Path("outputs/p1_5_full_dataset_wirelen_v2")
FLOW_CSV = BASE / "catboost_flow_v2" / "flow_features.csv"
CNN_FILES = [
    BASE / "cnn1d" / "train_predictions.csv",
    BASE / "cnn1d" / "validation_predictions.csv",
    BASE / "cnn1d" / "test_predictions.csv",
]
MODEL_PATH = BASE / "catboost_flow_v2" / "catboost_flow_v2.cbm"
OUT = BASE / "late_fusion"

OUT.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------
# 1. Load CatBoost model and flow features
# --------------------------------------------------
model = CatBoostClassifier()
model.load_model(str(MODEL_PATH))

flow = pd.read_csv(FLOW_CSV)
classes = list(model.classes_)

metadata = ["session_id", "flow_id", "application", "batch_id", "split"]
feature_names = list(model.feature_names_)

missing = [c for c in metadata + feature_names if c not in flow.columns]
if missing:
    raise ValueError(f"Missing columns in flow_features.csv: {missing}")

if flow.duplicated(["session_id", "flow_id"]).any():
    raise ValueError("Duplicate Flow keys in flow_features.csv")

# --------------------------------------------------
# 2. Load CNN probabilities
# --------------------------------------------------
cnn = pd.concat([pd.read_csv(f) for f in CNN_FILES], ignore_index=True)

key = ["session_id", "flow_id"]
prob_cols = [f"prob_{c}" for c in classes]

required_cnn = key + ["split", "true_label", "predicted_label"] + prob_cols
missing = [c for c in required_cnn if c not in cnn.columns]
if missing:
    raise ValueError(
        f"Missing CNN columns: {missing}\n"
        f"Available columns: {list(cnn.columns)}"
    )

if cnn.duplicated(key).any():
    raise ValueError("Duplicate Flow keys in CNN predictions")

# --------------------------------------------------
# 3. Match exactly the same flows
# --------------------------------------------------
data = flow.merge(
    cnn[required_cnn],
    on=key,
    how="inner",
    validate="one_to_one",
    suffixes=("_flow", "_cnn"),
)

if len(data) != len(flow) or len(data) != len(cnn):
    raise ValueError(
        f"Flow mismatch: features={len(flow)}, CNN={len(cnn)}, matched={len(data)}"
    )

if not (data["application"] == data["true_label"]).all():
    raise ValueError("Ground-truth labels differ between Flow features and CNN")

if not (data["split_flow"] == data["split_cnn"]).all():
    raise ValueError("Split labels differ between Flow features and CNN")

# --------------------------------------------------
# 4. CatBoost probabilities
# --------------------------------------------------
X = data[feature_names].copy()

for col in feature_names:
    X[col] = pd.to_numeric(X[col], errors="raise")

cat_prob = model.predict_proba(X)
cnn_prob = data[prob_cols].to_numpy(dtype=float)

if not np.isfinite(cat_prob).all():
    raise ValueError("CatBoost probabilities contain NaN or infinity")

if not np.isfinite(cnn_prob).all():
    raise ValueError("CNN probabilities contain NaN or infinity")

if not np.allclose(cat_prob.sum(axis=1), 1, atol=1e-4):
    raise ValueError("CatBoost probability rows do not sum to 1")

if not np.allclose(cnn_prob.sum(axis=1), 1, atol=1e-3):
    raise ValueError("CNN probability rows do not sum to 1")

y = data["application"].to_numpy()
splits = data["split_flow"].to_numpy()

# --------------------------------------------------
# 5. Evaluate helper
# --------------------------------------------------
def evaluate(y_true, probabilities):
    predictions = np.array(classes)[probabilities.argmax(axis=1)]

    return {
        "samples": len(y_true),
        "accuracy": float(accuracy_score(y_true, predictions)),
        "macro_f1": float(f1_score(
            y_true, predictions, labels=classes,
            average="macro", zero_division=0
        )),
        "balanced_accuracy": float(
            balanced_accuracy_score(y_true, predictions)
        ),
        "classification_report": classification_report(
            y_true, predictions, labels=classes,
            output_dict=True, zero_division=0
        ),
        "confusion_matrix": confusion_matrix(
            y_true, predictions, labels=classes
        ).tolist(),
    }

# --------------------------------------------------
# 6. Tune alpha using VALIDATION ONLY
#    fusion = alpha * CatBoost + (1-alpha) * CNN
# --------------------------------------------------
val_mask = splits == "validation"
if not val_mask.any():
    raise ValueError("No validation samples found")

best = None
search_results = []

for alpha in np.arange(0, 1.0001, 0.05):
    fused = alpha * cat_prob[val_mask] + (1 - alpha) * cnn_prob[val_mask]
    metrics = evaluate(y[val_mask], fused)

    row = {
        "alpha_catboost": round(float(alpha), 2),
        "alpha_cnn": round(float(1 - alpha), 2),
        "macro_f1": metrics["macro_f1"],
        "balanced_accuracy": metrics["balanced_accuracy"],
        "accuracy": metrics["accuracy"],
    }
    search_results.append(row)

    score = (
        metrics["macro_f1"],
        metrics["balanced_accuracy"],
        alpha,
    )

    if best is None or score > best["score"]:
        best = {"score": score, "alpha": float(alpha), "metrics": metrics}

alpha = best["alpha"]

# --------------------------------------------------
# 7. Evaluate all splits with selected alpha
# --------------------------------------------------
summary = {
    "classes": classes,
    "best_alpha_catboost": alpha,
    "best_alpha_cnn": 1 - alpha,
    "selection_rule": "Highest validation macro F1; tie-break balanced accuracy, then CatBoost weight",
    "validation_alpha_search": search_results,
    "splits": {},
}

prediction_frames = []

for split_name in ["train", "validation", "test"]:
    mask = splits == split_name
    if not mask.any():
        continue

    fused = alpha * cat_prob[mask] + (1 - alpha) * cnn_prob[mask]
    metrics = evaluate(y[mask], fused)
    summary["splits"][split_name] = metrics

    part = data.loc[mask, key + ["batch_id", "application"]].copy()
    part = part.rename(columns={"application": "true_label"})
    part["split"] = split_name

    part["catboost_prediction"] = np.array(classes)[
        cat_prob[mask].argmax(axis=1)
    ]
    part["cnn_prediction"] = np.array(classes)[
        cnn_prob[mask].argmax(axis=1)
    ]
    part["fusion_prediction"] = np.array(classes)[
        fused.argmax(axis=1)
    ]

    for i, cls in enumerate(classes):
        part[f"catboost_prob_{cls}"] = cat_prob[mask, i]
        part[f"cnn_prob_{cls}"] = cnn_prob[mask, i]
        part[f"fusion_prob_{cls}"] = fused[:, i]

    prediction_frames.append(part)

# --------------------------------------------------
# 8. Save outputs
# --------------------------------------------------
predictions = pd.concat(prediction_frames, ignore_index=True)
predictions.to_csv(OUT / "fusion_predictions.csv", index=False)

with open(OUT / "metrics.json", "w") as f:
    json.dump(summary, f, indent=2)

pd.DataFrame(search_results).to_csv(
    OUT / "validation_alpha_search.csv", index=False
)

print("\n========== LATE FUSION RESULTS ==========")
print("Best CatBoost alpha:", alpha)
print("Best CNN alpha:", 1 - alpha)

for split_name, metrics in summary["splits"].items():
    print(f"\n--- {split_name.upper()} ---")
    print("Samples:", metrics["samples"])
    print("Accuracy:", round(metrics["accuracy"], 4))
    print("Macro F1:", round(metrics["macro_f1"], 4))
    print("Balanced accuracy:", round(metrics["balanced_accuracy"], 4))

print("\nSaved outputs to:", OUT)
