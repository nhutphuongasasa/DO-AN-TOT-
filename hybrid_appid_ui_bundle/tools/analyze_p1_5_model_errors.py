from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)

BASE = Path("outputs/p1_5_full_dataset_v1")
CLASSES = [
    "chatgpt",
    "facebook",
    "other-web",
    "spotify",
    "tiktok",
    "youtube",
]

fusion = pd.read_csv(BASE / "late_fusion" / "fusion_predictions.csv")

# Chỉ phân tích Test
df = fusion[fusion["split"] == "test"].copy()

models = {
    "CatBoost": "catboost_prediction",
    "CNN": "cnn_prediction",
    "Late Fusion": "fusion_prediction",
}

print("=" * 75)
print("TEST SET: MODEL COMPARISON")
print("=" * 75)

for name, pred_col in models.items():
    y_true = df["true_label"]
    y_pred = df[pred_col]

    print(f"\n--- {name} ---")
    print("Accuracy:", round(accuracy_score(y_true, y_pred), 4))
    print("Macro F1:", round(f1_score(
        y_true, y_pred, labels=CLASSES,
        average="macro", zero_division=0
    ), 4))
    print("Balanced accuracy:", round(
        balanced_accuracy_score(y_true, y_pred), 4
    ))

    report = classification_report(
        y_true,
        y_pred,
        labels=CLASSES,
        output_dict=True,
        zero_division=0,
    )

    print("\nPer-class metrics:")
    for cls in CLASSES:
        item = report[cls]
        print(
            f"{cls:12s} "
            f"P={item['precision']:.3f} "
            f"R={item['recall']:.3f} "
            f"F1={item['f1-score']:.3f} "
            f"N={int(item['support'])}"
        )

    cm = confusion_matrix(y_true, y_pred, labels=CLASSES)
    print("\nConfusion matrix (rows=true, columns=predicted):")
    print(pd.DataFrame(cm, index=CLASSES, columns=CLASSES))

print("\n" + "=" * 75)
print("LATE FUSION: WRONG PREDICTIONS")
print("=" * 75)

wrong = df[df["true_label"] != df["fusion_prediction"]]

print("Wrong flows:", len(wrong), "/", len(df))
print("\nMost common confusion pairs:")
print(
    wrong.groupby(["true_label", "fusion_prediction"])
    .size()
    .sort_values(ascending=False)
    .head(20)
    .to_string()
)

print("\n" + "=" * 75)
print("PER-BATCH TEST PERFORMANCE")
print("=" * 75)

for batch, part in df.groupby("batch_id"):
    print(f"\n{batch}: samples={len(part)}")
    for name, pred_col in models.items():
        print(
            f"{name:12s} "
            f"Accuracy={accuracy_score(part['true_label'], part[pred_col]):.4f} "
            f"MacroF1={f1_score(part['true_label'], part[pred_col], labels=CLASSES, average='macro', zero_division=0):.4f}"
        )

print("\nAnalysis complete.")
