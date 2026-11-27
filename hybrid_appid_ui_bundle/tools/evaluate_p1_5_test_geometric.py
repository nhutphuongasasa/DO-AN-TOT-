import csv
import math
from pathlib import Path

from catboost import CatBoostClassifier, Pool
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)

BASE = Path("outputs/p1_5_full_dataset_v1/catboost")
PREP = BASE / "prepared"
OUT = BASE / "flow_aggregation"
OUT.mkdir(parents=True, exist_ok=True)

classes = [
    "chatgpt", "facebook", "other-web",
    "spotify", "tiktok", "youtube",
]

def read_tsv(path):
    with path.open(encoding="utf-8") as f:
        return list(csv.reader(f, delimiter="\t"))

print("Loading CatBoost model...")
model = CatBoostClassifier()
model.load_model(str(BASE / "catboost_p1_5.cbm"))

data = read_tsv(PREP / "test.tsv")
keys = read_tsv(PREP / "test.keys.tsv")

assert len(data) == len(keys)
assert len(data) > 0

X = []
labels = []

for i, row in enumerate(data):
    if len(row) != 22:
        raise ValueError(f"Unexpected columns at row {i}: {len(row)}")

    labels.append(row[0])

    features = []
    for value in row[2:21]:
        value = value.strip()
        features.append(float(value) if value else float("nan"))

    features.append(row[21])
    X.append(features)

print("Test Burst rows:", len(X))
print("Predicting Burst probabilities...")

pool = Pool(X, cat_features=[19])
probs = model.predict_proba(pool)

flows = {}

for key, label, prob in zip(keys, labels, probs):
    flow_key = (key[0], key[1])

    if flow_key not in flows:
        flows[flow_key] = {
            "label": label,
            "probs": [],
        }

    if flows[flow_key]["label"] != label:
        raise ValueError(f"Inconsistent label: {flow_key}")

    flows[flow_key]["probs"].append([float(x) for x in prob])

print("Test Flows:", len(flows))

def mean_aggregate(rows):
    n = len(rows)
    return [
        sum(row[c] for row in rows) / n
        for c in range(len(classes))
    ]

def geometric_aggregate(rows):
    eps = 1e-12
    n = len(rows)

    values = [
        math.exp(
            sum(math.log(max(row[c], eps)) for row in rows) / n
        )
        for c in range(len(classes))
    ]

    total = sum(values)
    return [v / total for v in values]

y_true = [flow["label"] for flow in flows.values()]

for method, fn in [
    ("mean", mean_aggregate),
    ("geometric_mean", geometric_aggregate),
]:
    y_pred = []
    output_rows = []

    for key, flow in flows.items():
        p = fn(flow["probs"])
        pred = classes[max(range(len(p)), key=lambda i: p[i])]
        y_pred.append(pred)

        output_rows.append({
            "session_id": key[0],
            "flow_id": key[1],
            "true_application": flow["label"],
            "predicted_application": pred,
            **{
                f"prob_{classes[i]}": p[i]
                for i in range(len(classes))
            },
        })

    print("\n" + "=" * 70)
    print(method.upper())
    print("=" * 70)

    print("Accuracy:", accuracy_score(y_true, y_pred))
    print("Macro F1:", f1_score(
        y_true, y_pred,
        labels=classes,
        average="macro",
        zero_division=0,
    ))
    print("Balanced Accuracy:", balanced_accuracy_score(y_true, y_pred))

    print(classification_report(
        y_true, y_pred,
        labels=classes,
        target_names=classes,
        digits=4,
        zero_division=0,
    ))

    print("Confusion matrix (rows=true, columns=predicted):")
    for row in confusion_matrix(y_true, y_pred, labels=classes):
        print(row)

    path = OUT / f"test_{method}_predictions.csv"
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(output_rows[0]))
        writer.writeheader()
        writer.writerows(output_rows)

    print("Saved:", path)

print("\nTEST EVALUATION COMPLETE")
