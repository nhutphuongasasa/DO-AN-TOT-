import csv
import json
import math
from pathlib import Path

from catboost import CatBoostClassifier, Pool
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    f1_score,
)

BASE = Path("outputs/p1_5_full_dataset_v1/catboost")
PREP = BASE / "prepared"

MODEL_PATH = BASE / "catboost_p1_5.cbm"
DATA_PATH = PREP / "validation.tsv"
KEYS_PATH = PREP / "validation.keys.tsv"
CD_PATH = PREP / "column_description.tsv"
BASELINE_PATH = BASE / "validation_flow_predictions.csv"

OUT_DIR = BASE / "flow_aggregation"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def read_tsv(path):
    with path.open(encoding="utf-8") as f:
        return list(csv.reader(f, delimiter="\t"))


print("=== FLOW AGGREGATION EXPERIMENT ===")

# 1. Load model
model = CatBoostClassifier()
model.load_model(str(MODEL_PATH))

classes = [str(x) for x in model.classes_]
class_index = {name: i for i, name in enumerate(classes)}

print("Classes:", classes)

# 2. Load prepared Burst data and Flow keys
data_rows = read_tsv(DATA_PATH)
key_rows = read_tsv(KEYS_PATH)

assert len(data_rows) == len(key_rows), (
    f"Row mismatch: data={len(data_rows)}, keys={len(key_rows)}"
)

assert data_rows, "Validation data is empty"

# Original feature layout:
# column 0: label
# column 1: weight
# columns 2..20: 19 numeric features
# column 21: categorical direction

X = []
burst_labels = []
packet_weights = []

for i, row in enumerate(data_rows):
    if len(row) != 22:
        raise ValueError(
            f"Unexpected column count at row {i}: {len(row)}"
        )

    burst_labels.append(row[0])

    features = []
    for value in row[2:21]:
        value = value.strip()
        features.append(float(value) if value else float("nan"))

    features.append(row[21])
    X.append(features)

    packet_count = float(row[3])
    packet_weights.append(max(packet_count, 1.0))

print("Burst rows:", len(X))
print("Flow keys:", len(key_rows))

# 3. Predict Burst probabilities using existing model
print("\nPredicting Burst probabilities...")

pool = Pool(
    data=X,
    cat_features=[19],
)

burst_probabilities = model.predict_proba(pool)

assert len(burst_probabilities) == len(key_rows)

# 4. Group Burst predictions by Flow
flows = {}

for i, (key, label, probs, weight) in enumerate(
    zip(key_rows, burst_labels, burst_probabilities, packet_weights)
):
    session_id, flow_id = key

    flow_key = (session_id, flow_id)

    if flow_key not in flows:
        flows[flow_key] = {
            "label": label,
            "probabilities": [],
            "weights": [],
        }

    flow = flows[flow_key]

    if flow["label"] != label:
        raise ValueError(f"Inconsistent labels: {flow_key}")

    flow["probabilities"].append([float(x) for x in probs])
    flow["weights"].append(weight)

print("Grouped Flows:", len(flows))

# 5. Load existing Flow predictions for baseline comparison
baseline = {}

with BASELINE_PATH.open(encoding="utf-8", newline="") as f:
    for row in csv.DictReader(f):
        key = (row["session_id"], row["flow_id"])

        baseline[key] = {
            "label": row["true_application"],
            "prediction": row["predicted_application"],
            "probabilities": [
                float(row[f"prob_{name}"]) for name in classes
            ],
        }

assert set(baseline) == set(flows), (
    "Flow keys do not match existing baseline predictions"
)

# 6. Aggregation methods
def aggregate_mean(probabilities, weights):
    n = len(probabilities)

    return [
        sum(p[c] for p in probabilities) / n
        for c in range(len(classes))
    ]


def aggregate_packet_weighted(probabilities, weights):
    total_weight = sum(weights)

    return [
        sum(
            probabilities[i][c] * weights[i]
            for i in range(len(probabilities))
        ) / total_weight
        for c in range(len(classes))
    ]


def aggregate_geometric(probabilities, weights):
    eps = 1e-12
    n = len(probabilities)

    values = [
        math.exp(
            sum(
                math.log(max(p[c], eps))
                for p in probabilities
            ) / n
        )
        for c in range(len(classes))
    ]

    total = sum(values)

    return [x / total for x in values]


methods = {
    "mean": aggregate_mean,
    "packet_weighted": aggregate_packet_weighted,
    "geometric_mean": aggregate_geometric,
}

y_true = []
for key in flows:
    y_true.append(flows[key]["label"])

results = {}

# Baseline metrics
baseline_pred = [baseline[key]["prediction"] for key in flows]

results["baseline_existing"] = {
    "accuracy": accuracy_score(y_true, baseline_pred),
    "macro_f1": f1_score(
        y_true, baseline_pred,
        labels=classes,
        average="macro",
        zero_division=0,
    ),
    "balanced_accuracy": balanced_accuracy_score(
        y_true, baseline_pred
    ),
}

# 7. Evaluate each aggregation method
all_output_rows = []

for method_name, aggregate_fn in methods.items():
    predictions = []

    for key, flow in flows.items():
        probs = aggregate_fn(
            flow["probabilities"],
            flow["weights"],
        )

        pred = classes[max(range(len(probs)), key=lambda c: probs[c])]
        predictions.append(pred)

        all_output_rows.append({
            "method": method_name,
            "session_id": key[0],
            "flow_id": key[1],
            "true_application": flow["label"],
            "predicted_application": pred,
            **{
                f"prob_{classes[c]}": probs[c]
                for c in range(len(classes))
            },
        })

    results[method_name] = {
        "accuracy": accuracy_score(y_true, predictions),
        "macro_f1": f1_score(
            y_true, predictions,
            labels=classes,
            average="macro",
            zero_division=0,
        ),
        "balanced_accuracy": balanced_accuracy_score(
            y_true, predictions
        ),
    }

# 8. Verify mean aggregation against existing predictions
mean_differences = []

for key, flow in flows.items():
    calculated = aggregate_mean(
        flow["probabilities"],
        flow["weights"],
    )

    saved = baseline[key]["probabilities"]

    mean_differences.append(
        max(abs(a - b) for a, b in zip(calculated, saved))
    )

max_difference = max(mean_differences)

results["verification"] = {
    "max_probability_difference_mean_vs_saved": max_difference,
    "flow_count": len(flows),
    "burst_count": len(data_rows),
}

# 9. Save results
output_csv = OUT_DIR / "validation_aggregation_predictions.csv"

fieldnames = [
    "method",
    "session_id",
    "flow_id",
    "true_application",
    "predicted_application",
] + [f"prob_{name}" for name in classes]

with output_csv.open("w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(all_output_rows)

metrics_path = OUT_DIR / "validation_aggregation_metrics.json"

with metrics_path.open("w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

# 10. Print summary
print("\n=== VALIDATION RESULTS ===")

for name in [
    "baseline_existing",
    "mean",
    "packet_weighted",
    "geometric_mean",
]:
    result = results[name]

    print(f"\n{name}")
    print(f"  Accuracy:          {result['accuracy']:.6f}")
    print(f"  Macro F1:          {result['macro_f1']:.6f}")
    print(f"  Balanced Accuracy: {result['balanced_accuracy']:.6f}")

print("\n=== BASELINE VERIFICATION ===")
print("Maximum probability difference:", max_difference)

if max_difference > 1e-5:
    print("WARNING: Mean aggregation differs from saved baseline.")
else:
    print("PASS: Mean aggregation matches saved baseline.")

print("\nSaved:")
print(output_csv)
print(metrics_path)

print("\n=== EXPERIMENT COMPLETE ===")
