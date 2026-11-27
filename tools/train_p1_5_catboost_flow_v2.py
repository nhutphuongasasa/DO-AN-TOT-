import csv
import json
import math
from collections import Counter
from pathlib import Path

from catboost import CatBoostClassifier, Pool
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)

BASE = Path("outputs/p1_5_full_dataset_wirelen_v2")
CSV_FILE = BASE / "burst_statistics.csv"
SPLIT_FILE = BASE / "split_manifest.json"

OUT = BASE / "catboost_flow_v2"
OUT.mkdir(parents=True, exist_ok=True)

CLASSES = [
    "chatgpt",
    "facebook",
    "other-web",
    "spotify",
    "tiktok",
    "youtube",
]

SPLITS = ["train", "validation", "test"]

SEED = 42
THREADS = 4
ITERATIONS = 2000
EARLY_STOPPING = 150

# Các trường Burst được tổng hợp thành mean/std/min/max ở cấp Flow.
BURST_FIELDS = [
    "duration_seconds",
    "packet_count",
    "total_bytes",
    "packet_length_min",
    "packet_length_max",
    "packet_length_mean",
    "packet_length_median",
    "packet_length_std_population",
    "iat_min_seconds",
    "iat_max_seconds",
    "iat_mean_seconds",
    "iat_std_population_seconds",
    "inter_burst_gap_seconds",
]


class OnlineStats:
    """Tính mean, population std, min, max mà không cần lưu toàn bộ dữ liệu."""

    def __init__(self):
        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.minimum = None
        self.maximum = None

    def add(self, value):
        if value is None or not math.isfinite(value):
            return

        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

        if self.minimum is None or value < self.minimum:
            self.minimum = value

        if self.maximum is None or value > self.maximum:
            self.maximum = value

    def summary(self):
        if self.count == 0:
            return {
                "mean": float("nan"),
                "std": float("nan"),
                "min": float("nan"),
                "max": float("nan"),
            }

        variance = max(0.0, self.m2 / self.count)

        return {
            "mean": self.mean,
            "std": math.sqrt(variance),
            "min": self.minimum,
            "max": self.maximum,
        }


def parse_number(value):
    if value is None or value.strip() == "":
        return None

    try:
        result = float(value)
    except (TypeError, ValueError):
        return None

    if not math.isfinite(result):
        return None

    return result


class FlowAccumulator:
    def __init__(self):
        self.burst_count = 0
        self.packet_count = 0
        self.total_bytes = 0

        self.start_ts = None
        self.end_ts = None

        self.direction_counts = Counter()
        self.forward_bytes = 0
        self.backward_bytes = 0
        self.unknown_bytes = 0

        self.iat_missing_bursts = 0
        self.gap_missing_bursts = 0

        self.stats = {
            name: OnlineStats()
            for name in BURST_FIELDS
        }

    def add_burst(self, row):
        self.burst_count += 1

        packet_count = int(row["packet_count"])
        total_bytes = int(row["total_bytes"])

        self.packet_count += packet_count
        self.total_bytes += total_bytes

        start_ts = parse_number(row["start_ts"])
        end_ts = parse_number(row["end_ts"])

        if start_ts is not None:
            if self.start_ts is None or start_ts < self.start_ts:
                self.start_ts = start_ts

        if end_ts is not None:
            if self.end_ts is None or end_ts > self.end_ts:
                self.end_ts = end_ts

        direction = row["direction"]
        self.direction_counts[direction] += 1

        self.forward_bytes += int(row["forward_bytes"] or 0)
        self.backward_bytes += int(row["backward_bytes"] or 0)
        self.unknown_bytes += int(row["unknown_bytes"] or 0)

        if parse_number(row["iat_mean_seconds"]) is None:
            self.iat_missing_bursts += 1

        if parse_number(row["inter_burst_gap_seconds"]) is None:
            self.gap_missing_bursts += 1

        for name in BURST_FIELDS:
            self.stats[name].add(parse_number(row[name]))

    def features(self):
        if self.burst_count == 0:
            raise RuntimeError("Cannot build features for an empty Flow")

        result = {
            "flow_burst_count": self.burst_count,
            "flow_packet_count": self.packet_count,
            "flow_total_bytes": self.total_bytes,
            "flow_duration_seconds": (
                max(0.0, self.end_ts - self.start_ts)
                if self.start_ts is not None and self.end_ts is not None
                else float("nan")
            ),
            "flow_forward_burst_count": self.direction_counts["forward"],
            "flow_backward_burst_count": self.direction_counts["backward"],
            "flow_unknown_burst_count": self.direction_counts["unknown"],
            "flow_forward_burst_ratio": (
                self.direction_counts["forward"] / self.burst_count
            ),
            "flow_backward_burst_ratio": (
                self.direction_counts["backward"] / self.burst_count
            ),
            "flow_unknown_burst_ratio": (
                self.direction_counts["unknown"] / self.burst_count
            ),
            "flow_forward_bytes": self.forward_bytes,
            "flow_backward_bytes": self.backward_bytes,
            "flow_unknown_bytes": self.unknown_bytes,
            "flow_forward_byte_ratio": (
                self.forward_bytes / self.total_bytes
                if self.total_bytes else 0.0
            ),
            "flow_backward_byte_ratio": (
                self.backward_bytes / self.total_bytes
                if self.total_bytes else 0.0
            ),
            "flow_unknown_byte_ratio": (
                self.unknown_bytes / self.total_bytes
                if self.total_bytes else 0.0
            ),
            "flow_iat_missing_fraction": (
                self.iat_missing_bursts / self.burst_count
            ),
            "flow_gap_missing_fraction": (
                self.gap_missing_bursts / self.burst_count
            ),
        }

        for name in BURST_FIELDS:
            summary = self.stats[name].summary()

            for stat_name, value in summary.items():
                result[f"burst_{name}_{stat_name}"] = value

        return result


def load_manifest():
    with SPLIT_FILE.open(encoding="utf-8") as f:
        manifest = json.load(f)

    flow_map = {}

    for item in manifest["flows"]:
        key = (item["session_id"], item["flow_id"])

        if key in flow_map:
            raise RuntimeError(f"Duplicate Flow in manifest: {key}")

        if item["application"] not in CLASSES:
            raise RuntimeError(f"Unexpected class: {item['application']}")

        if item["split"] not in SPLITS:
            raise RuntimeError(f"Unexpected split: {item['split']}")

        flow_map[key] = item

    return manifest, flow_map


def build_flow_dataset(flow_map):
    print("\n=== PASS 1: AGGREGATE BURSTS INTO FLOWS ===")

    accumulators = {}
    seen_keys = set()
    burst_rows = 0

    with CSV_FILE.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)

        required = {
            "session_id", "flow_id", "application", "batch_id",
            "direction", "start_ts", "end_ts",
            "packet_count", "total_bytes",
            "forward_bytes", "backward_bytes", "unknown_bytes",
            *BURST_FIELDS,
        }

        missing = required - set(reader.fieldnames or [])

        if missing:
            raise RuntimeError(
                f"Missing CSV columns: {sorted(missing)}"
            )

        for row in reader:
            key = (row["session_id"], row["flow_id"])

            if key not in flow_map:
                if row["application"] == "other-idle":
                    continue
                raise RuntimeError(f"Flow missing from manifest: {key}")

            meta = flow_map[key]

            if row["application"] != meta["application"]:
                raise RuntimeError(f"Application mismatch: {key}")

            if row["batch_id"] != meta["batch_id"]:
                raise RuntimeError(f"Batch mismatch: {key}")

            if key not in accumulators:
                accumulators[key] = FlowAccumulator()

            accumulators[key].add_burst(row)
            seen_keys.add(key)
            burst_rows += 1

    if seen_keys != set(flow_map):
        missing_flows = set(flow_map) - seen_keys
        extra_flows = seen_keys - set(flow_map)
        raise RuntimeError(
            f"Flow mismatch. Missing={len(missing_flows)}, "
            f"extra={len(extra_flows)}"
        )

    if len(accumulators) != len(flow_map):
        raise RuntimeError("Unexpected Flow accumulator count")

    print("Burst CSV rows:", burst_rows)
    print("Manifest Flows:", len(flow_map))
    print("Aggregated Flows:", len(accumulators))
    print("CSV/manifest consistency: PASS")

    rows = []

    for key, meta in flow_map.items():
        features = accumulators[key].features()

        rows.append({
            "session_id": key[0],
            "flow_id": key[1],
            "application": meta["application"],
            "batch_id": meta["batch_id"],
            "split": meta["split"],
            **features,
        })

    return rows


def save_flow_features(rows):
    path = OUT / "flow_features.csv"

    if not rows:
        raise RuntimeError("No Flow rows to save")

    fieldnames = list(rows[0].keys())

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print("Flow feature CSV:", path)
    print("Flow feature columns:", len(fieldnames) - 5)

    return path


def get_feature_names(rows):
    excluded = {
        "session_id",
        "flow_id",
        "application",
        "batch_id",
        "split",
    }

    return [name for name in rows[0] if name not in excluded]


def make_xy(rows, feature_names):
    x = []

    for row in rows:
        values = []

        for name in feature_names:
            value = row[name]

            if value is None or isinstance(value, float) and not math.isfinite(value):
                values.append(float("nan"))
            else:
                values.append(float(value))

        x.append(values)

    y = [row["application"] for row in rows]

    return x, y


def evaluate(model, split, rows, feature_names):
    x, y_true = make_xy(rows, feature_names)
    probabilities = model.predict_proba(Pool(x, feature_names=feature_names))

    model_classes = [str(value) for value in model.classes_]
    indices = probabilities.argmax(axis=1)
    y_pred = [model_classes[index] for index in indices]

    metrics = {
        "flow_count": len(rows),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(
            f1_score(
                y_true,
                y_pred,
                labels=CLASSES,
                average="macro",
                zero_division=0,
            )
        ),
        "balanced_accuracy": float(
            balanced_accuracy_score(y_true, y_pred)
        ),
        "classification_report": classification_report(
            y_true,
            y_pred,
            labels=CLASSES,
            output_dict=True,
            zero_division=0,
        ),
        "confusion_matrix": confusion_matrix(
            y_true,
            y_pred,
            labels=CLASSES,
        ).tolist(),
    }

    prediction_path = OUT / f"{split}_predictions.csv"

    with prediction_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "session_id", "flow_id", "batch_id",
            "true_application", "predicted_application",
        ])

        for row, prediction in zip(rows, y_pred):
            writer.writerow([
                row["session_id"],
                row["flow_id"],
                row["batch_id"],
                row["application"],
                prediction,
            ])

    print(f"\n=== {split.upper()} RESULTS ===")
    print("Flows:", metrics["flow_count"])
    print(f"Accuracy:          {metrics['accuracy']:.6f}")
    print(f"Macro F1:          {metrics['macro_f1']:.6f}")
    print(f"Balanced Accuracy: {metrics['balanced_accuracy']:.6f}")

    print("\nPer-class report:")
    print(classification_report(
        y_true,
        y_pred,
        labels=CLASSES,
        zero_division=0,
    ))

    print("Confusion matrix (true rows, predicted columns):")
    print(confusion_matrix(y_true, y_pred, labels=CLASSES))

    return metrics


def main():
    manifest, flow_map = load_manifest()

    print("Manifest Flows:", len(flow_map))
    print("Manifest split policy:")
    print(json.dumps(
        manifest["split_policy"],
        ensure_ascii=False,
        indent=2,
    ))

    rows = build_flow_dataset(flow_map)
    save_flow_features(rows)

    feature_names = get_feature_names(rows)

    print("\nFeature count:", len(feature_names))
    print("Features:")
    for name in feature_names:
        print(" ", name)

    split_rows = {
        split: [row for row in rows if row["split"] == split]
        for split in SPLITS
    }

    for split in SPLITS:
        counts = Counter(
            row["application"] for row in split_rows[split]
        )
        print(f"\n{split.upper()} Flow counts:", dict(counts))

        if not split_rows[split]:
            raise RuntimeError(f"Empty split: {split}")

    train_rows = split_rows["train"]
    validation_rows = split_rows["validation"]

    train_counts = Counter(
        row["application"] for row in train_rows
    )

    if set(train_counts) != set(CLASSES):
        raise RuntimeError("Training data does not contain all classes")

    total_train = len(train_rows)

    class_weights = {
        app: total_train / (len(CLASSES) * train_counts[app])
        for app in CLASSES
    }

    x_train, y_train = make_xy(train_rows, feature_names)
    x_val, y_val = make_xy(validation_rows, feature_names)

    train_weights = [
        class_weights[label] for label in y_train
    ]

    train_pool = Pool(
        x_train,
        label=y_train,
        weight=train_weights,
        feature_names=feature_names,
    )

    validation_pool = Pool(
        x_val,
        label=y_val,
        feature_names=feature_names,
    )

    model = CatBoostClassifier(
        loss_function="MultiClass",
        eval_metric="MultiClass",
        iterations=ITERATIONS,
        learning_rate=0.05,
        depth=8,
        random_seed=SEED,
        thread_count=THREADS,
        l2_leaf_reg=5.0,
        random_strength=1.0,
        verbose=100,
        allow_writing_files=False,
    )

    print("\n=== TRAIN CATBOOST FLOW V2 ===")
    model.fit(
        train_pool,
        eval_set=validation_pool,
        early_stopping_rounds=EARLY_STOPPING,
        use_best_model=True,
    )

    model_path = OUT / "catboost_flow_v2.cbm"
    model.save_model(str(model_path))

    print("\nModel saved:", model_path)
    print("Best iteration:", model.get_best_iteration())

    results = {
        "model": "CatBoost Flow-Level V2",
        "dataset": manifest["dataset"],
        "split_policy": manifest["split_policy"],
        "feature_count": len(feature_names),
        "features": feature_names,
        "train_class_weights": class_weights,
        "best_iteration": model.get_best_iteration(),
        "model_path": str(model_path),
        "results": {},
    }

    for split in SPLITS:
        results["results"][split] = evaluate(
            model,
            split,
            split_rows[split],
            feature_names,
        )

    report_path = OUT / "metrics.json"

    with report_path.open("w", encoding="utf-8") as f:
        json.dump(
            results,
            f,
            ensure_ascii=False,
            indent=2,
            allow_nan=True,
        )

    print("\nMetrics saved:", report_path)

    print("\n=== V1 BASELINE REFERENCE ===")
    print("Validation Flow Macro F1: 0.4909")
    print("Validation Flow Accuracy: 0.5094")
    print("Test Flow Macro F1:       0.2480")
    print("Test Flow Accuracy:       0.2716")

    print("\nV2 completed. Compare Validation first.")
    print("Batch2 Test is a cross-batch diagnostic,")
    print("not an untouched independent generalization test.")


if __name__ == "__main__":
    main()
