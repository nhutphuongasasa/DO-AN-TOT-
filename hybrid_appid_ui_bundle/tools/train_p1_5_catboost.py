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

BASE = Path("outputs/p1_5_full_dataset_v1")
OUT = BASE / "catboost"
PREP = OUT / "prepared"

CSV_FILE = BASE / "burst_statistics.csv"
SPLIT_FILE = BASE / "split_manifest.json"

SEED = 42
THREADS = 4
ITERATIONS = 2000
EARLY_STOPPING = 150

CLASSES = [
    "chatgpt",
    "facebook",
    "other-web",
    "spotify",
    "tiktok",
    "youtube",
]

# Chỉ sử dụng các đặc trưng có ý nghĩa về hành vi Burst.
NUM_FEATURES = [
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
    "forward_packet_count",
    "backward_packet_count",
    "unknown_packet_count",
    "forward_bytes",
    "backward_bytes",
    "unknown_bytes",
    "inter_burst_gap_seconds",
]

CAT_FEATURES = ["direction"]
FEATURES = NUM_FEATURES + CAT_FEATURES

SPLITS = ["train", "validation", "test"]


def load_manifest():
    with SPLIT_FILE.open(encoding="utf-8") as f:
        manifest = json.load(f)

    flow_map = {}

    for item in manifest["flows"]:
        key = (item["session_id"], item["flow_id"])

        if key in flow_map:
            raise RuntimeError(f"Duplicate Flow in split manifest: {key}")

        if item["application"] not in CLASSES:
            raise RuntimeError(f"Unexpected class: {item['application']}")

        if item["split"] not in SPLITS:
            raise RuntimeError(f"Unexpected split: {item['split']}")

        flow_map[key] = item

    return manifest, flow_map


def number(value):
    if value is None or value.strip() == "":
        return "nan"

    try:
        result = float(value)
    except ValueError:
        return "nan"

    if not math.isfinite(result):
        return "nan"

    return repr(result)


def write_column_description():
    path = PREP / "column_description.tsv"

    with path.open("w", encoding="utf-8") as f:
        f.write("0\tLabel\tapplication\n")
        f.write("1\tWeight\tflow_balanced_weight\n")

        for i, name in enumerate(FEATURES, start=2):
            kind = "Categ" if name in CAT_FEATURES else "Num"
            f.write(f"{i}\t{kind}\t{name}\n")

    return path


def prepare_data(flow_map):
    PREP.mkdir(parents=True, exist_ok=True)

    burst_counts = Counter()
    csv_keys = set()
    csv_rows = 0

    print("\n=== PASS 1: CHECK CSV AND COUNT BURSTS ===")

    with CSV_FILE.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)

        required = {
            "session_id", "flow_id", "application",
            "batch_id", *FEATURES
        }

        missing = required - set(reader.fieldnames or [])

        if missing:
            raise RuntimeError(f"Missing CSV columns: {sorted(missing)}")

        for row in reader:
            key = (row["session_id"], row["flow_id"])

            if key not in flow_map:
                raise RuntimeError(f"CSV Flow missing from manifest: {key}")

            meta = flow_map[key]

            if row["application"] != meta["application"]:
                raise RuntimeError(f"Application mismatch: {key}")

            if row["batch_id"] != meta["batch_id"]:
                raise RuntimeError(f"Batch mismatch: {key}")

            burst_counts[key] += 1
            csv_keys.add(key)
            csv_rows += 1

    if csv_keys != set(flow_map):
        raise RuntimeError(
            f"Flow mismatch: CSV={len(csv_keys)}, manifest={len(flow_map)}"
        )

    print("CSV rows:", csv_rows)
    print("CSV/manifest Flow consistency: PASS")

    for key in flow_map:
        if burst_counts[key] == 0:
            raise RuntimeError(f"Flow has no Burst rows: {key}")

    train_class_flows = Counter(
        item["application"]
        for item in flow_map.values()
        if item["split"] == "train"
    )

    total_train_flows = sum(train_class_flows.values())

    if set(train_class_flows) != set(CLASSES):
        raise RuntimeError("Training set does not contain all six classes")

    # Mỗi Flow có tổng trọng số bằng nhau trong cùng một lớp.
    # Đồng thời cân bằng đóng góp giữa các lớp.
    class_weights = {
        app: total_train_flows / (len(CLASSES) * train_class_flows[app])
        for app in CLASSES
    }

    data_files = {}
    key_files = {}
    data_writers = {}
    key_writers = {}
    handles = []

    try:
        for split in SPLITS:
            data_path = PREP / f"{split}.tsv"
            keys_path = PREP / f"{split}.keys.tsv"

            data_file = data_path.open("w", encoding="utf-8", newline="")
            keys_file = keys_path.open("w", encoding="utf-8", newline="")
            handles.extend([data_file, keys_file])

            data_files[split] = data_path
            key_files[split] = keys_path

            data_writers[split] = csv.writer(
                data_file, delimiter="\t", lineterminator="\n"
            )
            key_writers[split] = csv.writer(
                keys_file, delimiter="\t", lineterminator="\n"
            )

        print("\n=== PASS 2: PREPARE CATBOOST DATA ===")

        with CSV_FILE.open(encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)

            for row in reader:
                key = (row["session_id"], row["flow_id"])
                meta = flow_map[key]

                split = meta["split"]
                app = meta["application"]

                weight = (
                    class_weights[app] / burst_counts[key]
                )

                values = [
                    app,
                    repr(weight),
                ]

                for name in NUM_FEATURES:
                    values.append(number(row[name]))

                for name in CAT_FEATURES:
                    value = row[name].strip()
                    values.append(value if value else "unknown")

                data_writers[split].writerow(values)
                key_writers[split].writerow(key)

    finally:
        for handle in handles:
            handle.close()

    cd_path = write_column_description()

    print("Prepared data:")
    for split in SPLITS:
        print(f"  {split}: {data_files[split]}")
        print(f"  keys:  {key_files[split]}")

    return data_files, key_files, cd_path, burst_counts, class_weights


def make_pool(path, cd_path):
    return Pool(
        data=str(path),
        column_description=str(cd_path),
        delimiter="\t",
        has_header=False,
    )


def evaluate_split(model, split, data_path, keys_path, flow_map):
    print(f"\n=== EVALUATION: {split.upper()} ===")

    pool = make_pool(data_path, PREP / "column_description.tsv")
    probabilities = model.predict_proba(pool)

    classes = [str(x) for x in model.classes_]
    predicted_indices = probabilities.argmax(axis=1)
    burst_predictions = [classes[i] for i in predicted_indices]

    burst_truth = []
    with data_path.open(encoding="utf-8") as f:
        for line in f:
            burst_truth.append(line.split("\t", 1)[0])

    if len(burst_truth) != len(probabilities):
        raise RuntimeError("Prediction/data row count mismatch")

    burst_metrics = {
        "accuracy": float(accuracy_score(burst_truth, burst_predictions)),
        "macro_f1": float(
            f1_score(burst_truth, burst_predictions, average="macro")
        ),
        "balanced_accuracy": float(
            balanced_accuracy_score(burst_truth, burst_predictions)
        ),
        "classification_report": classification_report(
            burst_truth,
            burst_predictions,
            labels=classes,
            output_dict=True,
            zero_division=0,
        ),
    }

    # Tổng hợp xác suất Burst thành xác suất Flow bằng trung bình.
    aggregate = {}

    with keys_path.open(encoding="utf-8", newline="") as f:
        reader = csv.reader(f, delimiter="\t")

        for key_parts, probs in zip(reader, probabilities):
            key = tuple(key_parts)

            if len(key) != 2:
                raise RuntimeError("Invalid Flow key file")

            meta = flow_map[key]

            if key not in aggregate:
                aggregate[key] = {
                    "application": meta["application"],
                    "sum": [0.0] * len(classes),
                    "count": 0,
                }

            entry = aggregate[key]
            entry["count"] += 1

            for i, value in enumerate(probs):
                entry["sum"][i] += float(value)

    flow_truth = []
    flow_predictions = []
    flow_records = []

    for key in sorted(aggregate):
        entry = aggregate[key]

        mean_probs = [
            value / entry["count"] for value in entry["sum"]
        ]

        pred_index = max(
            range(len(classes)),
            key=lambda i: mean_probs[i],
        )

        truth = entry["application"]
        prediction = classes[pred_index]

        flow_truth.append(truth)
        flow_predictions.append(prediction)

        record = {
            "session_id": key[0],
            "flow_id": key[1],
            "true_application": truth,
            "predicted_application": prediction,
            "burst_count": entry["count"],
        }

        for i, app in enumerate(classes):
            record[f"prob_{app}"] = mean_probs[i]

        flow_records.append(record)

    flow_metrics = {
        "accuracy": float(accuracy_score(flow_truth, flow_predictions)),
        "macro_f1": float(
            f1_score(flow_truth, flow_predictions, average="macro")
        ),
        "balanced_accuracy": float(
            balanced_accuracy_score(flow_truth, flow_predictions)
        ),
        "classification_report": classification_report(
            flow_truth,
            flow_predictions,
            labels=classes,
            output_dict=True,
            zero_division=0,
        ),
    }

    # Lưu confusion matrix ở cả hai mức.
    for level, truth, predictions in [
        ("burst", burst_truth, burst_predictions),
        ("flow", flow_truth, flow_predictions),
    ]:
        matrix = confusion_matrix(
            truth, predictions, labels=classes
        )

        with (OUT / f"{split}_{level}_confusion_matrix.csv").open(
            "w", encoding="utf-8", newline=""
        ) as f:
            writer = csv.writer(f)
            writer.writerow(["true/predicted"] + classes)

            for app, values in zip(classes, matrix):
                writer.writerow([app] + values.tolist())

    with (OUT / f"{split}_flow_predictions.csv").open(
        "w", encoding="utf-8", newline=""
    ) as f:
        writer = csv.DictWriter(f, fieldnames=list(flow_records[0].keys()))
        writer.writeheader()
        writer.writerows(flow_records)

    metrics = {
        "split": split,
        "burst_level": burst_metrics,
        "flow_level": flow_metrics,
        "flow_count": len(flow_truth),
        "burst_count": len(burst_truth),
    }

    with (OUT / f"{split}_metrics.json").open(
        "w", encoding="utf-8"
    ) as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)

    print("Burst count:", len(burst_truth))
    print("Flow count:", len(flow_truth))
    print("Burst Macro F1:", round(burst_metrics["macro_f1"], 4))
    print("Flow Macro F1:", round(flow_metrics["macro_f1"], 4))
    print("Flow Accuracy:", round(flow_metrics["accuracy"], 4))
    print("Flow Balanced Accuracy:", round(
        flow_metrics["balanced_accuracy"], 4
    ))

    return metrics


def main():
    OUT.mkdir(parents=True, exist_ok=True)

    print("=== P1.5 CATBOOST TRAINING ===")

    manifest, flow_map = load_manifest()
    print("Manifest flows:", len(flow_map))

    data_files, key_files, cd_path, burst_counts, class_weights = (
        prepare_data(flow_map)
    )

    print("\nClass weights:", class_weights)

    train_pool = make_pool(data_files["train"], cd_path)
    val_pool = make_pool(data_files["validation"], cd_path)

    model = CatBoostClassifier(
        iterations=ITERATIONS,
        depth=8,
        learning_rate=0.05,
        loss_function="MultiClass",
        eval_metric="MultiClass",
        l2_leaf_reg=5,
        random_seed=SEED,
        thread_count=THREADS,
        verbose=100,
        allow_writing_files=True,
        train_dir=str(OUT / "catboost_info"),
    )

    print("\n=== TRAINING ===")

    model.fit(
        train_pool,
        eval_set=val_pool,
        early_stopping_rounds=EARLY_STOPPING,
        use_best_model=True,
        verbose=100,
    )

    model_path = OUT / "catboost_p1_5.cbm"
    model.save_model(str(model_path))

    print("\nBest iteration:", model.get_best_iteration())
    print("Model saved:", model_path)

    # Validation dùng để kiểm tra/chọn mô hình.
    validation_metrics = evaluate_split(
        model,
        "validation",
        data_files["validation"],
        key_files["validation"],
        flow_map,
    )

    # Test Batch 2 chỉ được đánh giá sau khi huấn luyện hoàn tất.
    test_metrics = evaluate_split(
        model,
        "test",
        data_files["test"],
        key_files["test"],
        flow_map,
    )

    feature_importance = model.get_feature_importance()

    with (OUT / "feature_importance.csv").open(
        "w", encoding="utf-8", newline=""
    ) as f:
        writer = csv.writer(f)
        writer.writerow(["feature", "importance"])

        for name, value in sorted(
            zip(FEATURES, feature_importance),
            key=lambda x: x[1],
            reverse=True,
        ):
            writer.writerow([name, float(value)])

    summary = {
        "dataset": "P1.5 full dataset v1",
        "model": "CatBoostClassifier",
        "classes": CLASSES,
        "features": FEATURES,
        "excluded_fields": [
            "schema_version",
            "session_id",
            "flow_id",
            "burst_index",
            "start_ts",
            "end_ts",
            "application_as_feature",
            "batch_id",
        ],
        "split_manifest": str(SPLIT_FILE),
        "train_flows": sum(
            1 for x in flow_map.values() if x["split"] == "train"
        ),
        "validation_flows": sum(
            1 for x in flow_map.values() if x["split"] == "validation"
        ),
        "test_flows": sum(
            1 for x in flow_map.values() if x["split"] == "test"
        ),
        "best_iteration": model.get_best_iteration(),
        "validation": validation_metrics,
        "test": test_metrics,
    }

    with (OUT / "training_summary.json").open(
        "w", encoding="utf-8"
    ) as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print("\n=== CATBOOST COMPLETE ===")
    print("Model:", model_path)
    print("Results:", OUT)
    print("Validation Flow Macro F1:",
          round(validation_metrics["flow_level"]["macro_f1"], 4))
    print("Test Flow Macro F1:",
          round(test_metrics["flow_level"]["macro_f1"], 4))


if __name__ == "__main__":
    main()
