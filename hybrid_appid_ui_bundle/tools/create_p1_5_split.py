import csv
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

BASE = Path("outputs/p1_5_full_dataset_v1")
JSONL = BASE / "burst_sequences.jsonl"
CSV_FILE = BASE / "burst_statistics.csv"
OUTPUT = BASE / "split_manifest.json"

SEED = 42
VAL_RATIO = 0.20

# 1. Đọc danh sách Flow từ JSONL
flows = {}
with JSONL.open(encoding="utf-8") as f:
    for line in f:
        obj = json.loads(line)
        key = (obj["session_id"], obj["flow_id"])

        if key in flows:
            raise RuntimeError(f"Duplicate Flow in JSONL: {key}")

        flows[key] = {
            "session_id": obj["session_id"],
            "flow_id": obj["flow_id"],
            "application": obj["application"],
            "batch_id": obj["batch_id"],
        }

print("JSONL flows:", len(flows))

# 2. Kiểm tra CSV có cùng danh sách Flow và nhãn
csv_keys = set()

with CSV_FILE.open(encoding="utf-8", newline="") as f:
    reader = csv.DictReader(f)

    for row in reader:
        key = (row["session_id"], row["flow_id"])

        if key not in flows:
            raise RuntimeError(f"CSV Flow missing in JSONL: {key}")

        meta = flows[key]

        if row["application"] != meta["application"]:
            raise RuntimeError(f"Application mismatch: {key}")

        if row["batch_id"] != meta["batch_id"]:
            raise RuntimeError(f"Batch mismatch: {key}")

        csv_keys.add(key)

if csv_keys != set(flows):
    missing = set(flows) - csv_keys
    raise RuntimeError(f"Flows missing from CSV: {len(missing)}")

print("CSV/JSONL Flow consistency: PASS")

# 3. Chia Batch 1 theo từng lớp ứng dụng
by_class = defaultdict(list)

for key, meta in flows.items():
    if meta["batch_id"] == "batch1":
        by_class[meta["application"]].append(key)
    elif meta["batch_id"] != "batch2":
        raise RuntimeError(f"Unexpected batch: {meta['batch_id']}")

rng = random.Random(SEED)
assignments = {}

for app, keys in sorted(by_class.items()):
    keys = sorted(keys)
    rng.shuffle(keys)

    if len(keys) < 2:
        raise RuntimeError(f"Not enough Batch 1 flows for {app}")

    n_val = max(1, round(len(keys) * VAL_RATIO))
    val_keys = set(keys[:n_val])

    for key in keys:
        assignments[key] = "validation" if key in val_keys else "train"

# 4. Toàn bộ Batch 2 là test
for key, meta in flows.items():
    if meta["batch_id"] == "batch2":
        assignments[key] = "test"

if len(assignments) != len(flows):
    raise RuntimeError("Some flows were not assigned")

# 5. Thống kê số Flow theo tập và lớp
flow_counts = Counter()
class_counts = defaultdict(Counter)

for key, split in assignments.items():
    app = flows[key]["application"]
    flow_counts[split] += 1
    class_counts[app][split] += 1

if set(class_counts) != {
    "chatgpt", "facebook", "other-web",
    "spotify", "tiktok", "youtube"
}:
    raise RuntimeError("Unexpected application classes")

for app in sorted(class_counts):
    if class_counts[app]["test"] == 0:
        raise RuntimeError(f"No test flows for {app}")
    if class_counts[app]["train"] == 0:
        raise RuntimeError(f"No train flows for {app}")
    if class_counts[app]["validation"] == 0:
        raise RuntimeError(f"No validation flows for {app}")

# 6. Đếm số Burst CSV thuộc từng tập
burst_counts = Counter()

with CSV_FILE.open(encoding="utf-8", newline="") as f:
    for row in csv.DictReader(f):
        key = (row["session_id"], row["flow_id"])
        burst_counts[assignments[key]] += 1

# 7. Xuất manifest dùng chung cho CatBoost và CNN
flow_records = []

for key in sorted(flows):
    meta = flows[key].copy()
    meta["split"] = assignments[key]
    flow_records.append(meta)

manifest = {
    "dataset": "P1.5 full dataset v1",
    "split_seed": SEED,
    "split_policy": {
        "train": "80% of Batch 1, stratified by application and grouped by Flow",
        "validation": "20% of Batch 1, stratified by application and grouped by Flow",
        "test": "All Batch 2 Flows",
        "flow_key": ["session_id", "flow_id"],
        "same_assignments_for": ["CatBoost", "1D-CNN"],
    },
    "total_flows": len(flows),
    "flow_counts": dict(flow_counts),
    "burst_counts": dict(burst_counts),
    "class_counts": {
        app: dict(counts)
        for app, counts in sorted(class_counts.items())
    },
    "flows": flow_records,
}

OUTPUT.write_text(
    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
)

print("\n=== SPLIT RESULT ===")
print("Total flows:", len(flows))

for split in ("train", "validation", "test"):
    print(f"{split:12s} Flows: {flow_counts[split]:6d} | Bursts: {burst_counts[split]:9d}")

print("\n=== FLOWS BY APPLICATION ===")
for app in sorted(class_counts):
    c = class_counts[app]
    print(
        f"{app:12s} "
        f"train={c['train']:5d} "
        f"validation={c['validation']:5d} "
        f"test={c['test']:5d}"
    )

print("\nSaved:", OUTPUT)
print("STATUS: PASS")
