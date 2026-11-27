import shutil
from pathlib import Path

OLD = 'outputs/p1_5_full_dataset_v1'
NEW = 'outputs/p1_5_full_dataset_wirelen_v2'

patches = {
    "tools/train_p1_5_catboost_flow_v2.py": [
        (
'''            if key not in flow_map:
                raise RuntimeError(f"Flow missing from manifest: {key}")
''',
'''            if key not in flow_map:
                if row["application"] == "other-idle":
                    continue
                raise RuntimeError(f"Flow missing from manifest: {key}")
'''
        )
    ],
    "tools/train_p1_5_cnn1d.py": [
        (
'''        if key not in split_map:
            raise RuntimeError(
                f"Flow not found in manifest at line {line_number}: {key}"
            )
''',
'''        if key not in split_map:
            if obj["application"] == "other-idle":
                continue
            raise RuntimeError(
                f"Flow not found in manifest at line {line_number}: {key}"
            )
'''
        )
    ],
    "tools/export_p1_5_cnn1d_predictions.py": [
        (
'''        if key not in manifest_map:
            raise RuntimeError(
                f"Sequence missing in manifest: {key}"
            )
''',
'''        if key not in manifest_map:
            if obj["application"] == "other-idle":
                continue
            raise RuntimeError(
                f"Sequence missing in manifest: {key}"
            )
'''
        )
    ],
    "tools/evaluate_p1_5_late_fusion.py": [],
}

# Validate every expected source fragment before changing anything.
for filename, replacements in patches.items():
    path = Path(filename)
    if not path.exists():
        raise FileNotFoundError(path)

    source = path.read_text(encoding="utf-8")

    if source.count(f'Path("{OLD}")') != 1:
        raise RuntimeError(
            f"Unexpected BASE declaration in {filename}"
        )

    for old, new in replacements:
        if source.count(old) != 1:
            raise RuntimeError(
                f"Expected exactly one patch location in {filename}"
            )

# Prepare the new dataset manifest.
old_manifest = Path(OLD) / "split_manifest.json"
new_base = Path(NEW)
new_manifest = new_base / "split_manifest.json"

if not old_manifest.exists():
    raise FileNotFoundError(old_manifest)

new_base.mkdir(parents=True, exist_ok=True)

if new_manifest.exists():
    if new_manifest.read_bytes() != old_manifest.read_bytes():
        raise RuntimeError(
            "A different v2 split_manifest.json already exists. "
            "Refusing to overwrite it."
        )
else:
    shutil.copy2(old_manifest, new_manifest)

# Back up and patch scripts.
for filename, replacements in patches.items():
    path = Path(filename)
    source = path.read_text(encoding="utf-8")

    backup = path.with_name(path.name + ".bak_wirelen_v2")
    if backup.exists():
        raise RuntimeError(
            f"Backup already exists: {backup}. Refusing to overwrite."
        )

    shutil.copy2(path, backup)

    source = source.replace(
        f'Path("{OLD}")',
        f'Path("{NEW}")',
        1,
    )

    for old, new in replacements:
        source = source.replace(old, new, 1)

    path.write_text(source, encoding="utf-8")

print("PATCH SUCCESS")
print("Dataset:", NEW)
print("Manifest:", new_manifest)
print("Original scripts backed up with .bak_wirelen_v2")
print("other-idle is excluded; unexpected missing flows still raise errors.")
