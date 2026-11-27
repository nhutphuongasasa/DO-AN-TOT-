# P1.5 CNN1D + Late Fusion runtime integration

## Changes

- Added `src/appid/ml/cnn1d_inference.py`.
  - Mirrors the training/export feature schema and preprocessing.
  - Uses the checkpoint's saved `train_mean` and `train_std`.
  - Recreates the trained Conv1D/BatchNorm/Pooling/Classifier architecture.
  - Accepts both JSON-like burst mappings and runtime `BurstSequenceItem` objects.
- Added `src/appid/ml/late_fusion.py`.
  - Validates and combines CatBoost/CNN1D class probabilities.
  - Loads the validation-selected CatBoost alpha from `metrics.json` and checks class order.
- Updated `pyproject.toml` so pytest can import project-root helper scripts as well as `src` modules.
- Added `scripts/__init__.py` so the existing local `scripts/` directory is importable as a package.
- Extended CNN inference tests for runtime sequence objects and metrics class-order validation.

## Validation performed against the supplied archive

- `python -m compileall -q src/appid scripts`: passed.
- `pytest -q tests/unit --ignore=tests/unit/capture/test_tcp_acceptance.py tests/integration/test_pcap_burst_pipeline.py`: **193 passed, 2 skipped**.
- Loaded the supplied CatBoost and CNN1D checkpoints and ran inference.
- Instantiated `PacketProcessor` with both real checkpoints and the supplied late-fusion metrics; one synthetic Burst reached `CATBOOST_CNN1D_WEIGHTED_LATE_FUSION`, both model counters incremented, and fused probabilities summed to 1.0.

## Validation limitation

The uploaded archive did not contain the project-root `scripts/` directory (including the existing `verify_tcp_appid_acceptance.py`) or `docs/`. Those local files are not overwritten by this overlay. Consequently, `tests/unit/capture/test_tcp_acceptance.py` could not be executed against the uploaded archive. The original local `scripts/` directory should remain in place when this overlay is extracted.

No live-NIC capture was run.
