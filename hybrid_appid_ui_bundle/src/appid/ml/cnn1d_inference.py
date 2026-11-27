"""Runtime inference for the P1.5 Burst-sequence CNN1D checkpoint.

The feature encoding, uniform sequence sampling and train-only normalization in
this module intentionally mirror ``tools/train_p1_5_cnn1d.py`` and
``tools/export_p1_5_cnn1d_predictions.py``.
"""
from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

CLASSES = ["chatgpt", "facebook", "other-web", "spotify", "tiktok", "youtube"]
FEATURE_NAMES = [
    "direction",
    "log_duration_ms",
    "log_packet_count",
    "log_total_bytes",
    "log_gap_ms",
    "gap_missing",
    "log_packet_length_mean",
    "log_packet_length_min",
    "log_packet_length_max",
]
MAX_LEN = 256


def _get(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return number if math.isfinite(number) else default


def _direction_name(value: Any) -> str:
    # Direction is a str Enum in the runtime domain model.
    value = getattr(value, "value", value)
    return str(value if value is not None else "UNKNOWN").upper()


def burst_to_features(burst: Any) -> list[float]:
    """Encode one mapping or BurstSequenceItem exactly like the trainer."""
    direction_name = _direction_name(_get(burst, "direction", "UNKNOWN"))
    direction = 1.0 if direction_name == "FORWARD" else (
        -1.0 if direction_name == "BACKWARD" else 0.0
    )

    duration = max(0.0, _safe_float(_get(burst, "duration_seconds")))
    packet_count = max(0.0, _safe_float(_get(burst, "packet_count")))
    total_bytes = max(0.0, _safe_float(_get(burst, "total_bytes")))

    gap_value = _get(burst, "inter_burst_gap_seconds")
    gap_missing = 1.0 if gap_value is None else 0.0
    gap = max(0.0, _safe_float(gap_value))

    lengths = _get(burst, "packet_lengths")
    if lengths is None:
        packets = _get(burst, "packets", ()) or ()
        lengths = [_get(packet, "packet_length", 0) for packet in packets]
    valid_lengths = []
    for item in lengths or ():
        number = _safe_float(item, -1.0)
        if number >= 0:
            valid_lengths.append(number)

    if valid_lengths:
        length_mean = float(np.mean(valid_lengths))
        length_min = float(min(valid_lengths))
        length_max = float(max(valid_lengths))
    else:
        length_mean = total_bytes / packet_count if packet_count > 0 else 0.0
        length_min = 0.0
        length_max = 0.0

    return [
        direction,
        math.log1p(duration * 1000.0),
        math.log1p(packet_count),
        math.log1p(total_bytes),
        math.log1p(gap * 1000.0),
        gap_missing,
        math.log1p(max(0.0, length_mean)),
        math.log1p(max(0.0, length_min)),
        math.log1p(max(0.0, length_max)),
    ]


def encode_burst_sequence(bursts: Sequence[Any]) -> np.ndarray:
    """Return the trainer-compatible float32 array with shape ``(9, 256)``."""
    if bursts is None or len(bursts) == 0:
        raise ValueError("at least one burst is required")

    # Same uniform sampling (including repetition for short sequences) as train/export.
    indices = np.linspace(0, len(bursts) - 1, num=MAX_LEN).round().astype(np.int64)
    encoded = np.empty((MAX_LEN, len(FEATURE_NAMES)), dtype=np.float32)
    for row, index in enumerate(indices):
        encoded[row] = burst_to_features(bursts[int(index)])
    return np.transpose(encoded, (1, 0)).copy()


class _CNN1D:
    """Factory for the exact training architecture without eager torch import."""

    @staticmethod
    def build(torch: Any) -> Any:
        nn = torch.nn

        class CNN1DModel(nn.Module):
            def __init__(self) -> None:
                super().__init__()
                self.features = nn.Sequential(
                    nn.Conv1d(len(FEATURE_NAMES), 64, kernel_size=5, padding=2),
                    nn.BatchNorm1d(64),
                    nn.ReLU(),
                    nn.MaxPool1d(2),
                    nn.Conv1d(64, 128, kernel_size=5, padding=2),
                    nn.BatchNorm1d(128),
                    nn.ReLU(),
                    nn.MaxPool1d(2),
                    nn.Conv1d(128, 128, kernel_size=3, padding=1),
                    nn.BatchNorm1d(128),
                    nn.ReLU(),
                )
                self.pool = nn.AdaptiveAvgPool1d(1)
                self.classifier = nn.Sequential(
                    nn.Flatten(),
                    nn.Linear(128, 64),
                    nn.ReLU(),
                    nn.Dropout(0.4),
                    nn.Linear(64, len(CLASSES)),
                )

            def forward(self, x: Any) -> Any:
                return self.classifier(self.pool(self.features(x)))

        return CNN1DModel()


class CNN1DInference:
    """Load one trained checkpoint and predict application probabilities."""

    def __init__(self, checkpoint_path: str | Path):
        try:
            import torch
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError('PyTorch is required. Install with: pip install -e ".[ml]"') from exc

        self.checkpoint_path = Path(checkpoint_path)
        if not self.checkpoint_path.is_file():
            raise FileNotFoundError(f"CNN1D checkpoint not found: {self.checkpoint_path}")

        try:
            checkpoint = torch.load(
                self.checkpoint_path, map_location="cpu", weights_only=True
            )
        except TypeError:  # PyTorch versions before weights_only was introduced.
            checkpoint = torch.load(self.checkpoint_path, map_location="cpu")

        required = {
            "model_state_dict", "classes", "feature_names", "max_len",
            "train_mean", "train_std",
        }
        missing = sorted(required - set(checkpoint))
        if missing:
            raise ValueError(f"CNN1D checkpoint is missing fields: {missing}")
        if list(checkpoint["classes"]) != CLASSES:
            raise ValueError("CNN1D checkpoint class order differs from runtime schema")
        if list(checkpoint["feature_names"]) != FEATURE_NAMES:
            raise ValueError("CNN1D checkpoint feature names differ from runtime schema")
        if int(checkpoint["max_len"]) != MAX_LEN:
            raise ValueError(f"CNN1D checkpoint max_len must be {MAX_LEN}")

        self.train_mean = np.asarray(checkpoint["train_mean"], dtype=np.float32)
        self.train_std = np.asarray(checkpoint["train_std"], dtype=np.float32)
        if self.train_mean.shape != (len(FEATURE_NAMES),):
            raise ValueError("CNN1D checkpoint train_mean has an invalid shape")
        if self.train_std.shape != (len(FEATURE_NAMES),):
            raise ValueError("CNN1D checkpoint train_std has an invalid shape")
        if not np.isfinite(self.train_mean).all() or not np.isfinite(self.train_std).all():
            raise ValueError("CNN1D checkpoint normalization contains non-finite values")
        if np.any(self.train_std <= 0):
            raise ValueError("CNN1D checkpoint train_std must be positive")

        self.model = _CNN1D.build(torch)
        self.model.load_state_dict(checkpoint["model_state_dict"], strict=True)
        self.model.eval()
        self.classes = list(CLASSES)
        self.feature_names = list(FEATURE_NAMES)
        self.model_name = self.checkpoint_path.name
        self._torch = torch

    def predict(self, bursts: Sequence[Any]) -> dict[str, Any]:
        encoded = encode_burst_sequence(bursts)
        normalized = (encoded.T - self.train_mean) / self.train_std
        tensor_array = np.transpose(normalized.astype(np.float32), (1, 0)).copy()
        tensor = self._torch.from_numpy(tensor_array).unsqueeze(0)

        with self._torch.no_grad():
            logits = self.model(tensor)
            probabilities = self._torch.softmax(logits, dim=1)[0].cpu().numpy()

        if probabilities.shape != (len(self.classes),) or not np.isfinite(probabilities).all():
            raise RuntimeError("CNN1D produced invalid probabilities")
        total = float(probabilities.sum())
        if total <= 0:
            raise RuntimeError("CNN1D produced a zero probability sum")
        probabilities = probabilities / total
        probability_map = {
            name: float(probability)
            for name, probability in zip(self.classes, probabilities)
        }
        application = max(probability_map, key=probability_map.get)
        return {
            "application": application,
            "confidence": probability_map[application],
            "probabilities": probability_map,
            "model": self.model_name,
            "feature_count": len(FEATURE_NAMES),
            "tensor_shape": [1, len(FEATURE_NAMES), MAX_LEN],
        }
