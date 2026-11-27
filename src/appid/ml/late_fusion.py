"""Validated probability-level late fusion for CatBoost Flow V2 and CNN1D."""
from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from pathlib import Path


def _validate_alpha(alpha: float) -> float:
    try:
        value = float(alpha)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("alpha_catboost must be a finite number in [0, 1]") from exc
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError("alpha_catboost must be a finite number in [0, 1]")
    return value


def _validated_probabilities(values: Mapping[str, float], name: str) -> dict[str, float]:
    if not isinstance(values, Mapping) or not values:
        raise ValueError(f"{name} probabilities must be a non-empty mapping")
    result: dict[str, float] = {}
    for label, raw in values.items():
        try:
            probability = float(raw)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"{name} probability for {label!r} is not numeric") from exc
        if not math.isfinite(probability) or probability < 0.0:
            raise ValueError(f"{name} probability for {label!r} must be finite and >= 0")
        result[str(label)] = probability
    total = sum(result.values())
    if total <= 0.0:
        raise ValueError(f"{name} probabilities must have a positive sum")
    return {label: value / total for label, value in result.items()}


def weighted_late_fusion(
    catboost_probabilities: Mapping[str, float],
    cnn_probabilities: Mapping[str, float],
    *,
    alpha_catboost: float = 0.5,
) -> dict[str, float]:
    """Fuse aligned class probabilities; alpha is the CatBoost weight."""
    alpha = _validate_alpha(alpha_catboost)
    cat = _validated_probabilities(catboost_probabilities, "CatBoost")
    cnn = _validated_probabilities(cnn_probabilities, "CNN1D")
    if set(cat) != set(cnn):
        raise ValueError("CatBoost and CNN1D probabilities must have identical classes")

    fused = {
        label: alpha * cat[label] + (1.0 - alpha) * cnn[label]
        for label in cat
    }
    total = sum(fused.values())
    if not math.isfinite(total) or total <= 0.0:
        raise ValueError("fused probabilities have an invalid sum")
    return {label: value / total for label, value in fused.items()}


def load_fusion_alpha(metrics_path: str | Path, classes: Sequence[str]) -> float:
    """Load validation-selected CatBoost weight and verify its class ordering."""
    path = Path(metrics_path)
    if not path.is_file():
        raise FileNotFoundError(f"Late-fusion metrics not found: {path}")
    try:
        metrics = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read late-fusion metrics: {path}") from exc

    metric_classes = metrics.get("classes")
    if not isinstance(metric_classes, list) or list(metric_classes) != list(classes):
        raise ValueError(
            "Late-fusion metrics class order must exactly match CatBoost classes"
        )
    if "best_alpha_catboost" not in metrics:
        raise ValueError("Late-fusion metrics missing best_alpha_catboost")
    return _validate_alpha(metrics["best_alpha_catboost"])
