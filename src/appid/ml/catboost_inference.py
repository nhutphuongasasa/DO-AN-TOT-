
"""Load CatBoost Flow V2 once and perform Flow-level inference."""
from __future__ import annotations

from pathlib import Path


class CatBoostFlowV2:
    def __init__(self, model_path: str | Path):
        try:
            from catboost import CatBoostClassifier
        except ImportError as exc:
            raise RuntimeError(
                'CatBoost is required. Install with: pip install -e ".[ml]"'
            ) from exc

        self.model_path = Path(model_path)
        if not self.model_path.is_file():
            raise FileNotFoundError(f"Model not found: {self.model_path}")

        self.model = CatBoostClassifier()
        self.model.load_model(str(self.model_path))

        self.feature_names = list(self.model.feature_names_)
        self.classes = [str(value) for value in self.model.classes_]

        if len(self.feature_names) != 70:
            raise ValueError(
                f"Expected 70 model features, got {len(self.feature_names)}"
            )

        if len(set(self.feature_names)) != len(self.feature_names):
            raise ValueError("Duplicate feature names in CatBoost model")

    def predict(self, features: dict) -> dict:
        missing = [name for name in self.feature_names if name not in features]
        if missing:
            raise ValueError(f"Missing model features: {missing}")

        # Preserve the exact order stored in the trained model.
        values = [features[name] for name in self.feature_names]

        probabilities = self.model.predict_proba([values])[0]

        probability_map = {
            app: float(probability)
            for app, probability in zip(self.classes, probabilities)
        }

        application = max(probability_map, key=probability_map.get)

        return {
            "application": application,
            "confidence": probability_map[application],
            "probabilities": probability_map,
            "model": self.model_path.name,
            "feature_count": len(values),
        }
