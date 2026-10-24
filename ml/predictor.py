"""ml/predictor.py — Inference engine: LightGBM (native) + optional CNN (ONNX).

Chạy trên Raspberry Pi:
  - LightGBM: dùng native booster (không cần ONNX, nhẹ hơn)
  - 1D-CNN: dùng ONNX Runtime (sau khi export từ train_ts.py)
  - Isotonic calibration: tính trong Python, không cần export vào ONNX

Usage:
    from ml.predictor import FlowPredictor, DeviceWindowPredictor

    # Flow-level
    pred = FlowPredictor("ml/models/flow/fold_batch5/")
    app, conf = pred.predict(feature_dict)

    # Device-window level
    dpred = DeviceWindowPredictor("ml/models/device/fold_batch5/")
    app, conf = dpred.predict(device_feature_dict)
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Label Encoder helpers (no sklearn dependency at inference time)
# ---------------------------------------------------------------------------

class SimpleLabelEncoder:
    """Lightweight label encoder — loads from JSON, no sklearn needed on Pi."""

    def __init__(self, classes: List[str]) -> None:
        self.classes_ = classes
        self._cls2idx = {c: i for i, c in enumerate(classes)}

    @classmethod
    def from_json(cls, path: Path) -> "SimpleLabelEncoder":
        data = json.loads(path.read_text())
        return cls(data["classes"])

    def inverse_transform(self, indices: np.ndarray) -> List[str]:
        return [self.classes_[i] for i in indices]


# ---------------------------------------------------------------------------
# Isotonic Calibrator (loaded from JSON, no sklearn needed)
# ---------------------------------------------------------------------------

class _IsotonicCalibrator:
    """Minimal isotonic regression predictor (step function, no sklearn)."""

    def __init__(self, X: np.ndarray, y: np.ndarray) -> None:
        self._X = X
        self._y = y

    def predict(self, probs: np.ndarray) -> np.ndarray:
        """Apply step-function isotonic mapping."""
        return np.interp(probs, self._X, self._y)


def _load_calibrators(path: Path) -> List[_IsotonicCalibrator]:
    data = json.loads(path.read_text())
    return [_IsotonicCalibrator(np.array(d["X_"]), np.array(d["y_"])) for d in data]


def _apply_calibration(
    calibrators: List[_IsotonicCalibrator],
    raw_probs: np.ndarray,  # shape (n_classes,)
) -> np.ndarray:
    """Apply per-class calibrators and re-normalize."""
    cal = np.array([calibrators[c].predict(np.array([raw_probs[c]]))[0]
                    for c in range(len(calibrators))], dtype=np.float64)
    total = cal.sum()
    return cal / total if total > 0 else cal


# ---------------------------------------------------------------------------
# LightGBM Native Predictor (no ONNX needed)
# ---------------------------------------------------------------------------

class _LGBMNativePredictor:
    """Wraps LightGBM booster for inference without sklearn dependency."""

    def __init__(self, model_path: Path) -> None:
        try:
            import lightgbm as lgb
            self._booster = lgb.Booster(model_file=str(model_path))
            log.info("LightGBM booster loaded from %s", model_path)
        except ImportError:
            raise ImportError("lightgbm not installed. Run: pip install lightgbm")

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return probability array, shape (n_samples, n_classes)."""
        return self._booster.predict(X)


# ---------------------------------------------------------------------------
# Base Predictor
# ---------------------------------------------------------------------------

class _BasePredictor:
    """Shared logic for flow and device predictors."""

    def __init__(
        self,
        model_dir: Path,
        rejection_threshold: float = 0.50,
    ) -> None:
        self._dir = Path(model_dir)
        self._threshold = rejection_threshold
        self._le   = SimpleLabelEncoder.from_json(self._dir.parent / "label_encoder.json"
                                                   if not (self._dir / "label_encoder.json").exists()
                                                   else self._dir / "label_encoder.json")
        model_path = self._dir / "model.txt"
        if not model_path.exists():
            # Try final model in parent
            model_path = self._dir / "model_final.txt"
        self._model = _LGBMNativePredictor(model_path)

        cal_path = self._dir / "calibrators.json"
        self._calibrators: Optional[List[_IsotonicCalibrator]] = (
            _load_calibrators(cal_path) if cal_path.exists() else None
        )
        if self._calibrators is None:
            log.warning("No calibrators found — using raw LightGBM probabilities")

    def _predict_proba_calibrated(self, feature_vec: np.ndarray) -> np.ndarray:
        """Return calibrated probability vector for a single sample."""
        raw = self._model.predict_proba(feature_vec.reshape(1, -1))[0]
        if self._calibrators:
            return _apply_calibration(self._calibrators, raw)
        return raw

    def _decode(self, probs: np.ndarray) -> Tuple[str, float]:
        """Convert probability vector to (app_name, confidence), or 'unknown'."""
        idx  = int(np.argmax(probs))
        conf = float(probs[idx])
        if conf < self._threshold:
            return "unknown", conf
        return self._le.classes_[idx], conf

    @property
    def classes(self) -> List[str]:
        return self._le.classes_

    @property
    def rejection_threshold(self) -> float:
        return self._threshold

    @rejection_threshold.setter
    def rejection_threshold(self, v: float) -> None:
        self._threshold = v


# ---------------------------------------------------------------------------
# Flow-level Predictor
# ---------------------------------------------------------------------------

class FlowPredictor(_BasePredictor):
    """Per-flow classifier: takes 24-feature dict, returns (app, confidence).

    Example:
        pred = FlowPredictor("ml/models/flow/fold_batch5")
        features = extract_flow_features(flow, dest_port=443, transport="tcp")
        app, conf = pred.predict(features)
    """

    FEATURE_ORDER: Optional[List[str]] = None  # loaded lazily

    def _get_feature_order(self) -> List[str]:
        """Load expected feature order from saved metadata, or infer."""
        if self.FEATURE_ORDER is not None:
            return self.FEATURE_ORDER
        meta_path = self._dir.parent / "feature_order.json"
        if meta_path.exists():
            self.FEATURE_ORDER = json.loads(meta_path.read_text())
        else:
            # Fallback: use WindowStats extract() key order
            from ml.features import WindowStats
            sample = WindowStats().extract()
            self.FEATURE_ORDER = list(sample.keys())
        return self.FEATURE_ORDER

    def predict(self, features: Dict[str, float]) -> Tuple[str, float]:
        """Predict app from per-flow feature dict.

        Args:
            features: Dict from ml.features.extract_flow_features()

        Returns:
            (app_name, calibrated_confidence)
            Returns ("unknown", conf) if confidence < threshold.
        """
        order = self._get_feature_order()
        vec = np.array([float(features.get(k, 0.0)) for k in order], dtype=np.float32)
        probs = self._predict_proba_calibrated(vec)
        return self._decode(probs)

    def predict_batch(
        self, features_list: List[Dict[str, float]]
    ) -> List[Tuple[str, float]]:
        """Predict a batch of flows efficiently."""
        order = self._get_feature_order()
        X = np.array(
            [[float(f.get(k, 0.0)) for k in order] for f in features_list],
            dtype=np.float32,
        )
        raw_all = self._model.predict_proba(X)
        results = []
        for raw in raw_all:
            probs = _apply_calibration(self._calibrators, raw) if self._calibrators else raw
            results.append(self._decode(probs))
        return results


# ---------------------------------------------------------------------------
# Device-Window Predictor
# ---------------------------------------------------------------------------

class DeviceWindowPredictor(_BasePredictor):
    """Per-device-window classifier: takes aggregated device stats dict.

    Example:
        collector = DeviceWindowCollector()
        # ... update collector with packets ...
        features = collector.get_device_window_features(mac)
        app, conf = device_pred.predict(features)
    """

    FEATURE_ORDER: Optional[List[str]] = None

    def _get_feature_order(self) -> List[str]:
        if self.FEATURE_ORDER is not None:
            return self.FEATURE_ORDER
        meta_path = self._dir.parent / "device_feature_order.json"
        if meta_path.exists():
            self.FEATURE_ORDER = json.loads(meta_path.read_text())
        else:
            from ml.features import DeviceWindowCollector
            col = DeviceWindowCollector()
            sample = col.get_device_window_features("__dummy__")
            self.FEATURE_ORDER = list(sample.keys())
        return self.FEATURE_ORDER

    def predict(self, features: Dict[str, float]) -> Tuple[str, float]:
        """Predict dominant app for a device in a time window.

        Args:
            features: Dict from DeviceWindowCollector.get_device_window_features()

        Returns:
            (app_name, calibrated_confidence)
        """
        order = self._get_feature_order()
        vec   = np.array([float(features.get(k, 0.0)) for k in order], dtype=np.float32)
        probs = self._predict_proba_calibrated(vec)
        return self._decode(probs)


# ---------------------------------------------------------------------------
# Device Activity Aggregator (per-device, vote by bytes)
# ---------------------------------------------------------------------------

class DeviceActivityAggregator:
    """Aggregates per-flow predictions into per-device dominant app.

    Fixes vs naive approach:
      - Denominator = total bytes of ALL flows (including other/unknown)
        to avoid idle devices being labeled as an app with 100% confidence
      - other/unknown excluded from vote but included in denominator
      - Direction computed from LAN perspective (src_in_lan), not SYN
      - Dominance threshold chosen from validation set
    """

    def __init__(
        self,
        dominance_threshold: float = 0.40,
        min_bytes_for_decision: int = 0,
    ) -> None:
        """
        Args:
            dominance_threshold: Fraction of total device bytes an app must exceed.
                                 Below this → return "other". Choose via val set.
            min_bytes_for_decision: If total_bytes < this → return "other" immediately.
                                    Default 0 = disabled (let model decide).
        """
        self._threshold  = dominance_threshold
        self._min_bytes  = min_bytes_for_decision
        # mac → {app → weighted_score}
        self._scores: Dict[str, Dict[str, float]] = {}
        # mac → total bytes (including other/unknown)
        self._total_bytes: Dict[str, float] = {}

    def update(
        self,
        mac: str,
        app: str,
        confidence: float,
        byte_count: int,
    ) -> None:
        """Record a flow prediction.

        Args:
            mac:        Source MAC of the LAN device.
            app:        Predicted app name (may be "unknown" or "other").
            confidence: Calibrated prediction confidence.
            byte_count: Total bytes of this flow in the current window.
        """
        if mac not in self._scores:
            self._scores[mac]      = {}
            self._total_bytes[mac] = 0.0

        # Always add to total denominator
        self._total_bytes[mac] += byte_count

        # Only vote for specific apps, not other/unknown
        if app in ("unknown", "other", "other-idle", "other-web", "other-update"):
            return
        self._scores[mac][app] = self._scores[mac].get(app, 0.0) + byte_count * confidence

    def get_dominant_app(self, mac: str) -> Tuple[str, float]:
        """Return dominant app for a device, or 'other' if below threshold.

        Returns:
            (app_name, dominance_ratio)  where ratio = app_bytes / total_device_bytes
        """
        total = self._total_bytes.get(mac, 0.0)
        scores = self._scores.get(mac, {})

        if total < self._min_bytes:
            return "other", 0.0

        if not scores:
            return "other", 0.0

        best_app   = max(scores, key=scores.__getitem__)
        best_score = scores[best_app]
        ratio      = best_score / total if total > 0 else 0.0

        if ratio < self._threshold:
            return "other", ratio
        return best_app, ratio

    def get_all_devices(self) -> Dict[str, Tuple[str, float]]:
        """Return dominant app for every tracked device."""
        return {mac: self.get_dominant_app(mac) for mac in self._scores}

    def reset(self, mac: Optional[str] = None) -> None:
        """Reset scores for one device or all devices (new window)."""
        if mac is not None:
            self._scores.pop(mac, None)
            self._total_bytes.pop(mac, None)
        else:
            self._scores.clear()
            self._total_bytes.clear()

    @staticmethod
    def is_lan_direction(src_ip: str, lan_prefix: str) -> int:
        """Return +1 if src_ip is in LAN (upload), -1 if not (download).

        Works with mid-stream flows and UDP (no SYN required).
        """
        import ipaddress
        try:
            return +1 if ipaddress.ip_address(src_ip) in ipaddress.ip_network(lan_prefix) else -1
        except ValueError:
            return +1


# ---------------------------------------------------------------------------
# Optional: CNN ONNX Predictor (for time-series model)
# ---------------------------------------------------------------------------

class CNNONNXPredictor:
    """1D-CNN predictor via ONNX Runtime. Used for time-series device-window model.

    Requires: pip install onnxruntime
    """

    def __init__(self, onnx_path: Path, label_encoder_path: Path,
                 rejection_threshold: float = 0.50) -> None:
        try:
            import onnxruntime as ort
            self._session = ort.InferenceSession(str(onnx_path))
        except ImportError:
            raise ImportError("onnxruntime not installed: pip install onnxruntime")
        self._le        = SimpleLabelEncoder.from_json(label_encoder_path)
        self._threshold = rejection_threshold
        self._input_name = self._session.get_inputs()[0].name
        log.info("CNN ONNX predictor loaded from %s", onnx_path)

    def predict(self, timeseries: np.ndarray) -> Tuple[str, float]:
        """Predict from time-series array.

        Args:
            timeseries: shape (T, 4) float32 — output of DeviceWindowCollector.get_timeseries()

        Returns:
            (app_name, confidence)
        """
        x = timeseries.astype(np.float32)[np.newaxis, ...]  # (1, T, 4)
        outputs = self._session.run(None, {self._input_name: x})
        probs   = outputs[0][0]  # (n_classes,)

        idx  = int(np.argmax(probs))
        conf = float(probs[idx])
        if conf < self._threshold:
            return "unknown", conf
        return self._le.classes_[idx], conf
