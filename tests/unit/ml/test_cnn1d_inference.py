import numpy as np
import pytest

from appid.ml.cnn1d_inference import (
    CLASSES,
    FEATURE_NAMES,
    CNN1DInference,
    encode_burst_sequence,
)
from appid.ml.late_fusion import weighted_late_fusion


def test_encode_burst_sequence_matches_training_shape_and_sampling():
    bursts = [
        {
            "direction": "FORWARD",
            "duration_seconds": 0.1,
            "packet_count": 2,
            "total_bytes": 150,
            "inter_burst_gap_seconds": None,
            "packet_lengths": [50, 100],
        },
        {
            "direction": "BACKWARD",
            "duration_seconds": 0.2,
            "packet_count": 1,
            "total_bytes": 80,
            "inter_burst_gap_seconds": 0.05,
            "packet_lengths": [80],
        },
    ]
    encoded = encode_burst_sequence(bursts)
    assert encoded.shape == (9, 256)
    assert encoded.dtype == np.float32
    assert encoded[0, 0] == 1.0
    assert encoded[0, -1] == -1.0
    assert len(FEATURE_NAMES) == 9


def test_encode_burst_sequence_rejects_empty_input():
    with pytest.raises(ValueError, match="at least one burst"):
        encode_burst_sequence(())


def test_weighted_late_fusion_uses_catboost_alpha_and_normalizes():
    fused = weighted_late_fusion(
        {"a": 0.8, "b": 0.2},
        {"a": 0.1, "b": 0.9},
        alpha_catboost=0.75,
    )
    assert fused == pytest.approx({"a": 0.625, "b": 0.375})
    assert sum(fused.values()) == pytest.approx(1.0)


@pytest.mark.parametrize("alpha", [-0.01, 1.01, float("nan")])
def test_weighted_late_fusion_rejects_invalid_alpha(alpha):
    with pytest.raises(ValueError, match="alpha_catboost"):
        weighted_late_fusion({"a": 1.0}, {"a": 1.0}, alpha_catboost=alpha)


def test_weighted_late_fusion_requires_identical_classes():
    with pytest.raises(ValueError, match="identical classes"):
        weighted_late_fusion({"a": 1.0}, {"b": 1.0})


def test_cnn_checkpoint_load_and_predict(tmp_path):
    torch = pytest.importorskip("torch")
    from appid.ml.cnn1d_inference import _CNN1D

    model = _CNN1D.build(torch)
    checkpoint_path = tmp_path / "test_cnn.pt"
    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "classes": CLASSES,
            "feature_names": FEATURE_NAMES,
            "max_len": 256,
            "train_mean": [0.0] * 9,
            "train_std": [1.0] * 9,
        },
        checkpoint_path,
    )
    inference = CNN1DInference(checkpoint_path)
    prediction = inference.predict([
        {
            "direction": "FORWARD",
            "duration_seconds": 0.1,
            "packet_count": 2,
            "total_bytes": 150,
            "inter_burst_gap_seconds": None,
            "packet_lengths": [50, 100],
        }
    ])
    assert set(prediction["probabilities"]) == set(CLASSES)
    assert sum(prediction["probabilities"].values()) == pytest.approx(1.0)
    assert prediction["tensor_shape"] == [1, 9, 256]


def test_encode_burst_sequence_accepts_runtime_sequence_items():
    from types import SimpleNamespace
    from appid.domain.models import Direction

    burst = SimpleNamespace(
        direction=Direction.FORWARD,
        duration_seconds=0.1,
        packet_count=2,
        total_bytes=150,
        inter_burst_gap_seconds=None,
        packet_lengths=(50, 100),
    )
    encoded = encode_burst_sequence([burst])
    assert encoded.shape == (9, 256)
    assert encoded.dtype == np.float32
    assert encoded[0, 0] == 1.0


def test_load_fusion_alpha_checks_metrics_classes(tmp_path):
    import json
    from appid.ml.late_fusion import load_fusion_alpha

    path = tmp_path / "metrics.json"
    path.write_text(json.dumps({
        "classes": CLASSES,
        "best_alpha_catboost": 0.7,
    }), encoding="utf-8")
    assert load_fusion_alpha(path, CLASSES) == pytest.approx(0.7)
    with pytest.raises(ValueError, match="class order"):
        load_fusion_alpha(path, list(reversed(CLASSES)))
