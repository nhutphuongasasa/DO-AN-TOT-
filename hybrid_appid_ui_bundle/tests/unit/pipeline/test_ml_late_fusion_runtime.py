from types import SimpleNamespace

import pytest

from appid.pipeline import processor as processor_module
from appid.pipeline.processor import PacketProcessor


class FakeCatBoost:
    classes = ["a", "b"]

    def predict(self, _features):
        return {
            "application": "a", "confidence": 0.8,
            "probabilities": {"a": 0.8, "b": 0.2},
            "model": "fake.cbm", "feature_count": 70,
        }


class FakeCNN:
    classes = ["b", "a"]

    def predict(self, _bursts):
        return {
            "application": "b", "confidence": 0.9,
            "probabilities": {"a": 0.1, "b": 0.9},
            "model": "fake.pt", "feature_count": 9,
            "tensor_shape": [1, 9, 256],
        }


def test_packet_processor_runs_catboost_cnn_and_late_fusion(monkeypatch):
    processor = PacketProcessor(
        session_id="fusion-session", lan_network="192.168.1.0/24", fusion_alpha=0.75
    )
    processor.ml_inference = FakeCatBoost()
    processor.cnn_inference = FakeCNN()
    monkeypatch.setattr(processor_module, "build_flow_features", lambda _bursts: {f"f{i}": 0 for i in range(70)})
    monkeypatch.setattr(
        "appid.ml.sequence.build_burst_sequence",
        lambda _bursts: SimpleNamespace(bursts=(object(),), sequence_length=1),
    )
    flow = SimpleNamespace(
        session_id="fusion-session", flow_id="flow-1", identification_result=None
    )

    processor._classify_flow_with_ml(flow, [object()])

    result = flow.identification_result
    assert result is not None
    assert result.application == "a"
    assert result.reason_code == "CATBOOST_CNN1D_WEIGHTED_LATE_FUSION"
    assert result.metadata["cnn_tensor_shape"] == [1, 9, 256]
    assert result.metadata["fusion_probabilities"] == pytest.approx({"a": 0.625, "b": 0.375})
    assert processor.stats.ml_catboost_predictions == 1
    assert processor.stats.ml_cnn_predictions == 1
    assert processor.stats.ml_fusion_predictions == 1
    assert processor.stats.ml_predictions == 1
    processor.close()


def test_packet_processor_falls_back_to_catboost_if_cnn_inference_fails(monkeypatch):
    class BrokenCNN:
        classes = ["a", "b"]

        def predict(self, _bursts):
            raise RuntimeError("synthetic CNN failure")

    processor = PacketProcessor(
        session_id="fallback-session", lan_network="192.168.1.0/24", fusion_alpha=0.5
    )
    processor.ml_inference = FakeCatBoost()
    processor.cnn_inference = BrokenCNN()
    monkeypatch.setattr(processor_module, "build_flow_features", lambda _bursts: {f"f{i}": 0 for i in range(70)})
    monkeypatch.setattr(
        "appid.ml.sequence.build_burst_sequence",
        lambda _bursts: SimpleNamespace(bursts=(object(),), sequence_length=1),
    )
    flow = SimpleNamespace(
        session_id="fallback-session", flow_id="flow-2", identification_result=None
    )

    processor._classify_flow_with_ml(flow, [object()])

    assert flow.identification_result.application == "a"
    assert flow.identification_result.reason_code == "CATBOOST_FALLBACK_CNN1D_ERROR"
    assert processor.stats.ml_catboost_predictions == 1
    assert processor.stats.ml_cnn_predictions == 0
    assert processor.stats.ml_fusion_predictions == 0
    assert processor.stats.ml_predictions == 1
    assert processor.stats.ml_inference_errors == 1
    processor.close()
