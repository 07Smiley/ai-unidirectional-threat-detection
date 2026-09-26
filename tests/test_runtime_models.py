import pandas as pd

from src.features.unidirectional_features import UNIDIRECTIONAL_FEATURES, transform_dataframe
from src.models import runtime


class FakeModel:
    classes_ = ["BENIGN", "THREAT"]

    def predict(self, data):
        return ["THREAT"] * len(data)

    def predict_proba(self, data):
        return [[0.1, 0.9] for _ in range(len(data))]


class FakeJoblib:
    @staticmethod
    def load(path):
        return {
            "model": FakeModel(),
            "model_type": "random_forest_unidirectional",
            "features": UNIDIRECTIONAL_FEATURES,
        }


def _features():
    return pd.DataFrame([{
        feature: 1.0
        for feature in UNIDIRECTIONAL_FEATURES
    }])


def test_runtime_model_prediction(monkeypatch, tmp_path):
    monkeypatch.setattr(runtime, "joblib", FakeJoblib)
    model_path = tmp_path / "ddos_unidirectional.pkl"
    model_path.write_bytes(b"test")

    model = runtime.RuntimeModel(model_path)
    result = model.predict(_features())

    assert result[0]["label"] == "THREAT"
    assert result[0]["confidence"] == 0.9
    assert result[0]["probabilities"]["THREAT"] == 0.9


def test_registry_reports_missing_models(monkeypatch, tmp_path):
    monkeypatch.setattr(runtime, "joblib", FakeJoblib)

    registry = runtime.RuntimeModelRegistry(
        {
            "ddos": tmp_path / "missing-ddos.pkl",
            "portscan": tmp_path / "missing-portscan.pkl",
        }
    )

    status = registry.status()

    assert status["loaded_models"] == []
    assert set(status["unavailable_models"]) == {"ddos", "portscan"}
    assert status["legacy_models_ignored"] is True


def test_legacy_artifact_features_are_rejected(monkeypatch, tmp_path):
    class LegacyJoblib:
        @staticmethod
        def load(path):
            return {
                "model": FakeModel(),
                "features": ["total_packets", "total_bytes"],
            }

    monkeypatch.setattr(runtime, "joblib", LegacyJoblib)
    model_path = tmp_path / "ddos_detector.pkl"
    model_path.write_bytes(b"test")

    try:
        runtime.RuntimeModel(model_path)
    except runtime.ModelNotAvailableError as exc:
        assert "expects features not produced" in str(exc)
    else:
        raise AssertionError("Legacy bidirectional model should be rejected")


def test_real_unidirectional_artifacts_predict_packet_derived_features():
    from scapy.layers.inet import IP, TCP
    from src.features.cicflow_features import CICFlowExtractor

    def packet(ts, src, dst, sport, dport, flags):
        p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / (b"x" * 20)
        p.time = ts
        return p

    extractor = CICFlowExtractor()
    extractor.add_packet(packet(1.0, "10.0.0.1", "10.0.0.2", 1234, 443, "S"))
    extractor.add_packet(packet(1.1, "10.0.0.1", "10.0.0.2", 1234, 443, "PA"))
    row = extractor.rows()[0]

    frame = pd.DataFrame([row])
    assert list(transform_dataframe(frame).columns) == UNIDIRECTIONAL_FEATURES

    registry = runtime.RuntimeModelRegistry()
    status = registry.status()

    assert status["loaded_models"] == [
        "bot",
        "ddos",
        "dos",
        "infiltration",
        "patator",
        "portscan",
        "webattack",
    ]
    assert status["unavailable_models"] == {}

    predictions = registry.predict(frame)

    assert len(predictions) == 7
    assert {prediction["model"] for prediction in predictions} == set(status["loaded_models"])
    assert all("label" in prediction for prediction in predictions)
    assert all("confidence" in prediction for prediction in predictions)
