import sys
import types

import pandas as pd

from src.models import runtime


class FakeModel:
    classes_ = ["BENIGN", "DDoS"]

    def predict(self, data):
        return ["DDoS"] * len(data)

    def predict_proba(self, data):
        return [[0.1, 0.9] for _ in range(len(data))]


class FakeJoblib:
    @staticmethod
    def load(path):
        return {"model": FakeModel(), "features": ["total_packets", "total_bytes"]}


def test_runtime_model_prediction(monkeypatch, tmp_path):
    monkeypatch.setattr(runtime, "joblib", FakeJoblib)
    model_path = tmp_path / "ddos_detector.pkl"
    model_path.write_bytes(b"test")

    model = runtime.RuntimeModel(model_path)
    features = pd.DataFrame(
        [{"total_packets": 20, "total_bytes": 2000, "unused": 1}]
    )

    result = model.predict(features)

    assert result[0]["label"] == "DDoS"
    assert result[0]["confidence"] == 0.9
    assert result[0]["probabilities"]["DDoS"] == 0.9


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
