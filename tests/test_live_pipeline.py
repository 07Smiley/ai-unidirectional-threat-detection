import pandas as pd

from src.detection.live_pipeline import LiveDetectionPipeline


class FakeModels:
    def status(self):
        return {"loaded_models": ["ddos"], "unavailable_models": {}}

    def predict(self, features):
        return [{"model": "ddos", "label": "DDoS", "confidence": 0.95}]


def test_pipeline_emits_ml_event(monkeypatch):
    pipeline = LiveDetectionPipeline()
    events = []
    pipeline.callback = events.append
    pipeline.models = FakeModels()

    batch = pd.DataFrame(
        [
            {
                "duration": 1.0,
                "orig_bytes": 100,
                "resp_bytes": 50,
                "orig_pkts": 2,
                "resp_pkts": 1,
            }
        ]
    )

    pipeline.process_batch(batch)

    assert any(
        event["source"] == "ml"
        and event["label"] == "DDoS"
        and event["confidence"] == 0.95
        for event in events
    )


def test_pipeline_exposes_model_status():
    pipeline = LiveDetectionPipeline()
    assert "loaded_models" in pipeline.model_status
    assert "unavailable_models" in pipeline.model_status
