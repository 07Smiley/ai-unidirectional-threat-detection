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
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 80,
                "protocol": "tcp",
                "Destination Port": 80,
                "Total Fwd Packets": 20,
                "Total Length of Fwd Packets": 2000,
                "Fwd Packet Length Max": 100,
                "Fwd Packet Length Min": 60,
                "Fwd Packet Length Mean": 100,
                "Fwd Packet Length Std": 10,
                "Fwd IAT Total": 100000,
                "Fwd IAT Mean": 5000,
                "Fwd IAT Std": 500,
                "Fwd IAT Max": 6000,
                "Fwd IAT Min": 4000,
                "Fwd PSH Flags": 5,
                "Fwd URG Flags": 0,
                "Fwd Header Length": 800,
            }
        ]
    )

    pipeline.process_packet_features(batch)

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
