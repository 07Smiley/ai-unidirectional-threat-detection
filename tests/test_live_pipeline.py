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
        and event["src_ip"] == "10.0.0.1"
        for event in events
    )
    scored = [event for event in events if event["type"] == "threat_score"]
    assert scored
    assert scored[-1]["score"] == 95.0
    assert scored[-1]["source_ip"] == "10.0.0.1"
    assert scored[-1]["prediction"]["src_ip"] == "10.0.0.1"


def test_pipeline_exposes_model_status():
    pipeline = LiveDetectionPipeline()
    assert "loaded_models" in pipeline.model_status
    assert "unavailable_models" in pipeline.model_status


def test_zeek_batch_does_not_run_packet_ml():
    pipeline = LiveDetectionPipeline()
    calls = []

    class TrackingModels:
        def status(self):
            return {"loaded_models": ["ddos"], "unavailable_models": {}}

        def predict(self, features):
            calls.append(features.copy())
            return []

    pipeline.models = TrackingModels()

    zeek_batch = pd.DataFrame(
        [
            {
                "ts": 1.0,
                "id.orig_h": "10.0.0.1",
                "id.resp_h": "10.0.0.2",
                "id.orig_p": 1234,
                "id.resp_p": 80,
                "proto": "tcp",
                "duration": 0.5,
                "orig_bytes": 100,
                "resp_bytes": 200,
                "orig_pkts": 2,
                "resp_pkts": 3,
                "orig_ip_bytes": 120,
                "resp_ip_bytes": 220,
                "missed_bytes": 0,
            }
        ]
    )

    pipeline.process_batch(zeek_batch)

    assert calls == []
