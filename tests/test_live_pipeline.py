import pandas as pd

from src.detection.live_pipeline import LiveDetectionPipeline


class FakeModels:
    def status(self):
        return {"loaded_models": ["ddos"], "unavailable_models": {}}

    def predict(self, features):
        return [{"model": "ddos", "label": "DDoS", "confidence": 0.95}]


def _packet_batch():
    return pd.DataFrame(
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
            },
            {
                "src_ip": "10.0.0.3",
                "dst_ip": "10.0.0.4",
                "src_port": 2345,
                "dst_port": 443,
                "protocol": "tcp",
                "Destination Port": 443,
                "Total Fwd Packets": 10,
                "Total Length of Fwd Packets": 1000,
                "Fwd Packet Length Max": 120,
                "Fwd Packet Length Min": 80,
                "Fwd Packet Length Mean": 100,
                "Fwd Packet Length Std": 8,
                "Fwd IAT Total": 50000,
                "Fwd IAT Mean": 5000,
                "Fwd IAT Std": 300,
                "Fwd IAT Max": 5500,
                "Fwd IAT Min": 4500,
                "Fwd PSH Flags": 2,
                "Fwd URG Flags": 0,
                "Fwd Header Length": 400,
            },
        ]
    )


def test_pipeline_emits_ml_event():
    pipeline = LiveDetectionPipeline()
    events = []
    pipeline.callback = events.append
    pipeline.models = FakeModels()
    pipeline._flagged_sources.add("10.0.0.1")

    pipeline.process_packet_features(_packet_batch().iloc[[0]])

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


def test_multi_model_predictions_keep_each_flow_metadata():
    pipeline = LiveDetectionPipeline()
    events = []

    class MultiModelFake:
        models = {"ddos": object(), "portscan": object()}

        def status(self):
            return {"loaded_models": ["ddos", "portscan"], "unavailable_models": {}}

        def predict(self, features):
            return [
                {"model": "ddos", "label": "DDoS", "confidence": 0.70},
                {"model": "ddos", "label": "DDoS", "confidence": 0.40},
                {"model": "portscan", "label": "PortScan", "confidence": 0.20},
                {"model": "portscan", "label": "PortScan", "confidence": 0.99},
            ]

    pipeline.models = MultiModelFake()
    pipeline._flagged_sources.add("10.0.0.1")
    pipeline._flagged_sources.add("10.0.0.3")
    pipeline.callback = events.append
    pipeline.process_packet_features(_packet_batch())

    predictions = [event for event in events if event["type"] == "ml_prediction"]
    assert [(event["model"], event["flow_index"], event["src_ip"], event["dst_ip"]) for event in predictions] == [
        ("ddos", 0, "10.0.0.1", "10.0.0.2"),
        ("ddos", 1, "10.0.0.3", "10.0.0.4"),
        ("portscan", 0, "10.0.0.1", "10.0.0.2"),
        ("portscan", 1, "10.0.0.3", "10.0.0.4"),
    ]

    scored = [event for event in events if event["type"] == "threat_score"]
    assert scored[-1]["score"] == 99.0
    assert scored[-1]["source_ip"] == "10.0.0.3"
    assert scored[-1]["destination_ip"] == "10.0.0.4"
    assert scored[-1]["prediction"]["model"] == "portscan"


def test_packet_flow_is_buffered_until_rule_flags_source():
    pipeline = LiveDetectionPipeline()
    events = []
    pipeline.callback = events.append
    pipeline.models = FakeModels()

    # Simulate the real race: packet capture sees the flow first.
    pipeline.process_packet_features(_packet_batch().iloc[[0]])
    assert not any(event["type"] == "ml_prediction" for event in events)
    assert pipeline._pending_packet_features

    # Then the Zeek/rule stream flags the source.
    pipeline.rule_detector.process = lambda _features: [
        {
            "type": "possible_port_scan",
            "severity": "high",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
        }
    ]
    pipeline._process_features(_packet_batch().iloc[[0]])

    predictions = [event for event in events if event["type"] == "ml_prediction"]
    assert len(predictions) == 1
    assert predictions[0]["src_ip"] == "10.0.0.1"
    assert predictions[0]["label"] == "DDoS"
    assert pipeline._pending_packet_features == []


def test_reset_clears_pending_packet_buffer():
    pipeline = LiveDetectionPipeline()
    pipeline.process_packet_features(_packet_batch().iloc[[0]])

    assert pipeline._pending_packet_features
    pipeline.reset()

    assert pipeline._pending_packet_features == []
    assert pipeline._flagged_sources == set()


def test_pending_packet_buffer_is_bounded():
    pipeline = LiveDetectionPipeline()
    pipeline._pending_packet_max_rows = 1

    pipeline.process_packet_features(_packet_batch())

    assert sum(len(frame) for _, frame in pipeline._pending_packet_features) <= 1



def test_rule_gate_routes_flagged_source_through_all_seven_unidirectional_models():
    pipeline = LiveDetectionPipeline()
    events = []
    pipeline.callback = events.append

    class SevenModelFake:
        models = {
            "bot": object(),
            "ddos": object(),
            "dos": object(),
            "infiltration": object(),
            "patator": object(),
            "portscan": object(),
            "webattack": object(),
        }

        def status(self):
            return {"loaded_models": list(self.models), "unavailable_models": {}}

        def predict(self, features):
            assert list(features.columns) == [
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "Destination Port",
                "Total Fwd Packets",
                "Total Length of Fwd Packets",
                "Fwd Packet Length Max",
                "Fwd Packet Length Min",
                "Fwd Packet Length Mean",
                "Fwd Packet Length Std",
                "Fwd IAT Total",
                "Fwd IAT Mean",
                "Fwd IAT Std",
                "Fwd IAT Max",
                "Fwd IAT Min",
                "Fwd PSH Flags",
                "Fwd URG Flags",
                "Fwd Header Length",
            ]
            return [
                {
                    "model": name,
                    "label": name.upper(),
                    "confidence": 0.90,
                }
                for name in self.models
            ]

    pipeline.models = SevenModelFake()
    pipeline.rule_detector.process = lambda _features: [
        {
            "type": "possible_port_scan",
            "severity": "high",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
        }
    ]

    # Rule stage flags the source first.
    pipeline._process_features(_packet_batch().iloc[[0]])

    # The same source can now enter packet-derived ML.
    pipeline.process_packet_features(_packet_batch().iloc[[0]])

    predictions = [event for event in events if event["type"] == "ml_prediction"]
    assert len(predictions) == 7
    assert {event["model"] for event in predictions} == set(SevenModelFake.models)
    assert all(event["src_ip"] == "10.0.0.1" for event in predictions)
    assert pipeline._pending_packet_features == []


def test_unflagged_source_does_not_reach_any_ml_model():
    pipeline = LiveDetectionPipeline()
    calls = []

    class TrackingSevenModels:
        models = {name: object() for name in (
            "bot", "ddos", "dos", "infiltration",
            "patator", "portscan", "webattack",
        )}

        def status(self):
            return {"loaded_models": list(self.models), "unavailable_models": {}}

        def predict(self, features):
            calls.append(features.copy())
            return []

    pipeline.models = TrackingSevenModels()
    pipeline.rule_detector.process = lambda _features: []

    pipeline._process_features(_packet_batch().iloc[[0]])
    pipeline.process_packet_features(_packet_batch().iloc[[0]])

    assert calls == []
    assert pipeline._pending_packet_features
