import pandas as pd

from src.features.live_flow_processor import LiveFlowProcessor


def test_process_live_zeek_batch():
    batch = pd.DataFrame(
        [
            {
                "ts": "1000.0",
                "id.orig_h": "10.0.0.1",
                "id.resp_h": "10.0.0.2",
                "id.orig_p": "12345",
                "id.resp_p": "443",
                "proto": "tcp",
                "duration": "2.0",
                "orig_bytes": "1000",
                "resp_bytes": "500",
                "orig_pkts": "10",
                "resp_pkts": "5",
            }
        ]
    )

    processor = LiveFlowProcessor()
    features = processor.process(batch)

    assert len(features) == 1
    assert features.iloc[0]["total_packets"] == 15
    assert features.iloc[0]["total_bytes"] == 1500
    assert features.iloc[0]["packet_rate"] == 7.5


def test_process_calls_callback():
    batch = pd.DataFrame(
        [
            {
                "duration": "1.0",
                "orig_bytes": "100",
                "resp_bytes": "100",
                "orig_pkts": "2",
                "resp_pkts": "2",
            }
        ]
    )
    received = []

    processor = LiveFlowProcessor(callback=received.append)
    processor.process(batch)

    assert len(received) == 1
    assert received[0].iloc[0]["total_packets"] == 4
