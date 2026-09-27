import pandas as pd

from src.detection.live_detector import LiveThreatDetector


def make_scan_rows():
    rows = []
    for port in range(1, 7):
        rows.append(
            {
                "id.orig_h": "10.0.0.10",
                "id.resp_h": "10.0.0.20",
                "id.resp_p": port,
                "id.orig_p": 50000 + port,
                "ts": float(port),
            }
        )
    return pd.DataFrame(rows)


def test_live_detector_uses_history_across_batches():
    detector = LiveThreatDetector(max_rows=100)

    first = detector.process(make_scan_rows().iloc[:3])
    assert first == []

    second = detector.process(make_scan_rows().iloc[3:])
    assert any(event["type"] == "possible_port_scan" for event in second)


def test_live_detector_limits_history():
    detector = LiveThreatDetector(max_rows=3)

    detector.process(make_scan_rows().iloc[:2])
    detector.process(make_scan_rows().iloc[2:])

    assert detector.row_count == 3



def test_live_detector_routes_dga_exfiltration_and_encrypted_screening():
    detector = LiveThreatDetector(max_rows=100)
    rows = [
        {
            "id.orig_h": "10.0.0.30",
            "id.resp_h": "10.0.0.40",
            "id.resp_p": 443,
            "id.orig_p": 50001,
            "proto": "tcp",
            "ts": 10.0,
            "orig_bytes": 1_500_000,
            "query": "xj3k9q7m2v8z4p1r7s6t5u4v3w2x1.example.com",
        },
    ]

    events = detector.process(pd.DataFrame(rows))

    types = {event["type"] for event in events}
    assert "possible_exfiltration" in types
    assert "observed_tls" in types
    assert "possible_dga" in types


def test_live_detector_does_not_require_optional_telemetry():
    detector = LiveThreatDetector(max_rows=100)

    rows = [
        {
            "id.orig_h": "10.0.0.50",
            "id.resp_h": "10.0.0.60",
            "id.resp_p": 80,
            "id.orig_p": 50002,
            "proto": "tcp",
            "ts": 20.0,
            "orig_bytes": 100,
        },
    ]

    events = detector.process(pd.DataFrame(rows))

    assert isinstance(events, list)
