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
