import pandas as pd

from src.detection.model_gate import (
    detect_dos_candidates,
    detect_patator_candidates,
    detect_webattack_candidates,
    detect_infiltration_candidates,
)


def _rows(count=8):
    return pd.DataFrame([
        {
            "id.orig_h": "10.0.0.1",
            "id.resp_h": "10.0.0.2",
            "id.resp_p": 80,
            "ts": float(i),
            "conn_state": "SF",
        }
        for i in range(count)
    ])


def test_dos_candidate_gate_uses_single_source():
    events = detect_dos_candidates(_rows(20))
    assert events and events[0]["gate"] == "dos"


def test_patator_candidate_gate_uses_repeated_service_attempts():
    events = detect_patator_candidates(_rows(8))
    assert events and events[0]["gate"] == "patator"


def test_webattack_gate_requires_http_telemetry():
    assert detect_webattack_candidates(_rows(20)) == []

    rows = _rows(1)
    rows["uri"] = ["../../etc/passwd"]
    rows["method"] = ["GET"]
    assert detect_webattack_candidates(rows)[0]["gate"] == "webattack"


def test_infiltration_gate_uses_available_zeek_telemetry():
    rows = _rows(1)
    rows["missed_bytes"] = [10]
    assert detect_infiltration_candidates(rows)[0]["gate"] == "infiltration"
