import pandas as pd

import src.detection.exfiltration as exfiltration


def test_exfiltration_uses_only_observed_direction(tmp_path, monkeypatch):
    log_file = tmp_path / "conn.log"
    log_file.write_text("placeholder", encoding="utf-8")

    monkeypatch.setattr(
        exfiltration,
        "read_zeek_log",
        lambda _: pd.DataFrame([
            {
                "id.orig_h": "10.0.0.1",
                "id.resp_h": "10.0.0.2",
                "orig_bytes": 1_500_000,
                "resp_bytes": 0,
            }
        ]),
    )

    alerts = exfiltration.detect_exfiltration(log_file)

    assert len(alerts) == 1
    assert alerts[0]["outbound_bytes"] == 1_500_000
    assert "inbound_bytes" not in alerts[0]
    assert "outbound_ratio" not in alerts[0]


def test_exfiltration_does_not_require_reverse_direction_column(tmp_path, monkeypatch):
    log_file = tmp_path / "conn.log"
    log_file.write_text("placeholder", encoding="utf-8")

    monkeypatch.setattr(
        exfiltration,
        "read_zeek_log",
        lambda _: pd.DataFrame([
            {
                "id.orig_h": "10.0.0.1",
                "id.resp_h": "10.0.0.2",
                "orig_bytes": 1_000_001,
            }
        ]),
    )

    alerts = exfiltration.detect_exfiltration(log_file)

    assert alerts[0]["type"] == "possible_exfiltration"


def test_exfiltration_stays_below_threshold_for_small_observed_transfer(tmp_path, monkeypatch):
    log_file = tmp_path / "conn.log"
    log_file.write_text("placeholder", encoding="utf-8")

    monkeypatch.setattr(
        exfiltration,
        "read_zeek_log",
        lambda _: pd.DataFrame([
            {
                "id.orig_h": "10.0.0.1",
                "id.resp_h": "10.0.0.2",
                "orig_bytes": 999_999,
            }
        ]),
    )

    assert exfiltration.detect_exfiltration(log_file) == []
