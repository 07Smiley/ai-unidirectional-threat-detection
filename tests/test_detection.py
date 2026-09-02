import pandas as pd
import pytest

from src.detection.beaconing import detect_beaconing
from src.detection.ddos import detect_ddos
from src.detection.scanning import detect_scanning


def test_detect_scanning_flags_many_ports_to_same_destination():
    flows = pd.DataFrame(
        {
            "id.orig_h": ["10.0.0.1"] * 6,
            "id.resp_h": ["10.0.0.2"] * 6,
            "id.resp_p": [20, 21, 22, 23, 24, 25],
        }
    )

    results = detect_scanning(flows, min_unique_ports=5)

    assert len(results) == 1
    assert results[0]["src_ip"] == "10.0.0.1"
    assert results[0]["unique_destination_ports"] == 6


def test_detect_ddos_flags_many_sources_to_one_destination():
    flows = pd.DataFrame(
        {
            "id.orig_h": [f"10.0.0.{index}" for index in range(1, 7)] * 4,
            "id.resp_h": ["10.0.0.99"] * 24,
        }
    )

    results = detect_ddos(flows, min_connections=20, min_unique_sources=5)

    assert len(results) == 1
    assert results[0]["dst_ip"] == "10.0.0.99"
    assert results[0]["unique_sources"] == 6


def test_detect_beaconing_sorts_timestamps_and_computes_interval():
    flows = pd.DataFrame(
        {
            "id.orig_h": ["192.168.1.10"] * 5,
            "id.resp_h": ["8.8.8.8"] * 5,
            "ts": [40, 10, 30, 20, 50],
        }
    )

    results = detect_beaconing(flows, min_connections=5)

    assert len(results) == 1
    assert results[0]["src_ip"] == "192.168.1.10"
    assert results[0]["average_interval"] == 10.0


def test_detectors_return_empty_results_for_empty_dataframes():
    empty_scanning = pd.DataFrame(columns=["id.orig_h", "id.resp_h", "id.resp_p"])
    empty_ddos = pd.DataFrame(columns=["id.orig_h", "id.resp_h"])
    empty_beaconing = pd.DataFrame(columns=["id.orig_h", "id.resp_h", "ts"])

    assert detect_scanning(empty_scanning) == []
    assert detect_ddos(empty_ddos) == []
    assert detect_beaconing(empty_beaconing) == []


def test_detect_beaconing_handles_invalid_timestamps_without_crashing():
    flows = pd.DataFrame(
        {
            "id.orig_h": ["192.168.1.10"] * 5,
            "id.resp_h": ["8.8.8.8"] * 5,
            "ts": ["bad", None, "still-bad", "", "nan"],
        }
    )

    results = detect_beaconing(flows, min_connections=5)

    assert len(results) == 1
    assert results[0]["average_interval"] is None


def test_detectors_reject_missing_required_columns():
    with pytest.raises(ValueError, match="Scanning detection requires columns"):
        detect_scanning(pd.DataFrame({"id.orig_h": ["10.0.0.1"]}))

    with pytest.raises(ValueError, match="DDoS detection requires columns"):
        detect_ddos(pd.DataFrame({"id.resp_h": ["10.0.0.2"]}))

    with pytest.raises(ValueError, match="Beaconing detection requires columns"):
        detect_beaconing(pd.DataFrame({"id.orig_h": ["10.0.0.1"]}))
