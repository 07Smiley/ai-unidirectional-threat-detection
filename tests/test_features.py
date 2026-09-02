import pandas as pd
import pytest
from scapy.all import Ether, IP, TCP

from src.features.flow_features import create_flow_features, extract_flow_features


def test_extract_flow_features_from_packets_produces_expected_columns():
    packets = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80),
    ]
    packets[0].time = 1.0
    packets[1].time = 3.0

    flows = extract_flow_features(packets)

    assert len(flows) == 1
    assert {
        "ts",
        "id.orig_h",
        "id.resp_h",
        "id.orig_p",
        "id.resp_p",
        "flow_duration",
        "total_packets",
        "total_bytes",
        "packet_rate",
        "average_packet_size",
    }.issubset(flows.columns)
    assert flows.loc[0, "id.orig_h"] == "10.0.0.1"
    assert flows.loc[0, "id.resp_h"] == "10.0.0.2"
    assert flows.loc[0, "total_packets"] == 2
    assert flows.loc[0, "flow_duration"] == 2.0


def test_create_flow_features_returns_empty_dataframe_for_empty_input():
    empty = pd.DataFrame(
        columns=[
            "ts",
            "id.orig_h",
            "id.resp_h",
            "id.orig_p",
            "id.resp_p",
            "proto",
            "duration",
            "orig_bytes",
            "resp_bytes",
            "orig_pkts",
            "resp_pkts",
            "orig_ip_bytes",
            "resp_ip_bytes",
            "missed_bytes",
        ]
    )

    features = create_flow_features(empty)

    assert features.empty


def test_create_flow_features_rejects_missing_required_columns():
    flows = pd.DataFrame({"orig_bytes": [10], "resp_bytes": [5]})

    with pytest.raises(ValueError, match="Missing required flow columns"):
        create_flow_features(flows)


def test_extract_flow_features_rejects_packet_sequences_without_ip_layers():
    with pytest.raises(ValueError, match="No usable network packets"):
        extract_flow_features([Ether(), Ether()])
