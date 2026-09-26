import pytest
from scapy.layers.inet import IP, TCP, UDP

from scapy.packet import Raw

from src.features.cicflow_features import CICFlowExtractor


def _packet(ts, src, dst, sport, dport, flags="A", payload=b"x" * 20):
    packet = (
        IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags=flags)
        / payload
    )
    packet.time = ts
    return packet


def test_bidirectional_flow_features():
    extractor = CICFlowExtractor()
    extractor.add_packet(_packet(1.0, "10.0.0.1", "10.0.0.2", 1234, 80, "S"))
    extractor.add_packet(_packet(1.1, "10.0.0.2", "10.0.0.1", 80, 1234, "SA"))
    extractor.add_packet(_packet(1.3, "10.0.0.1", "10.0.0.2", 1234, 80, "PA"))

    row = extractor.rows()[0]

    assert row["Destination Port"] == 80
    assert row["Total Fwd Packets"] == 2
    assert row["Total Length of Fwd Packets"] == 40
    assert row["Fwd Packet Length Max"] == 20
    assert row["Fwd Packet Length Min"] == 20
    assert row["Fwd Packet Length Mean"] == 20
    assert row["Total Backward Packets"] == 1
    assert row["SYN Flag Count"] == 2
    assert row["ACK Flag Count"] == 2
    assert row["Flow Duration"] == pytest.approx(300000.0)
    assert row["Fwd IAT Total"] == pytest.approx(300000.0)
    assert row["Fwd IAT Mean"] == pytest.approx(300000.0)
    assert row["Fwd IAT Std"] == 0.0
    assert row["Fwd IAT Max"] == pytest.approx(300000.0)
    assert row["Fwd IAT Min"] == pytest.approx(300000.0)
    assert row["Flow Packets/s"] > 0


def test_idle_flow_is_emitted():
    extractor = CICFlowExtractor()
    extractor.add_packet(_packet(10.0, "10.0.0.1", "10.0.0.2", 1111, 443))
    rows = extractor.pop_completed(idle_timeout=1.0, now=12.0)
    assert len(rows) == 1
    assert rows[0]["Total Fwd Packets"] == 1


def test_tcp_packet_features_match_cicflowmeter_payload_and_header_semantics():
    extractor = CICFlowExtractor()
    packet = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1234, dport=80, flags="PA")
        / Raw(b"x" * 20)
    )
    packet.time = 1.0

    extractor.add_packet(packet)
    row = extractor.rows()[0]

    # CICFlowMeter records TCP payload bytes for packet-length features and
    # transport-header bytes for Fwd Header Length.
    assert row["Total Length of Fwd Packets"] == 20.0
    assert row["Fwd Packet Length Max"] == 20.0
    assert row["Fwd Packet Length Min"] == 20.0
    assert row["Fwd Packet Length Mean"] == 20.0
    assert row["Fwd Header Length"] == 20.0
    assert row["Fwd PSH Flags"] == 1


def test_udp_packet_features_use_payload_and_udp_header_lengths():
    extractor = CICFlowExtractor()
    packet = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=1234, dport=53)
        / Raw(b"x" * 12)
    )
    packet.time = 1.0

    extractor.add_packet(packet)
    row = extractor.rows()[0]

    assert row["Total Length of Fwd Packets"] == 12.0
    assert row["Fwd Packet Length Max"] == 12.0
    assert row["Fwd Header Length"] == 8.0
    assert row["Fwd PSH Flags"] == 0
    assert row["Fwd URG Flags"] == 0


def test_backward_packet_does_not_change_forward_only_projection():
    forward = _packet(1.0, "10.0.0.1", "10.0.0.2", 1234, 80, "PA", b"x" * 20)
    reverse = _packet(1.5, "10.0.0.2", "10.0.0.1", 80, 1234, "A", b"y" * 900)

    one_way = CICFlowExtractor()
    one_way.add_packet(forward)
    one_way_row = one_way.rows()[0]

    two_way = CICFlowExtractor()
    two_way.add_packet(forward)
    two_way.add_packet(reverse)
    two_way_row = two_way.rows()[0]

    for name in (
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
    ):
        assert two_way_row[name] == one_way_row[name]
