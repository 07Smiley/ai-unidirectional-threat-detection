from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from src.features.cicflow_features import CICFlowExtractor


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
    forward = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1234, dport=80, flags="PA")
        / Raw(b"x" * 20)
    )
    forward.time = 1.0

    reverse = (
        IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=80, dport=1234, flags="A")
        / Raw(b"y" * 900)
    )
    reverse.time = 1.5

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
