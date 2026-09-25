from scapy.layers.inet import IP, TCP

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
    assert row["Flow Duration"] == 300000.0
    assert row["Fwd IAT Total"] == 300000.0
    assert row["Fwd IAT Mean"] == 300000.0
    assert row["Fwd IAT Std"] == 0.0
    assert row["Fwd IAT Max"] == 300000.0
    assert row["Fwd IAT Min"] == 300000.0
    assert row["Flow Packets/s"] > 0


def test_idle_flow_is_emitted():
    extractor = CICFlowExtractor()
    extractor.add_packet(_packet(10.0, "10.0.0.1", "10.0.0.2", 1111, 443))
    rows = extractor.pop_completed(idle_timeout=1.0, now=12.0)
    assert len(rows) == 1
    assert rows[0]["Total Fwd Packets"] == 1
