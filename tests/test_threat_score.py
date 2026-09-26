from src.detection.threat_score import calculate_threat_score, calculate_threat_evidence, response_offer


def test_threat_score_uses_strongest_malicious_confidence():
    events = [
        {"label": "BENIGN", "confidence": 0.99},
        {"label": "DDoS", "confidence": 0.81},
        {"label": "PortScan", "confidence": 0.72},
    ]
    assert calculate_threat_score(events) == 81.0


def test_response_threshold_only_offers_action():
    assert not response_offer(74.99, 75)
    assert response_offer(75, 75)


def test_threat_evidence_keeps_score_and_source_together():
    events = [
        {"model": "ddos", "label": "DDoS", "confidence": 0.98, "src_ip": "10.0.0.20", "dst_ip": "10.0.0.1"},
        {"model": "portscan", "label": "PortScan", "confidence": 0.70, "src_ip": "10.0.0.30", "dst_ip": "10.0.0.1"},
    ]
    evidence = calculate_threat_evidence(events)
    assert evidence["score"] == 98.0
    assert evidence["source_ip"] == "10.0.0.20"
    assert evidence["destination_ip"] == "10.0.0.1"
    assert evidence["prediction"]["model"] == "ddos"


def test_threat_evidence_ignores_benign_high_confidence():
    evidence = calculate_threat_evidence([
        {"model": "ddos", "label": "BENIGN", "confidence": 0.99, "src_ip": "10.0.0.99"},
        {"model": "portscan", "label": "PortScan", "confidence": 0.93, "src_ip": "10.0.0.20"},
    ])
    assert evidence["score"] == 93.0
    assert evidence["source_ip"] == "10.0.0.20"
