from src.detection.threat_score import calculate_threat_score, response_offer


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
