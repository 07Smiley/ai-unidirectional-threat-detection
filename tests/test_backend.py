import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.schemas import ThreatAnalysisResponse, ThreatEvent
from backend.services import DetectionInputError


def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_get_latest_threats_returns_empty_by_default():
    with TestClient(app) as client:
        response = client.get("/api/threats")

    assert response.status_code == 200
    assert response.json() == {
        "input_path": "",
        "threat_count": 0,
        "threats": [],
    }


def test_analyze_endpoint_returns_structured_threats(monkeypatch):
    response_model = ThreatAnalysisResponse(
        input_path="C:/sample/conn.log",
        threat_count=1,
        threats=[
            ThreatEvent(
                id="abc123",
                type="possible_ddos",
                severity="HIGH",
                source_ip=None,
                destination_ip="10.0.0.99",
                timestamp="2026-09-02T00:00:00+00:00",
                description="Destination received many connections from multiple source IPs.",
                details={"connection_count": 24, "unique_sources": 6},
            )
        ],
    )

    def fake_analyze(input_path: str) -> ThreatAnalysisResponse:
        assert input_path == "conn.log"
        return response_model

    with TestClient(app) as client:
        monkeypatch.setattr(app.state.detection_service, "analyze", fake_analyze)
        response = client.post("/api/threats/analyze", json={"input_path": "conn.log"})
        latest = client.get("/api/threats")

    assert response.status_code == 200
    body = response.json()
    assert body["threat_count"] == 1
    assert body["threats"][0]["id"] == "abc123"
    assert body["threats"][0]["severity"] == "HIGH"
    assert body["threats"][0]["details"]["connection_count"] == 24
    assert latest.json()["threats"][0]["type"] == "possible_ddos"


def test_analyze_endpoint_maps_input_errors(monkeypatch):
    def fake_analyze(_: str):
        raise DetectionInputError("input_path is required.")

    with TestClient(app) as client:
        monkeypatch.setattr(app.state.detection_service, "analyze", fake_analyze)
        response = client.post("/api/threats/analyze", json={"input_path": ""})

    assert response.status_code == 400
    assert response.json()["detail"] == "input_path is required."


def test_websocket_receives_analysis_events(monkeypatch):
    response_model = ThreatAnalysisResponse(
        input_path="C:/sample/conn.log",
        threat_count=1,
        threats=[
            ThreatEvent(
                id="abc123",
                type="possible_port_scan",
                severity="MEDIUM",
                source_ip="10.0.0.1",
                destination_ip="10.0.0.2",
                timestamp="2026-09-02T00:00:00+00:00",
                description="Source contacted the same destination across many destination ports.",
                details={"connection_count": 6, "unique_destination_ports": 6},
            )
        ],
    )

    def fake_analyze(_: str) -> ThreatAnalysisResponse:
        return response_model

    with TestClient(app) as client:
        monkeypatch.setattr(app.state.detection_service, "analyze", fake_analyze)
        with client.websocket_connect("/ws/threats") as websocket:
            connected = websocket.receive_json()
            assert connected["event"] == "connected"

            response = client.post("/api/threats/analyze", json={"input_path": "conn.log"})
            event = websocket.receive_json()

    assert response.status_code == 200
    assert event["event"] == "threat_analysis_completed"
    assert event["threat_count"] == 1
    assert event["threats"][0]["type"] == "possible_port_scan"


def test_run_rule_detectors_uses_shared_detector_set(monkeypatch, tmp_path):
    import backend.services as services

    calls = []

    def scanning(flows, **kwargs):
        calls.append(("scanning", kwargs))
        return [{"type": "possible_port_scan"}]

    def ddos(flows):
        calls.append(("ddos", {}))
        return [{"type": "possible_ddos"}]

    def beaconing(flows, **kwargs):
        calls.append(("beaconing", kwargs))
        return [{"type": "possible_beaconing"}]

    monkeypatch.setattr(services, "detect_scanning", scanning)
    monkeypatch.setattr(services, "detect_ddos", ddos)
    monkeypatch.setattr(services, "detect_beaconing", beaconing)
    monkeypatch.setattr(services, "detect_exfiltration", None)
    monkeypatch.setattr(services, "detect_dga", None)

    results = services.run_rule_detectors(object())

    assert [item["type"] for item in results] == [
        "possible_port_scan",
        "possible_ddos",
        "possible_beaconing",
    ]
    assert calls[0] == (
        "scanning",
        {"min_unique_ports": 8, "min_connections": 8},
    )
    assert calls[1] == ("ddos", {})
    assert calls[2] == (
        "beaconing",
        {
            "min_connections": 8,
            "min_span_seconds": 15.0,
            "max_interval_cv": 0.35,
        },
    )


def test_live_response_requires_threshold_and_matching_source(monkeypatch, tmp_path):
    from backend.live_service import LiveMonitoringService

    service = LiveMonitoringService(lambda payload: None, log_dir=tmp_path / "zeek")
    service.latest_ml.update({
        "score": 91.0,
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
    })

    with pytest.raises(ValueError, match="below the response threshold"):
        service.confirm_response("block", "10.0.0.1")

    service.latest_ml["score"] = 95.0
    with pytest.raises(ValueError, match="does not match"):
        service.confirm_response("block", "10.0.0.9")


def test_live_response_requires_explicit_firewall_call(monkeypatch, tmp_path):
    from backend.live_service import LiveMonitoringService

    service = LiveMonitoringService(lambda payload: None, log_dir=tmp_path / "zeek")
    service.latest_ml.update({
        "score": 95.0,
        "source_ip": "10.0.0.1",
    })

    calls = []
    monkeypatch.setattr(
        service.firewall,
        "block",
        lambda ip: calls.append(ip) or {"action": "block", "ip": ip},
    )

    result = service.confirm_response("block", "10.0.0.1")

    assert result == {"action": "block", "ip": "10.0.0.1"}
    assert calls == ["10.0.0.1"]



def test_dashboard_groups_are_sorted_by_threat_score(monkeypatch):
    import dashboard

    class FakeProvider:
        def get_flows(self):
            return [
                {
                    "src_ip": "10.0.0.10", "host": None, "request_count": 1,
                    "timestamp": "10:00:00", "timestamp_epoch": 10,
                    "label": "PORT_SCAN", "confidence": 0.65, "threat_score": 65.0,
                },
                {
                    "src_ip": "10.0.0.20", "host": None, "request_count": 1,
                    "timestamp": "10:00:01", "timestamp_epoch": 11,
                    "label": "DDOS", "confidence": 0.85, "threat_score": 85.0,
                },
                {
                    "src_ip": "10.0.0.30", "host": None, "request_count": 1,
                    "timestamp": "10:00:02", "timestamp_epoch": 12,
                    "label": "BENIGN", "confidence": None, "threat_score": 0.0,
                },
            ]

    monkeypatch.setattr(dashboard, "_data_provider", FakeProvider())

    groups = dashboard.get_groups()

    assert [g["src_ip"] for g in groups] == [
        "10.0.0.20",
        "10.0.0.10",
        "10.0.0.30",
    ]
    assert groups[0]["threat_score"] == 85.0
    assert groups[0]["flagged_flows"] == 1


def test_dashboard_group_analysis_includes_threat_score(monkeypatch):
    import dashboard

    class FakeProvider:
        def get_flows(self):
            return [{
                "src_ip": "10.0.0.20",
                "timestamp": "10:00:00",
                "timestamp_epoch": 10,
                "label": "DDOS",
                "confidence": 0.85,
                "threat_score": 85.0,
                "why": ["24 connections", "6 unique sources"],
            }]

    monkeypatch.setattr(dashboard, "_data_provider", FakeProvider())
    analysis = dashboard.get_group_analysis("10.0.0.20")

    assert analysis["threat_score"] == 85.0
    assert analysis["flagged_flows"] == 1
    assert analysis["total_flows"] == 1


def test_gemini_status_never_exposes_api_key(monkeypatch):
    import dashboard

    monkeypatch.setenv("GEMINI_API_KEY", "secret-value")
    with dashboard.app.test_client() as client:
        response = client.get("/api/gemini/status")

    assert response.status_code == 200
    assert response.json["configured"] is True
    assert "secret" not in response.get_data(as_text=True)
