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
