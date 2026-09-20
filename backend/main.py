from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.live_service import LiveMonitoringService
from backend.schemas import (
    HealthResponse,
    ThreatAnalysisRequest,
    ThreatAnalysisResponse,
)
from backend.services import DetectionInputError, DetectionService, ThreatAnalysisStore


ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:9000",
    "http://127.0.0.1:9000",
]


class LiveStartRequest(BaseModel):
    interface: str


class WebSocketManager:
    def __init__(self) -> None:
        self.connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.connections:
            self.connections.remove(websocket)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        disconnected: list[WebSocket] = []
        for websocket in list(self.connections):
            try:
                await websocket.send_json(payload)
            except (RuntimeError, WebSocketDisconnect):
                disconnected.append(websocket)

        for websocket in disconnected:
            self.disconnect(websocket)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    manager = WebSocketManager()
    app.state.detection_service = DetectionService()
    app.state.threat_store = ThreatAnalysisStore()
    app.state.websocket_manager = manager
    app.state.live_monitor = LiveMonitoringService(manager.broadcast)
    yield
    app.state.live_monitor.stop()


app = FastAPI(
    title="AI Unidirectional Threat Detection API",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return {"status": "ok"}


@app.get("/api/threats", response_model=ThreatAnalysisResponse)
def get_latest_threats() -> ThreatAnalysisResponse:
    return app.state.threat_store.get()


@app.post("/api/threats/analyze", response_model=ThreatAnalysisResponse)
async def analyze_threats(
    request: ThreatAnalysisRequest,
) -> ThreatAnalysisResponse:
    try:
        response = app.state.detection_service.analyze(request.input_path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DetectionInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    app.state.threat_store.set(response.input_path, response.threats)
    await app.state.websocket_manager.broadcast(
        {
            "event": "threat_analysis_completed",
            "input_path": response.input_path,
            "threat_count": response.threat_count,
            "threats": [threat.model_dump() for threat in response.threats],
        }
    )
    return response


@app.get("/api/live/status")
def live_status() -> dict[str, Any]:
    return app.state.live_monitor.status()


@app.post("/api/live/start")
async def live_start(request: LiveStartRequest) -> dict[str, Any]:
    try:
        return app.state.live_monitor.start(
            request.interface,
            asyncio.get_running_loop(),
        )
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/live/stop")
def live_stop() -> dict[str, Any]:
    return app.state.live_monitor.stop()


@app.websocket("/ws/threats")
async def threat_stream(websocket: WebSocket) -> None:
    manager: WebSocketManager = app.state.websocket_manager
    store: ThreatAnalysisStore = app.state.threat_store

    await manager.connect(websocket)
    try:
        snapshot = store.get()
        await websocket.send_json(
            {
                "event": "connected",
                "latest": snapshot.model_dump(),
                "live": app.state.live_monitor.status(),
            }
        )
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
