from __future__ import annotations

import asyncio
import os
import threading
import time
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

# live_monitor.status() can be slow (interface discovery). The dashboard polls
# it every few seconds and the websocket handshake reads it too, so the result
# is cached briefly and refreshed by one caller at a time.
STATUS_TTL_SECONDS = float(os.environ.get("LIVE_STATUS_TTL", "2"))
SLOW_STATUS_LOG_SECONDS = 1.0

_status_lock = threading.Lock()
_status_cache: dict[str, Any] = {"value": None, "ts": 0.0}


class LiveStartRequest(BaseModel):
    interface: str


class ResponseRequest(BaseModel):
    action: str
    ip: str


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

    # Interface discovery inside status() is slow. Run it once now, in the
    # background, so by the time the dashboard opens the answer is cached.
    def _warm_status() -> None:
        try:
            _status_snapshot()
        except Exception as exc:  # never let warm-up break startup
            print(f"[Sensor] Status warm-up failed: {type(exc).__name__}: {exc}")

    threading.Thread(target=_warm_status, name="status-warmup", daemon=True).start()
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


def _invalidate_status() -> None:
    """Drop the cached status so the next read reflects start/stop/response."""
    with _status_lock:
        _status_cache["value"] = None
        _status_cache["ts"] = 0.0


def _status_snapshot() -> dict[str, Any]:
    """Cached live_monitor.status(). Blocking: call it from a worker thread
    (sync route handlers already run in one; use asyncio.to_thread elsewhere)."""
    value = _status_cache["value"]
    if value is not None and time.monotonic() - _status_cache["ts"] < STATUS_TTL_SECONDS:
        return value

    # If another thread is already refreshing, serve the previous answer
    # instead of piling up behind it. Only block when there is nothing to serve.
    if not _status_lock.acquire(blocking=value is None):
        return value  # type: ignore[return-value]
    try:
        value = _status_cache["value"]
        if value is not None and time.monotonic() - _status_cache["ts"] < STATUS_TTL_SECONDS:
            return value
        started = time.monotonic()
        fresh = app.state.live_monitor.status()
        elapsed = time.monotonic() - started
        if elapsed > SLOW_STATUS_LOG_SECONDS:
            print(f"[Sensor] live_monitor.status() took {elapsed:.1f}s "
                  "(slow: interface discovery should be cached in LiveMonitoringService)")
        _status_cache["value"] = fresh
        _status_cache["ts"] = time.monotonic()
        return fresh
    finally:
        _status_lock.release()


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
    return _status_snapshot()


@app.post("/api/live/start")
async def live_start(request: LiveStartRequest) -> dict[str, Any]:
    try:
        result = app.state.live_monitor.start(
            request.interface,
            asyncio.get_running_loop(),
        )
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        _invalidate_status()
    return result


@app.post("/api/live/response")
def live_response(request: ResponseRequest) -> dict[str, Any]:
    try:
        return app.state.live_monitor.confirm_response(request.action, request.ip)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        _invalidate_status()


@app.post("/api/live/stop")
def live_stop() -> dict[str, Any]:
    # Stop is intentionally idempotent: pressing it while already offline
    # simply keeps the sensor stopped and returns a clean OFFLINE status.
    try:
        return app.state.live_monitor.stop()
    finally:
        _invalidate_status()


@app.websocket("/ws/threats")
async def threat_stream(websocket: WebSocket) -> None:
    manager: WebSocketManager = app.state.websocket_manager
    store: ThreatAnalysisStore = app.state.threat_store

    await manager.connect(websocket)
    try:
        snapshot = store.get()
        # status() is slow and blocking; running it on the event loop would
        # freeze every other request (including /health) while it runs.
        live = await asyncio.to_thread(_status_snapshot)
        await websocket.send_json(
            {
                "event": "connected",
                "latest": snapshot.model_dump(),
                "live": live,
            }
        )
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)