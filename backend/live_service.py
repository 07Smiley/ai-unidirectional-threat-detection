from __future__ import annotations

import asyncio
from pathlib import Path
import threading
from typing import Any, Awaitable, Callable
import uuid

from src.detection.live_pipeline import LiveDetectionPipeline
from src.ingest.live_zeek_reader import LiveZeekReader
from src.zeek.manager import DEFAULT_LOG_DIR, ZeekManager


class LiveMonitoringService:
    """Own the Zeek sensor and background live detection worker."""

    def __init__(
        self,
        broadcast: Callable[[dict[str, Any]], Awaitable[None]],
        log_dir: str | Path = DEFAULT_LOG_DIR,
    ) -> None:
        self.broadcast = broadcast
        self.zeek = ZeekManager(log_dir=log_dir)
        self.zeek.clear_logs()
        self.pipeline = LiveDetectionPipeline(callback=self._on_event)
        self.reader: LiveZeekReader | None = None
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.error: str | None = None

    def _on_event(self, event: dict[str, Any]) -> None:
        payload = {
            "event": "live_threat",
            "id": uuid.uuid4().hex[:16],
            **event,
        }

        if self.loop is None or self.loop.is_closed():
            return

        future = asyncio.run_coroutine_threadsafe(
            self.broadcast(payload),
            self.loop,
        )
        # Consume background exceptions so a disconnected client cannot
        # silently terminate the monitoring worker.
        future.add_done_callback(lambda task: task.exception())

    def _run_reader(self) -> None:
        assert self.reader is not None
        try:
            self.pipeline.run(self.reader, stop_event=self.stop_event)
        except Exception as exc:
            self.error = str(exc)

    def start(self, interface: str, loop: asyncio.AbstractEventLoop) -> dict[str, Any]:
        if self.worker is not None and self.worker.is_alive():
            raise RuntimeError("Live monitoring is already running.")

        status = self.zeek.start(interface)
        if not self.zeek.wait_for_log("conn.log", timeout=10):
            self.zeek.stop()
            raise RuntimeError("Zeek started but conn.log did not become available.")

        self.loop = loop
        self.stop_event.clear()
        self.error = None
        self.reader = LiveZeekReader(
            self.zeek.log_dir / "conn.log",
            start_at_end=False,
        )
        self.worker = threading.Thread(
            target=self._run_reader,
            name="live-threat-detector",
            daemon=True,
        )
        self.worker.start()

        return self.status()

    def stop(self) -> dict[str, Any]:
        self.stop_event.set()

        if self.worker is not None and self.worker.is_alive():
            self.worker.join(timeout=3)

        self.worker = None
        self.reader = None
        self.zeek.stop()
        return self.status()

    def status(self) -> dict[str, Any]:
        zeek_status = self.zeek.status().to_dict()
        return {
            "running": bool(self.worker and self.worker.is_alive()),
            "interface": zeek_status.get("interface"),
            "interfaces": self.zeek.list_interfaces(),
            "zeek": zeek_status,
            "models": self.pipeline.model_status,
            "error": self.error,
        }
