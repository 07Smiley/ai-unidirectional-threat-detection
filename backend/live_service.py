from __future__ import annotations

import asyncio
from pathlib import Path
import threading
from typing import Any, Awaitable, Callable
import uuid

import pandas as pd

from src.detection.live_pipeline import LiveDetectionPipeline
from src.ingest.live_packet_capture import LivePacketCapture
from src.ingest.live_zeek_reader import LiveZeekReader
from src.zeek.manager import DEFAULT_LOG_DIR, ZeekManager
from src.response.firewall import FirewallActionError, HostFirewall
from src.response.policy import ThreatResponsePolicy


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
        self.packet_capture: LivePacketCapture | None = None
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.error: str | None = None
        self.response_policy = ThreatResponsePolicy()
        self.firewall = HostFirewall()
        self.latest_ml: dict[str, Any] = {
            "score": 0.0,
            "response_available": False,
            "prediction": None,
            "source_ip": None,
            "destination_ip": None,
        }

    def confirm_response(self, action: str, ip: str) -> dict[str, Any]:
        """Apply a firewall action only after an explicit API confirmation."""
        if action not in {"block", "unblock"}:
            raise ValueError("Action must be 'block' or 'unblock'.")

        if action == "block":
            score = float(self.latest_ml.get("score", 0.0))
            source_ip = self.latest_ml.get("source_ip")
            if not self.response_policy.requires_user_confirmation(score / 100.0):
                raise ValueError("Current threat score is below the response threshold.")
            if not source_ip or ip != source_ip:
                raise ValueError("IP does not match the latest confirmed threat source.")

        try:
            result = self.firewall.block(ip) if action == "block" else self.firewall.unblock(ip)
        except FirewallActionError:
            raise
        return result

    def _on_event(self, event: dict[str, Any]) -> None:
        if event.get("type") == "ml_prediction":
            label = str(event.get("label", ""))
            if label.lower() not in {"benign", "normal"}:
                self.latest_ml["prediction"] = {
                    "model": event.get("model"),
                    "label": label,
                    "confidence": event.get("confidence"),
                    "probabilities": event.get("probabilities", {}),
                    "src_ip": event.get("src_ip"),
                    "dst_ip": event.get("dst_ip"),
                }
                self.latest_ml["source_ip"] = event.get("src_ip")
                self.latest_ml["destination_ip"] = event.get("dst_ip")
        elif event.get("type") == "threat_score":
            self.latest_ml["score"] = float(event.get("score", 0.0))
            self.latest_ml["response_available"] = bool(event.get("response_available", False))
            # The score and response target must come from the same winning
            # prediction. Never reuse whichever ML event happened to arrive last.
            self.latest_ml["source_ip"] = event.get("source_ip")
            self.latest_ml["destination_ip"] = event.get("destination_ip")
            if event.get("prediction") is not None:
                self.latest_ml["prediction"] = event.get("prediction")

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

    def _on_packet_flows(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        features = pd.DataFrame(rows)
        try:
            self.pipeline.process_packet_features(features)
        except Exception as exc:
            self.error = str(exc)

    def _run_reader(self) -> None:
        assert self.reader is not None
        try:
            self.pipeline.run(self.reader, stop_event=self.stop_event)
        except Exception as exc:
            self.error = str(exc)

    def start(self, interface: str, loop: asyncio.AbstractEventLoop) -> dict[str, Any]:
        if self.worker is not None and self.worker.is_alive():
            raise RuntimeError("Live monitoring is already running.")

        validation = self.zeek.validate_interface(interface)
        if not validation.get("valid"):
            raise ValueError(str(validation.get("reason") or "Selected interface is not suitable for live capture."))

        capture_check = self.zeek.verify_live_capture(
            interface,
            startup_timeout=5.0,
            log_timeout=3.0,
        )
        if not capture_check.get("ready"):
            raise RuntimeError(
                "Live Zeek capture is not ready: "
                + str(capture_check.get("message") or "unknown capture error")
            )

        status = self.zeek.start(interface)

        self.loop = loop
        self.stop_event.clear()
        self.error = None
        self.latest_ml = {
            "score": 0.0,
            "response_available": False,
            "prediction": None,
            "source_ip": None,
            "destination_ip": None,
        }
        self.packet_capture = LivePacketCapture(
            interface=interface,
            callback=self._on_packet_flows,
        )
        try:
            self.packet_capture.start()
        except Exception:
            self.packet_capture = None
            self.zeek.stop()
            raise

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

        if self.packet_capture is not None:
            try:
                self.packet_capture.stop()
            except Exception as exc:
                self.error = str(exc)
            self.packet_capture = None

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
            "interface_details": self.zeek.list_interface_details(),
            "zeek": zeek_status,
            "models": self.pipeline.model_status,
            "latest_ml": self.latest_ml,
            "response_policy": {
                "threshold": self.response_policy.threshold,
                "confirmation_required": self.response_policy.ask_before_block,
            },
            "packet_capture": {
                "running": bool(self.packet_capture and self.packet_capture.running),
                "error": self.packet_capture.error if self.packet_capture else None,
            },
            "error": self.error,
        }
