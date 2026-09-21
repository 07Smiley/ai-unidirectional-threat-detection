from __future__ import annotations

import threading
import time
from typing import Callable

from scapy.all import AsyncSniffer

from src.features.cicflow_features import CICFlowExtractor


class LivePacketCapture:
    """Capture packets from a network interface and emit completed CICFlow flows."""

    def __init__(
        self,
        interface: str,
        callback: Callable[[list[dict]], None],
        idle_timeout: float = 2.0,
        poll_interval: float = 0.5,
        bpf_filter: str | None = None,
        extractor: CICFlowExtractor | None = None,
    ) -> None:
        if not interface:
            raise ValueError("A network interface is required.")
        if idle_timeout <= 0:
            raise ValueError("idle_timeout must be greater than zero.")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be greater than zero.")

        self.interface = interface
        self.callback = callback
        self.idle_timeout = idle_timeout
        self.poll_interval = poll_interval
        self.bpf_filter = bpf_filter
        self.extractor = extractor or CICFlowExtractor()

        self._sniffer = None
        self._monitor_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._error: str | None = None

    @property
    def running(self) -> bool:
        return bool(
            self._sniffer is not None
            and getattr(self._sniffer, "running", False)
        )

    @property
    def error(self) -> str | None:
        return self._error

    def _on_packet(self, packet) -> None:
        try:
            with self._lock:
                self.extractor.add_packet(packet)
        except Exception as exc:  # one malformed packet must not kill capture
            self._error = str(exc)

    def _emit_completed(self) -> None:
        with self._lock:
            rows = self.extractor.pop_completed(
                idle_timeout=self.idle_timeout,
                now=time.time(),
            )
        if rows:
            self.callback(rows)

    def _monitor(self) -> None:
        while not self._stop_event.wait(self.poll_interval):
            self._emit_completed()

    def start(self) -> None:
        if self.running:
            raise RuntimeError("Packet capture is already running.")

        self._error = None
        self._stop_event.clear()
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._on_packet,
            store=False,
            filter=self.bpf_filter,
        )
        self._sniffer.start()

        self._monitor_thread = threading.Thread(
            target=self._monitor,
            name="live-packet-flow-monitor",
            daemon=True,
        )
        self._monitor_thread.start()

    def stop(self) -> list[dict]:
        self._stop_event.set()

        if self._sniffer is not None:
            try:
                if getattr(self._sniffer, "running", False):
                    self._sniffer.stop()
            finally:
                self._sniffer = None

        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=max(1.0, self.poll_interval * 3))
            self._monitor_thread = None

        with self._lock:
            rows = self.extractor.flush()

        if rows:
            self.callback(rows)

        return rows
