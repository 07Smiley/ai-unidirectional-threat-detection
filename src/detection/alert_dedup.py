from __future__ import annotations

import time
from typing import Any


class AlertDeduplicator:
    """Suppress repeated rule alerts for the same traffic signature.

    Deduplication is deliberately applied to alert events, not raw flows or
    ML inference results. This keeps telemetry complete while preventing a
    rolling detector from emitting the same alert on every polling batch.
    """

    def __init__(self, window_seconds: float = 30.0) -> None:
        if window_seconds < 0:
            raise ValueError("window_seconds must be non-negative.")
        self.window_seconds = float(window_seconds)
        self._last_seen: dict[tuple[Any, ...], float] = {}

    @staticmethod
    def key(event: dict) -> tuple[Any, ...]:
        """Build a stable signature from the fields that identify an alert."""
        return (
            event.get("type"),
            event.get("src_ip"),
            event.get("dst_ip"),
            event.get("dst_port"),
            event.get("domain"),
        )

    def is_duplicate(self, event: dict, now: float | None = None) -> bool:
        """Return True when this alert signature was emitted recently."""
        current = time.monotonic() if now is None else float(now)
        key = self.key(event)
        previous = self._last_seen.get(key)
        self._last_seen[key] = current

        if previous is None:
            return False
        return (current - previous) < self.window_seconds

    def clear(self) -> None:
        self._last_seen.clear()
