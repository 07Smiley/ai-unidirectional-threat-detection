from __future__ import annotations

from collections import deque

import pandas as pd

from src.detection.beaconing import detect_beaconing
from src.detection.ddos import detect_ddos
from src.detection.dga import is_suspicious_domain
from src.detection.scanning import detect_scanning
from src.detection.exfiltration import detect_exfiltration_live
from src.detection.encrypted import detect_encrypted_live


class LiveThreatDetector:
    """Run all available first-stage detectors over a rolling live window."""

    def __init__(self, max_rows: int = 1000) -> None:
        if max_rows < 1:
            raise ValueError("max_rows must be at least 1.")
        self.max_rows = max_rows
        self._history: deque[pd.DataFrame] = deque()
        self._row_count = 0

    @property
    def row_count(self) -> int:
        return self._row_count

    def reset(self) -> None:
        self._history.clear()
        self._row_count = 0

    def _append(self, batch: pd.DataFrame) -> None:
        if batch is None or batch.empty:
            return
        self._history.append(batch.copy())
        self._row_count += len(batch)
        while self._row_count > self.max_rows and self._history:
            oldest = self._history.popleft()
            overflow = self._row_count - self.max_rows
            if len(oldest) <= overflow:
                self._row_count -= len(oldest)
            else:
                self._history.appendleft(oldest.iloc[overflow:].copy())
                self._row_count -= overflow
                break

    def _window(self) -> pd.DataFrame:
        if not self._history:
            return pd.DataFrame()
        return pd.concat(list(self._history), ignore_index=True)

    @staticmethod
    def _detect_dga_live(window: pd.DataFrame) -> list[dict]:
        if "query" not in window.columns:
            return []
        results = []
        for _, row in window.iterrows():
            domain = row.get("query")
            if is_suspicious_domain(domain):
                results.append({
                    "type": "possible_dga",
                    "domain": domain,
                    "src_ip": row.get("id.orig_h", "unknown"),
                    "dst_ip": row.get("id.resp_h", "unknown"),
                    "dst_port": row.get("id.resp_p", 53),
                    "ts": row.get("ts"),
                    "severity": "medium",
                })
        return results

    def process(self, features: pd.DataFrame) -> list[dict]:
        """Run every available first-stage detector before ML gating."""
        self._append(features)
        window = self._window()
        if window.empty:
            return []

        return (
            detect_scanning(window)
            + detect_ddos(window)
            + detect_beaconing(window)
            + self._detect_dga_live(window)
            + detect_exfiltration_live(window)
            + detect_encrypted_live(window)
        )
