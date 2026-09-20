from __future__ import annotations

from collections import deque

import pandas as pd

from src.detection.beaconing import detect_beaconing
from src.detection.ddos import detect_ddos
from src.detection.scanning import detect_scanning


class LiveThreatDetector:
    """Run existing detectors over a rolling live-traffic window.

    A rolling window is important because a single Zeek batch may contain only
    a few connections and therefore cannot satisfy detectors that need
    multiple observations (for example, port scans or beaconing).
    """

    def __init__(self, max_rows: int = 1000) -> None:
        if max_rows < 1:
            raise ValueError("max_rows must be at least 1.")
        self.max_rows = max_rows
        self._history: deque[pd.DataFrame] = deque()
        self._row_count = 0

    @property
    def row_count(self) -> int:
        return self._row_count

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

    def process(self, features: pd.DataFrame) -> list[dict]:
        """Add new features and return newly detected threat candidates."""
        self._append(features)
        window = self._window()

        if window.empty:
            return []

        return (
            detect_scanning(window)
            + detect_ddos(window)
            + detect_beaconing(window)
        )
