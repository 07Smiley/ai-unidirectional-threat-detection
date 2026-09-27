from __future__ import annotations

from collections import deque

import pandas as pd

from src.detection.beaconing import detect_beaconing
from src.detection.ddos import detect_ddos
from src.detection.dga import is_suspicious_domain
from src.detection.scanning import detect_scanning


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

    @staticmethod
    def _detect_exfiltration_live(window: pd.DataFrame) -> list[dict]:
        if "orig_bytes" not in window.columns:
            return []
        observed = pd.to_numeric(window["orig_bytes"], errors="coerce").fillna(0)
        results = []
        for index, outbound in observed.items():
            if float(outbound) >= 1_000_000:
                row = window.loc[index]
                results.append({
                    "type": "possible_exfiltration",
                    "src_ip": row.get("id.orig_h", "unknown"),
                    "dst_ip": row.get("id.resp_h", "unknown"),
                    "outbound_bytes": int(outbound),
                    "severity": "medium",
                })
        return results

    @staticmethod
    def _detect_encrypted_live(window: pd.DataFrame) -> list[dict]:
        # Identification only: TLS-like TCP/443 and QUIC-like UDP/443.
        if "proto" not in window.columns or "id.resp_p" not in window.columns:
            return []
        results = []
        ports = pd.to_numeric(window["id.resp_p"], errors="coerce")
        protocols = window["proto"].astype(str).str.lower()
        for index, row in window.iterrows():
            port = ports.loc[index]
            proto = protocols.loc[index]
            if proto == "tcp" and port == 443:
                results.append({
                    "type": "observed_tls",
                    "src_ip": row.get("id.orig_h", "unknown"),
                    "dst_ip": row.get("id.resp_h", "unknown"),
                    "dst_port": 443,
                    "severity": "info",
                })
            elif proto == "udp" and port == 443:
                results.append({
                    "type": "observed_quic",
                    "src_ip": row.get("id.orig_h", "unknown"),
                    "dst_ip": row.get("id.resp_h", "unknown"),
                    "dst_port": 443,
                    "severity": "info",
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
            + self._detect_exfiltration_live(window)
            + self._detect_encrypted_live(window)
        )
