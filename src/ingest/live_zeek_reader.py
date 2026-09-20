from __future__ import annotations

from pathlib import Path
import time
from typing import Callable, Iterator

from src.ingest.pcap_reader import read_zeek_log


class LiveZeekReader:
    """Read newly appended records from a live Zeek TSV log.

    The reader keeps its own byte offset, skips Zeek metadata lines, and
    converts newly observed records into the same DataFrame shape used by
    the existing feature pipeline.
    """

    def __init__(
        self,
        log_path: str | Path,
        poll_interval: float = 0.25,
        start_at_end: bool = False,
    ) -> None:
        self.log_path = Path(log_path).resolve()
        self.poll_interval = poll_interval
        self.start_at_end = start_at_end
        self._offset = 0
        self._fields: list[str] | None = None
        self._partial_line = ""

    def _read_fields(self) -> list[str]:
        if not self.log_path.exists():
            raise FileNotFoundError(f"Zeek log not found: {self.log_path}")

        fields: list[str] | None = None
        with self.log_path.open("r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                if line.startswith("#fields"):
                    fields = line.rstrip("\n").split("\t")[1:]
                    break

        if fields is None:
            raise ValueError(f"Could not find #fields header in Zeek log: {self.log_path}")

        return fields

    def initialize(self) -> None:
        self._fields = self._read_fields()
        self._offset = self.log_path.stat().st_size if self.start_at_end else 0

    def read_new(self):
        """Return newly appended records as a DataFrame."""
        if self._fields is None:
            self.initialize()

        assert self._fields is not None
        if not self.log_path.exists():
            return None

        current_size = self.log_path.stat().st_size
        if current_size < self._offset:
            # Zeek rotated/recreated the file; begin from the new file.
            self._offset = 0
            self._partial_line = ""

        with self.log_path.open("r", encoding="utf-8", errors="ignore") as file:
            file.seek(self._offset)
            chunk = file.read()
            self._offset = file.tell()

        if not chunk:
            return None

        text = self._partial_line + chunk
        lines = text.splitlines(keepends=True)

        complete: list[str] = []
        self._partial_line = ""
        for line in lines:
            if line.endswith("\n"):
                complete.append(line.rstrip("\r\n"))
            else:
                self._partial_line = line

        records: list[list[str]] = []
        for line in complete:
            if not line or line.startswith("#"):
                continue
            values = line.split("\t")
            if len(values) < len(self._fields):
                continue
            records.append(values[: len(self._fields)])

        if not records:
            return None

        import pandas as pd
        return pd.DataFrame(records, columns=self._fields)

    def follow(self) -> Iterator:
        """Yield a DataFrame whenever new Zeek records arrive."""
        self.initialize()
        while True:
            batch = self.read_new()
            if batch is not None and not batch.empty:
                yield batch
            else:
                time.sleep(self.poll_interval)

    def run(
        self,
        callback: Callable,
        stop_event=None,
    ) -> None:
        """Follow the log and call callback(batch) for every new batch."""
        for batch in self.follow():
            if stop_event is not None and stop_event.is_set():
                break
            callback(batch)
