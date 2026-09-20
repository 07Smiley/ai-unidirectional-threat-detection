from __future__ import annotations

from typing import Callable

import pandas as pd

from src.features.flow_features import create_flow_features


class LiveFlowProcessor:
    """Convert live Zeek connection batches into model-ready flow features."""

    def __init__(self, callback: Callable[[pd.DataFrame], None] | None = None) -> None:
        self.callback = callback

    def process(self, batch: pd.DataFrame) -> pd.DataFrame:
        """Transform one LiveZeekReader batch using the existing feature pipeline."""
        if batch is None:
            raise ValueError("A Zeek flow batch is required.")

        if batch.empty:
            return create_flow_features(batch)

        features = create_flow_features(batch)

        if self.callback is not None and not features.empty:
            self.callback(features)

        return features

    def process_reader(self, reader, stop_event=None) -> None:
        """Consume a LiveZeekReader and process every new batch."""
        reader.run(self.process, stop_event=stop_event)
