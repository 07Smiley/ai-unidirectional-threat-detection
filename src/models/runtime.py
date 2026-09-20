from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from src.features.flow_features import FLOW_COLUMNS


LIVE_FEATURE_COLUMNS = set(FLOW_COLUMNS) | {
    "flow_duration",
    "total_packets",
    "total_bytes",
    "packet_rate",
    "byte_rate",
    "average_packet_size",
    "byte_ratio",
    "packet_ratio",
}

try:
    import joblib
except ImportError:  # pragma: no cover - handled as a runtime dependency error
    joblib = None


REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_MODEL_PATHS = {
    "ddos": REPO_ROOT / "src" / "models" / "ddos_detector.pkl",
    "portscan": REPO_ROOT / "src" / "models" / "portscan_detector.pkl",
}


class ModelNotAvailableError(RuntimeError):
    """Raised when a configured ML model cannot be loaded."""


class RuntimeModel:
    """Load a trained model artifact and expose safe prediction helpers."""

    def __init__(self, path: str | Path) -> None:
        if joblib is None:
            raise ModelNotAvailableError(
                "joblib is not installed. Install the project ML dependencies first."
            )

        self.path = Path(path).expanduser().resolve()
        if not self.path.exists():
            raise ModelNotAvailableError(
                f"Model artifact not found: {self.path}"
            )

        artifact = joblib.load(self.path)
        if not isinstance(artifact, dict) or "model" not in artifact:
            raise ModelNotAvailableError(
                f"Invalid model artifact: {self.path}. Expected a dict containing 'model'."
            )

        self.model = artifact["model"]
        self.features = list(artifact.get("features", []))
        unsupported = sorted(set(self.features) - LIVE_FEATURE_COLUMNS)
        if unsupported:
            raise ModelNotAvailableError(
                f"Model {self.path.name} expects features not produced by the live "
                f"Zeek pipeline: {', '.join(unsupported[:8])}"
                + (" ..." if len(unsupported) > 8 else "")
            )

    @property
    def name(self) -> str:
        return self.path.stem

    def _input(self, features: pd.DataFrame) -> pd.DataFrame:
        if features is None or features.empty:
            return pd.DataFrame(columns=self.features)

        if not self.features:
            raise ModelNotAvailableError(
                f"Model {self.path} does not contain its training feature names."
            )

        missing = [column for column in self.features if column not in features.columns]
        if missing:
            raise ValueError(
                f"Live features are missing model columns: {', '.join(missing)}"
            )

        return features.loc[:, self.features].apply(
            pd.to_numeric, errors="coerce"
        ).fillna(0)

    def predict(self, features: pd.DataFrame) -> list[dict[str, Any]]:
        model_input = self._input(features)
        if model_input.empty:
            return []

        labels = self.model.predict(model_input)

        probabilities = None
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(model_input)

        results = []
        for index, label in enumerate(labels):
            item: dict[str, Any] = {"label": str(label)}
            if probabilities is not None and hasattr(self.model, "classes_"):
                class_names = list(self.model.classes_)
                item["confidence"] = float(probabilities[index].max())
                item["probabilities"] = {
                    str(name): float(probabilities[index][position])
                    for position, name in enumerate(class_names)
                }
            results.append(item)

        return results


class RuntimeModelRegistry:
    """Manage optional DDoS and port-scan model artifacts."""

    def __init__(self, model_paths: dict[str, str | Path] | None = None) -> None:
        paths = dict(DEFAULT_MODEL_PATHS)
        if model_paths:
            paths.update(model_paths)

        self.models: dict[str, RuntimeModel] = {}
        self.errors: dict[str, str] = {}

        for name, path in paths.items():
            try:
                self.models[name] = RuntimeModel(path)
            except ModelNotAvailableError as exc:
                self.errors[name] = str(exc)

    def predict(self, features: pd.DataFrame) -> list[dict[str, Any]]:
        predictions = []

        for name, model in self.models.items():
            for prediction in model.predict(features):
                predictions.append(
                    {
                        "model": name,
                        **prediction,
                    }
                )

        return predictions

    def status(self) -> dict[str, Any]:
        return {
            "loaded_models": sorted(self.models),
            "unavailable_models": self.errors.copy(),
        }
