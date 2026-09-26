from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from src.features.cicflow_features import CICFLOW_FEATURES
from src.features.flow_features import FLOW_COLUMNS
from src.features.unidirectional_features import UNIDIRECTIONAL_FEATURES, transform_dataframe

LIVE_FEATURE_COLUMNS = set(FLOW_COLUMNS) | set(CICFLOW_FEATURES) | set(UNIDIRECTIONAL_FEATURES) | {
    "flow_duration", "total_packets", "total_bytes", "packet_rate",
    "byte_rate", "average_packet_size", "byte_ratio", "packet_ratio",
}

try:
    import joblib
except ImportError:
    joblib = None

REPO_ROOT = Path(__file__).resolve().parents[2]

MODEL_DIR = REPO_ROOT / "src" / "models" / "pkl"

# Live inference is intentionally restricted to the unidirectional artifacts.
# Legacy *_detector.pkl files may remain in the repository for compatibility
# and historical experiments, but they must never be loaded by the live engine.
MODEL_NAMES = (
    "bot", "ddos", "dos", "infiltration", "patator", "portscan", "webattack",
)

DEFAULT_MODEL_PATHS = {
    name: MODEL_DIR / f"{name}_unidirectional.pkl"
    for name in MODEL_NAMES
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
            raise ModelNotAvailableError(f"Model artifact not found: {self.path}")

        artifact = joblib.load(self.path)
        if not isinstance(artifact, dict) or "model" not in artifact:
            raise ModelNotAvailableError(
                f"Invalid model artifact: {self.path}. Expected a dict containing 'model'."
            )

        self.model = artifact["model"]
        self.model_type = str(artifact.get("model_type", ""))
        self.features = list(artifact.get("features", []))

        # The live engine accepts only the exact forward-only training schema.
        # This prevents historical/bidirectional artifacts from being loaded
        # merely because some of their columns happen to exist in live rows.
        if self.model_type != "random_forest_unidirectional":
            raise ModelNotAvailableError(
                f"Model {self.path.name} is not a supported unidirectional "
                f"runtime artifact."
            )
        if self.features != UNIDIRECTIONAL_FEATURES:
            raise ModelNotAvailableError(
                f"Model {self.path.name} expects features not produced by the live "
                f"pipeline: {', '.join(self.features[:8])}"
                + (" ..." if len(self.features) > 8 else "")
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

        working = features
        missing = [column for column in self.features if column not in working.columns]
        if missing and self.model_type == "random_forest_unidirectional":
            working = transform_dataframe(working)
            missing = [column for column in self.features if column not in working.columns]

        if missing:
            raise ValueError(
                "Live features are missing model columns: " + ", ".join(missing)
            )

        return working.loc[:, self.features].apply(
            pd.to_numeric, errors="coerce"
        ).fillna(0)

    def predict(self, features: pd.DataFrame) -> list[dict[str, Any]]:
        model_input = self._input(features)
        if model_input.empty:
            return []

        labels = self.model.predict(model_input)
        probabilities = self.model.predict_proba(model_input) if hasattr(self.model, "predict_proba") else None

        results = []
        for index, label in enumerate(labels):
            item: dict[str, Any] = {"label": str(label)}
            if probabilities is not None and hasattr(self.model, "classes_"):
                class_names = list(self.model.classes_)
                item["confidence"] = float(max(probabilities[index]))
                item["probabilities"] = {
                    str(name): float(probabilities[index][position])
                    for position, name in enumerate(class_names)
                }
            results.append(item)
        return results


class RuntimeModelRegistry:
    """Manage the trained detector artifacts available to the live pipeline."""

    def __init__(self, model_paths: dict[str, str | Path] | None = None) -> None:
        paths = dict(model_paths) if model_paths is not None else dict(DEFAULT_MODEL_PATHS)
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
                predictions.append({"model": name, **prediction})
        return predictions

    def status(self) -> dict[str, Any]:
        loaded = sorted(self.models)
        return {
            "engine": "UNIDIRECTIONAL ML ENGINE" if loaded else "UNIDIRECTIONAL ML ENGINE (NO MODELS)",
            "schema": "forward-only",
            "loaded_models": loaded,
            "unavailable_models": self.errors.copy(),
            "legacy_models_ignored": True,
        }
