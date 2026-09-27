import pytest

from src.models.runtime import (
    DEFAULT_MODEL_PATHS,
    MODEL_NAMES,
    RuntimeModel,
    UNIDIRECTIONAL_FEATURES,
)


def test_deployed_model_set_is_exactly_the_runtime_contract():
    assert tuple(DEFAULT_MODEL_PATHS) == MODEL_NAMES
    assert len(MODEL_NAMES) == 7

    for name, path in DEFAULT_MODEL_PATHS.items():
        assert path.name == f"{name}_unidirectional.pkl"
        assert path.exists(), f"Missing deployed model: {path}"


@pytest.mark.parametrize("model_name", MODEL_NAMES)
def test_deployed_unidirectional_model_artifact_loads(model_name):
    model = RuntimeModel(DEFAULT_MODEL_PATHS[model_name])

    assert model.model_type == "random_forest_unidirectional"
    assert model.features == UNIDIRECTIONAL_FEATURES
    assert model.model is not None
    assert hasattr(model.model, "predict")
    assert hasattr(model.model, "classes_")


def test_runtime_schema_contains_no_forbidden_bidirectional_features():
    from src.features.unidirectional_features import FORBIDDEN_BIDIRECTIONAL_FEATURES

    assert not (set(UNIDIRECTIONAL_FEATURES) & FORBIDDEN_BIDIRECTIONAL_FEATURES)


def test_runtime_prediction_projects_live_rows_to_exact_unidirectional_schema():
    import pandas as pd

    from src.models.runtime import RuntimeModelRegistry

    row = {
        "Destination Port": 443,
        "Total Fwd Packets": 4,
        "Total Backward Packets": 999,
        "Total Length of Fwd Packets": 400,
        "Total Length of Bwd Packets": 999999,
        "Fwd Packet Length Max": 120,
        "Fwd Packet Length Min": 80,
        "Fwd Packet Length Mean": 100,
        "Fwd Packet Length Std": 10,
        "Bwd Packet Length Max": 9000,
        "Bwd Packet Length Min": 9000,
        "Fwd IAT Total": 3000,
        "Fwd IAT Mean": 1000,
        "Fwd IAT Std": 100,
        "Fwd IAT Max": 1100,
        "Fwd IAT Min": 900,
        "Bwd IAT Total": 999999,
        "Bwd IAT Mean": 999999,
        "Bwd IAT Std": 999999,
        "Bwd IAT Max": 999999,
        "Bwd IAT Min": 999999,
        "Fwd PSH Flags": 1,
        "Bwd PSH Flags": 99,
        "Fwd URG Flags": 0,
        "Bwd URG Flags": 99,
        "Fwd Header Length": 80,
        "Bwd Header Length": 9999,
        "Total Packets": 1003,
        "Total Bytes": 1000399,
        "Flow Bytes/s": 999999,
        "Flow Packets/s": 999999,
        "Average Packet Size": 9999,
        "FIN Flag Count": 99,
        "SYN Flag Count": 99,
        "ACK Flag Count": 99,
    }

    registry = RuntimeModelRegistry()
    assert len(registry.models) == 7
    predictions = registry.predict(pd.DataFrame([row]))

    assert len(predictions) == 7
    assert {item["model"] for item in predictions} == set(MODEL_NAMES)
    assert all("label" in item and "confidence" in item for item in predictions)
