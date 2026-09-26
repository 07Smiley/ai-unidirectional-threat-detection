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
