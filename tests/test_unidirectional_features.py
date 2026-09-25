import pandas as pd

from src.features.unidirectional_features import (
    FORBIDDEN_BIDIRECTIONAL_FEATURES,
    UNIDIRECTIONAL_FEATURES,
    transform_dataframe,
)


def test_only_forward_direction_is_used():
    row = {
        "Destination Port": 80,
        "Flow Duration": 1000,
        "Total Fwd Packets": 3,
        "Total Backward Packets": 999,
        "Total Length of Fwd Packets": 300,
        "Total Length of Bwd Packets": 99999,
        "Fwd Packet Length Max": 150,
        "Bwd Packet Length Max": 999,
        "Fwd Packet Length Min": 50,
        "Bwd Packet Length Min": 1,
        "Fwd Packet Length Mean": 100,
        "Bwd Packet Length Mean": 500,
        "Fwd Packet Length Std": 10,
        "Bwd Packet Length Std": 200,
        "Fwd IAT Total": 300,
        "Fwd IAT Mean": 100,
        "Fwd IAT Std": 10,
        "Fwd IAT Max": 120,
        "Fwd IAT Min": 80,
        "Bwd IAT Total": 99999,
        "Bwd IAT Mean": 99999,
        "Fwd PSH Flags": 1,
        "Bwd PSH Flags": 99,
        "Fwd URG Flags": 0,
        "Bwd URG Flags": 99,
        "Fwd Header Length": 60,
        "Bwd Header Length": 999,
        "Fwd Packets/s": 3000,
        "Bwd Packets/s": 999999,
        # Deliberately supplied aggregate values: these must never be used.
        "Total Packets": 1002,
        "Total Bytes": 100299,
        "Flow Bytes/s": 100299,
        "Flow Packets/s": 1002,
        "Average Packet Size": 999,
        "FIN Flag Count": 99,
        "SYN Flag Count": 99,
        "ACK Flag Count": 99,
    }

    result = transform_dataframe(pd.DataFrame([row]))

    assert result.loc[0, "Total Fwd Packets"] == 3
    assert result.loc[0, "Total Length of Fwd Packets"] == 300
    assert result.loc[0, "Fwd Packet Length Max"] == 150
    assert result.loc[0, "Fwd Packet Length Mean"] == 100
    assert result.loc[0, "Fwd IAT Mean"] == 100
    assert result.loc[0, "Fwd PSH Flags"] == 1
    assert result.loc[0, "Fwd Header Length"] == 60

    assert not any(name.startswith("Bwd ") for name in result.columns)
    assert not any(name in FORBIDDEN_BIDIRECTIONAL_FEATURES for name in result.columns)
    assert list(result.columns) == UNIDIRECTIONAL_FEATURES


def test_backward_changes_do_not_change_transformed_features():
    base = {
        "Destination Port": 443,
        "Flow Duration": 5000,
        "Total Fwd Packets": 10,
        "Total Length of Fwd Packets": 1200,
        "Fwd Packet Length Max": 300,
        "Fwd Packet Length Min": 60,
        "Fwd Packet Length Mean": 120,
        "Fwd Packet Length Std": 20,
        "Fwd IAT Total": 4000,
        "Fwd IAT Mean": 400,
        "Fwd IAT Std": 10,
        "Fwd IAT Max": 500,
        "Fwd IAT Min": 300,
        "Fwd PSH Flags": 2,
        "Fwd URG Flags": 0,
        "Fwd Header Length": 200,
        "Fwd Packets/s": 2,
    }
    first = dict(base, **{
        "Total Backward Packets": 1,
        "Total Length of Bwd Packets": 100,
        "Bwd Packet Length Max": 100,
        "Bwd IAT Mean": 50,
    })
    second = dict(base, **{
        "Total Backward Packets": 1000,
        "Total Length of Bwd Packets": 900000,
        "Bwd Packet Length Max": 9000,
        "Bwd IAT Mean": 9000,
    })

    a = transform_dataframe(pd.DataFrame([first]))
    b = transform_dataframe(pd.DataFrame([second]))

    pd.testing.assert_frame_equal(a, b)
