import pandas as pd

from src.features.unidirectional_features import UNIDIRECTIONAL_FEATURES, transform_dataframe


def test_directional_columns_are_collapsed():
    row = {
        "Destination Port": 80, "Flow Duration": 1000,
        "Total Fwd Packets": 3, "Total Backward Packets": 2,
        "Total Length of Fwd Packets": 300, "Total Length of Bwd Packets": 200,
        "Fwd Packet Length Max": 150, "Bwd Packet Length Max": 120,
        "Fwd Packet Length Min": 50, "Bwd Packet Length Min": 40,
        "Fwd Packet Length Mean": 100, "Bwd Packet Length Mean": 100,
        "Fwd Packet Length Std": 10, "Bwd Packet Length Std": 20,
        "Flow Bytes/s": 500000, "Flow Packets/s": 5000,
        "Flow IAT Mean": 250, "Flow IAT Std": 50, "Flow IAT Max": 400, "Flow IAT Min": 100,
        "Fwd PSH Flags": 1, "Bwd PSH Flags": 2, "Fwd URG Flags": 0, "Bwd URG Flags": 1,
        "Fwd Header Length": 60, "Bwd Header Length": 40,
        "FIN Flag Count": 1, "SYN Flag Count": 1, "RST Flag Count": 0, "ACK Flag Count": 4,
        "Average Packet Size": 100,
    }
    result = transform_dataframe(pd.DataFrame([row]))
    assert result.loc[0, "Total Packets"] == 5
    assert result.loc[0, "Total Bytes"] == 500
    assert result.loc[0, "PSH Flags"] == 3
    assert result.loc[0, "Header Length"] == 100
    assert not any(name.startswith("Fwd ") or name.startswith("Bwd ") for name in result.columns)
    assert list(result.columns) == UNIDIRECTIONAL_FEATURES
