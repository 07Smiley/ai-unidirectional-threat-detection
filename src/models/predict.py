import joblib
import pandas as pd

# Load saved model package
data = joblib.load("ddos_detector.pkl")

# Extract model and feature names
model = data["model"]
features = data["features"]

# Load test data
df = pd.read_csv("ai-unidirectional-threat-detection/src/models/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

# Make sure all required features exist
missing = [col for col in features if col not in df.columns]

if missing:
    print("Missing features:")
    print(missing)
    exit()

# Select features in the SAME order used during training
X = df[features]

# Predict
predictions = model.predict(X)

# Show predictions
for i, prediction in enumerate(predictions):
    print(f"Flow {i + 1}: {prediction}")

# Summary
print("\nPrediction Summary:")
print(pd.Series(predictions).value_counts())