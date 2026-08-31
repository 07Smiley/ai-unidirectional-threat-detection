import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Load dataset
df = pd.read_csv("ai-unidirectional-threat-detection/src/models/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

# Clean column names
df.columns = df.columns.str.strip()

# Remove duplicates
df = df.drop_duplicates()

# Remove constant columns
constant_cols = [
    col for col in df.columns
    if df[col].nunique() <= 1
]

df = df.drop(columns=constant_cols)

# Replace infinity values
df = df.replace([np.inf, -np.inf], np.nan)

# Fill missing values
df = df.fillna(0)

# Separate features and label
X = df.drop(columns=["Label"])
y = df["Label"]

print("Dataset shape:", X.shape)
print("\nLabels:")
print(y.value_counts())

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\nTraining model...")

# Train Random Forest
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# Predictions
predictions = model.predict(X_test)

# Results
print("\nClassification Report:")
print(classification_report(y_test, predictions))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))

# Save model + feature names
joblib.dump(
    {
        "model": model,
        "features": X.columns.tolist()
    },
    "ddos_detector.pkl"
)

print("\nModel saved successfully as ddos_detector.pkl")