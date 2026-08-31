import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Load the ALREADY-CLEANED dataset (negative sentinels dropped, Destination Port
# dropped, backward features dropped, deduped pre- and post-pruning).
# Do not re-clean here — that logic already ran in clean_ddos_data.py.
df = pd.read_csv("cleaned_data1.csv")

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

# Train Random Forest — class_weight='balanced' to account for the ~2:1
# DDoS:BENIGN skew introduced by the negative-sentinel filtering step.
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
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