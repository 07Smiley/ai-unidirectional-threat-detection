import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

df = pd.read_csv("cleaned_data2.csv")

X = df.drop(columns=["Label"])
y = df["Label"]

print("Dataset shape:", X.shape)
print("\nLabels:")
print(y.value_counts())

# Stratified split — critical here given the 29:1 imbalance, to make sure
# both train and test keep a proportional (thin) slice of PortScan rows.
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("\nTraining model...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, predictions))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))

# Feature importance — check whether this is learning genuine scan behavior
# or just a thin-data fluke, same diagnostic as the DDoS model.
importances = pd.Series(
    model.feature_importances_, index=X.columns
).sort_values(ascending=False)
print("\nTop 15 features by importance:")
print(importances.head(15))
print(f"\nTop 3 combined importance: {importances.head(3).sum():.3f}")

joblib.dump(
    {"model": model, "features": X.columns.tolist()},
    "portscan_detector.pkl"
)
print("\nModel saved as portscan_detector.pkl")