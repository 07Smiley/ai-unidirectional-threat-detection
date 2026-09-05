import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from xgboost import XGBClassifier
import joblib

df = pd.read_csv("cleaned_data3.csv")
df.columns = [c.strip() for c in df.columns]

# CICFlowMeter duplicates this column
if "Fwd Header Length.1" in df.columns:
    df = df.drop(columns=["Fwd Header Length.1"])

df["Label"] = df["Label"].astype(str).str.strip()
df = df.replace([np.inf, -np.inf], np.nan).dropna().drop_duplicates()

X = df.drop(columns=["Label"])
y_raw = df["Label"]

le = LabelEncoder()
y = le.fit_transform(y_raw)  # BENIGN=0, Bot=1

print("Dataset shape:", X.shape)
print("\nLabels:")
print(y_raw.value_counts())

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

neg, pos = np.bincount(y_train)
scale_pos_weight = neg / pos

print("\nTraining models...")

rf = RandomForestClassifier(
    n_estimators=300,
    class_weight="balanced",
    n_jobs=-1,
    random_state=42,
)
xgb = XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    scale_pos_weight=scale_pos_weight,
    eval_metric="logloss",
    n_jobs=-1,
    random_state=42,
)

candidates = {"random_forest": rf, "xgboost": xgb}
scores = {}

for name, model in candidates.items():
    model.fit(X_train, y_train)
    preds = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]

    print(f"\n=== {name} ===")
    print(classification_report(y_test, preds, target_names=le.classes_))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, preds))
    print("ROC-AUC:", round(roc_auc_score(y_test, probs), 5))

    bot_idx = list(le.classes_).index("Bot")
    f1 = classification_report(
        y_test, preds, target_names=le.classes_, output_dict=True
    )[le.classes_[bot_idx]]["f1-score"]
    scores[name] = f1

best_name = max(scores, key=scores.get)
best_model = candidates[best_name]
print(f"\nBest model: {best_name} (Bot F1={scores[best_name]:.4f})")

importances = pd.Series(
    best_model.feature_importances_, index=X.columns
).sort_values(ascending=False)
print("\nTop 15 features by importance:")
print(importances.head(15))

joblib.dump(
    {
        "model": best_model,
        "model_type": best_name,
        "features": X.columns.tolist(),
        "label_encoder": le,
    },
    "bot_detector.pkl"
)
print("\nModel saved as bot_detector.pkl")