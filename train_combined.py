import pandas as pd
import numpy as np
import joblib
import warnings
warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split
from sklearn.metrics import (classification_report, accuracy_score,
                             precision_score, recall_score,
                             f1_score, confusion_matrix)
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

# ── 1. Load combined dataset ──────────────────────────────────
print("[*] Loading combined dataset...")
X, y = joblib.load('combined_dataset.pkl')
feature_names = joblib.load('feature_names_combined.pkl')

print(f"[+] Total samples : {len(X)}")
print(f"[+] Features      : {len(feature_names)}")
print(f"[+] Label dist    : {y.value_counts().to_dict()}")

# ── 2. Train/test split ───────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)
print(f"[+] Train: {len(X_train)} | Test: {len(X_test)}")

# ── 3. Models ─────────────────────────────────────────────────
models = {
    'XGBoost':      XGBClassifier(n_estimators=100, eval_metric='logloss', random_state=42),
    'LightGBM':     LGBMClassifier(n_estimators=100, random_state=42, verbose=-1),
    'RandomForest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
    'AdaBoost':     AdaBoostClassifier(n_estimators=100, random_state=42),
    'DecisionTree': DecisionTreeClassifier(random_state=42),
    'MLP':          Pipeline([
                        ('scaler', StandardScaler()),
                        ('mlp', MLPClassifier(
                            hidden_layer_sizes=(128, 64, 32),
                            activation='relu',
                            max_iter=300,
                            random_state=42,
                            verbose=False))
                    ]),
}

results = {}
for name, model in models.items():
    print(f"\n[*] Training {name}...")
    model.fit(X_train, y_train)

    y_train_pred = model.predict(X_train)
    y_test_pred  = model.predict(X_test)

    train_acc = accuracy_score(y_train, y_train_pred)
    test_acc  = accuracy_score(y_test,  y_test_pred)
    precision = precision_score(y_test, y_test_pred, zero_division=0)
    recall    = recall_score(y_test,    y_test_pred, zero_division=0)
    f1        = f1_score(y_test,        y_test_pred, zero_division=0)
    fpr       = 1 - precision
    gap       = train_acc - test_acc
    cm        = confusion_matrix(y_test, y_test_pred)

    results[name] = test_acc

    print(f"[+] {name}")
    print(f"    Train Accuracy : {train_acc:.4f}")
    print(f"    Test Accuracy  : {test_acc:.4f}")
    print(f"    Precision      : {precision:.4f}")
    print(f"    Recall         : {recall:.4f}")
    print(f"    F1-Score       : {f1:.4f}")
    print(f"    False Pos Rate : {fpr:.4f}")
    print(f"    Gap (overfit?) : {gap:.4f} {'⚠ OVERFIT' if gap > 0.05 else '✓ OK'}")
    print(f"    Confusion Matrix:")
    print(f"      TN: {cm[0][0]}  FP: {cm[0][1]}")
    print(f"      FN: {cm[1][0]}  TP: {cm[1][1]}")
    print(classification_report(y_test, y_test_pred,
          target_names=['BENIGN', 'ATTACK'], digits=4))

# ── 4. Save best model ────────────────────────────────────────
best_name  = max(results, key=results.get)
best_model = models[best_name]
print(f"\n[+] Best model: {best_name} ({results[best_name]:.4f})")
joblib.dump(best_model, 'best_model_combined.pkl')
joblib.dump(feature_names, 'feature_names_combined.pkl')
print("[+] Saved as best_model_combined.pkl")
