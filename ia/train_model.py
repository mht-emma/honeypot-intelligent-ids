#!/usr/bin/env python3
"""
train_model.py
Entraîne le Random Forest sur le dataset généré.
Sauvegarde model.pkl et scaler.pkl
"""

import pandas as pd
import numpy as np
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix

DATASET = "/opt/cowrie/ia/dataset/dataset_final.csv"
MODEL   = "/opt/cowrie/ia/model.pkl"
SCALER  = "/opt/cowrie/ia/scaler.pkl"

FEATURES = [
    "nb_sessions",
    "nb_tentatives_auth",
    "nb_passwords_uniques",
    "nb_usernames_uniques",
    "duree_moyenne",
    "frequence_par_min",
    "nb_commandes",
    "commandes_sensibles",
    "succes_auth",
]

def main():
    print("=== Entraînement Random Forest ===\n")

    # ── Charger le dataset ────────────────────────────────────────────────────
    print("Chargement dataset...")
    df = pd.read_csv(DATASET)
    print(f"  {len(df)} lignes chargées")
    print(f"  Distribution : {df['label_nom'].value_counts().to_dict()}\n")

    X = df[FEATURES].values
    y = df["label"].values

    # ── Split train/test ──────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train : {len(X_train)} | Test : {len(X_test)}\n")

    # ── Normalisation ─────────────────────────────────────────────────────────
    print("Normalisation des features...")
    scaler  = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # ── Entraînement ──────────────────────────────────────────────────────────
    print("Entraînement Random Forest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    print("  Entraînement terminé\n")

    # ── Évaluation ────────────────────────────────────────────────────────────
    print("=== Évaluation ===")
    y_pred = model.predict(X_test)

    print("\nRapport de classification :")
    print(classification_report(
        y_test, y_pred,
        target_names=["normal", "suspect", "malveillant"]
    ))

    print("Matrice de confusion :")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                normal  suspect  malveillant")
    labels = ["normal", "suspect", "malveillant"]
    for i, row in enumerate(cm):
        print(f"  {labels[i]:<12} {row}")

    # Cross-validation
    print("\nCross-validation (5 folds)...")
    scores = cross_val_score(model, X, y, cv=5, scoring="f1_weighted")
    print(f"  F1 moyen : {scores.mean():.3f} (+/- {scores.std():.3f})")

    # ── Feature importance ────────────────────────────────────────────────────
    print("\n=== Importance des features ===")
    importances = model.feature_importances_
    indices     = np.argsort(importances)[::-1]
    for i in indices:
        print(f"  {FEATURES[i]:<25} : {importances[i]:.3f}")

    # ── Sauvegarde ────────────────────────────────────────────────────────────
    print("\nSauvegarde du modèle...")
    with open(MODEL, "wb") as f:
        pickle.dump(model, f)
    with open(SCALER, "wb") as f:
        pickle.dump(scaler, f)
    print(f"  model.pkl  → {MODEL}")
    print(f"  scaler.pkl → {SCALER}")

    # ── Test rapide ───────────────────────────────────────────────────────────
    print("\n=== Test prédiction ===")
    exemples = [
        ([1, 2, 1, 1, 120.0, 0.1, 5, 0, 1],  "normal attendu"),
        ([3, 25, 12, 2, 8.0, 8.0, 2, 1, 0],  "suspect attendu"),
        ([10, 200, 100, 3, 2.0, 80.0, 3, 2, 0], "malveillant attendu"),
    ]
    labels_map = {0: "normal", 1: "suspect", 2: "malveillant"}
    for features_test, description in exemples:
        x     = scaler.transform([features_test])
        pred  = model.predict(x)[0]
        proba = model.predict_proba(x)[0]
        score = int(proba[2] * 60 + proba[1] * 30 + proba[0] * 10)
        print(f"  {description:<25} → {labels_map[pred]:<12} score={score}/100")

    print("\nModèle prêt pour la production.")

if __name__ == "__main__":
    main()
