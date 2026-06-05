#!/usr/bin/env python3
"""
scorer.py
Calcule le score de risque [0-100] depuis les features.
Utilise model.pkl + scaler.pkl
"""

import pickle
import numpy as np


def boost_score(features: dict, score: float) -> float:
    """
    Boost heuristique du score pour les cas
    que le RF synthétique ne détecte pas bien.
    """
    # 64 succès auth = compte compromis ou scan massif
    if features.get("succes_auth", 0) > 10:
        score = max(score, 75.0)

    # Beaucoup de sessions avec peu de passwords = scan credential stuffing
    if features.get("nb_sessions", 0) > 30 and features.get("nb_passwords_uniques", 0) < 5:
        score = max(score, 65.0)

    # Fréquence nulle mais beaucoup de sessions = données anciennes, on garde score actuel
    return round(min(score, 100.0), 2)
MODEL_PATH  = "/opt/cowrie/ia/model.pkl"
SCALER_PATH = "/opt/cowrie/ia/scaler.pkl"

FEATURES_ORDER = [
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

# Charger le modèle une seule fois au démarrage
with open(MODEL_PATH, "rb") as f:
    MODEL = pickle.load(f)
with open(SCALER_PATH, "rb") as f:
    SCALER = pickle.load(f)

def calculer_score(features: dict) -> float:
    x = np.array([[features.get(f, 0) for f in FEATURES_ORDER]])
    x = SCALER.transform(x)
    proba = MODEL.predict_proba(x)[0]
    score = (proba[2] * 100) + (proba[1] * 50) + (proba[0] * 5)
    score = min(100.0, max(0.0, score))

    # Boost heuristique
    if features.get("succes_auth", 0) > 10:
        score = max(score, 75.0)
    if features.get("nb_sessions", 0) > 30 and features.get("nb_passwords_uniques", 0) < 5:
        score = max(score, 65.0)
    if features.get("nb_tentatives_auth", 0) > 50:
        score = max(score, 70.0)

    return round(min(score, 100.0), 2)


def predire_classe(features: dict) -> str:
    """Retourne la classe basée sur le score final (cohérent avec boost)."""
    score = calculer_score(features)
    if score >= 70:
        return "malveillant"
    elif score >= 30:
        return "suspect"
    else:
        return "normal"


if __name__ == "__main__":
    print("=== Test scorer.py ===\n")

    tests = [
        ({
            "nb_sessions": 1, "nb_tentatives_auth": 2,
            "nb_passwords_uniques": 1, "nb_usernames_uniques": 1,
            "duree_moyenne": 120.0, "frequence_par_min": 0.1,
            "nb_commandes": 5, "commandes_sensibles": 0, "succes_auth": 1
        }, "normal"),
        ({
            "nb_sessions": 3, "nb_tentatives_auth": 25,
            "nb_passwords_uniques": 12, "nb_usernames_uniques": 2,
            "duree_moyenne": 8.0, "frequence_par_min": 8.0,
            "nb_commandes": 2, "commandes_sensibles": 1, "succes_auth": 0
        }, "suspect"),
        ({
            "nb_sessions": 10, "nb_tentatives_auth": 200,
            "nb_passwords_uniques": 100, "nb_usernames_uniques": 3,
            "duree_moyenne": 2.0, "frequence_par_min": 80.0,
            "nb_commandes": 3, "commandes_sensibles": 2, "succes_auth": 0
        }, "malveillant"),
    ]

    for features, attendu in tests:
        score  = calculer_score(features)
        classe = predire_classe(features)
        ok     = "✅" if classe == attendu else "❌"
        print(f"  {ok} {attendu:<12} → score={score:5.1f}/100  classe={classe}")
