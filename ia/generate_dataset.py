#!/usr/bin/env python3
"""
generate_dataset.py
Génère un dataset d'entraînement complet :
  - Données synthétiques normales / suspectes / malveillantes
  - Données réelles depuis MongoDB
Sauvegarde dans dataset/dataset_final.csv
"""

import pandas as pd
import numpy as np
import os

np.random.seed(42)
OUTPUT = "/opt/cowrie/ia/dataset/dataset_final.csv"
os.makedirs("/opt/cowrie/ia/dataset", exist_ok=True)

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

def generer_normaux(n=300):
    """Connexions SSH légitimes — un vrai utilisateur."""
    return pd.DataFrame({
        "nb_sessions":          np.random.randint(1, 4, n),
        "nb_tentatives_auth":   np.random.randint(1, 4, n),
        "nb_passwords_uniques": np.random.randint(1, 2, n),
        "nb_usernames_uniques": np.ones(n, dtype=int),
        "duree_moyenne":        np.random.uniform(30, 300, n),
        "frequence_par_min":    np.random.uniform(0.01, 0.5, n),
        "nb_commandes":         np.random.randint(1, 20, n),
        "commandes_sensibles":  np.zeros(n, dtype=int),
        "succes_auth":          np.random.randint(1, 4, n),
        "label":                np.zeros(n, dtype=int),
        "label_nom":            "normal",
    })

def generer_suspects(n=200):
    """Comportement ambigu — scan léger ou erreurs répétées."""
    return pd.DataFrame({
        "nb_sessions":          np.random.randint(2, 8, n),
        "nb_tentatives_auth":   np.random.randint(10, 50, n),
        "nb_passwords_uniques": np.random.randint(3, 15, n),
        "nb_usernames_uniques": np.random.randint(1, 4, n),
        "duree_moyenne":        np.random.uniform(5, 30, n),
        "frequence_par_min":    np.random.uniform(2, 15, n),
        "nb_commandes":         np.random.randint(0, 10, n),
        "commandes_sensibles":  np.random.randint(0, 2, n),
        "succes_auth":          np.random.randint(0, 2, n),
        "label":                np.ones(n, dtype=int),
        "label_nom":            "suspect",
    })

def generer_malveillants(n=400):
    """Brute force SSH — attaque automatisée."""
    return pd.DataFrame({
        "nb_sessions":          np.random.randint(5, 30, n),
        "nb_tentatives_auth":   np.random.randint(50, 500, n),
        "nb_passwords_uniques": np.random.randint(20, 200, n),
        "nb_usernames_uniques": np.random.randint(1, 10, n),
        "duree_moyenne":        np.random.uniform(0.5, 5, n),
        "frequence_par_min":    np.random.uniform(20, 200, n),
        "nb_commandes":         np.random.randint(0, 15, n),
        "commandes_sensibles":  np.random.randint(0, 5, n),
        "succes_auth":          np.random.randint(0, 3, n),
        "label":                np.full(n, 2, dtype=int),
        "label_nom":            "malveillant",
    })

def charger_mongodb():
    """Charge les données réelles depuis MongoDB."""
    try:
        from features import extraire_dataset_complet, labelliser
        df = extraire_dataset_complet()
        if df.empty:
            print("  MongoDB vide — ignoré")
            return pd.DataFrame()
        df = labelliser(df)
        df = df[FEATURES + ["label", "label_nom"]]
        print(f"  MongoDB : {len(df)} IPs chargées")
        return df
    except Exception as e:
        print(f"  MongoDB erreur : {e}")
        return pd.DataFrame()

def main():
    print("=== Génération du dataset d'entraînement ===\n")

    # Générer les données synthétiques
    print("Génération données normales    (300)...")
    normaux      = generer_normaux(300)

    print("Génération données suspectes   (200)...")
    suspects     = generer_suspects(200)

    print("Génération données malveillantes (400)...")
    malveillants = generer_malveillants(400)

    # Charger données MongoDB réelles
    print("\nChargement données MongoDB...")
    mongo_df = charger_mongodb()

    # Assembler
    dfs = [normaux, suspects, malveillants]
    if not mongo_df.empty:
        dfs.append(mongo_df)

    df = pd.concat(dfs, ignore_index=True)

    # Garder uniquement les features + label
    colonnes = FEATURES + ["label", "label_nom"]
    df = df[colonnes]

    # Mélanger
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Stats
    print(f"\n=== Dataset final ===")
    print(f"Total lignes : {len(df)}")
    print(f"\nDistribution :")
    print(df["label_nom"].value_counts())
    print(f"\nFeatures :")
    print(df[FEATURES].describe().round(2))

    # Sauvegarder
    df.to_csv(OUTPUT, index=False)
    print(f"\nDataset sauvegardé : {OUTPUT}")

if __name__ == "__main__":
    main()
