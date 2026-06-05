#!/usr/bin/env python3
"""
features.py
Extrait et calcule les features par IP depuis MongoDB.
C'est le pont entre les logs Cowrie et le modèle ML.
"""

from pymongo import MongoClient
from datetime import datetime, timezone, timedelta
import pandas as pd
import numpy as np

# ─── Config ──────────────────────────────────────────────────────────────────
MONGO_URI = "mongodb://cowrie_user:CowrieMongo2026!@127.0.0.1:27017/cowrie"
DB_NAME   = "cowrie"

# Commandes considérées comme sensibles
COMMANDES_SENSIBLES = [
    "wget", "curl", "chmod", "chown", "passwd",
    "/etc/passwd", "/etc/shadow", "nc ", "netcat",
    "python", "perl", "bash -i", "sh -i",
    "iptables", "nmap", "masscan", "hydra",
    "rm -rf", "dd if", "mkfs", "crontab"
]

client = MongoClient(MONGO_URI)
db     = client[DB_NAME]


def calculer_features_ip(ip: str, fenetre_minutes: int = 60) -> dict:
    """
    Calcule toutes les features pour une IP donnée
    sur une fenêtre temporelle.

    Args:
        ip              : adresse IP à analyser
        fenetre_minutes : fenêtre d'analyse en minutes

    Returns:
        dict des features calculées
    """
    maintenant = datetime.now(timezone.utc)
    debut      = maintenant - timedelta(minutes=fenetre_minutes)
    debut_ts   = debut.timestamp()

    # ── Sessions ─────────────────────────────────────────────────────────────
    sessions = list(db.sessions.find(
        {"src_ip": ip, "time": {"$gte": debut_ts}},
        {"time": 1, "starttime": 1, "endtime": 1}
    ))
    nb_sessions = len(sessions)

    # Durée moyenne des sessions
    durees = []
    for s in sessions:
        try:
            if s.get("starttime") and s.get("endtime"):
                t1 = datetime.fromisoformat(s["starttime"].replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(s["endtime"].replace("Z", "+00:00"))
                duree = (t2 - t1).total_seconds()
                if duree > 0:
                    durees.append(duree)
        except Exception:
            pass
    duree_moyenne = float(np.mean(durees)) if durees else 0.0

    # ── Authentification ─────────────────────────────────────────────────────
    auth_docs = list(db.auth.find(
        {"src_ip": ip, "time": {"$gte": debut_ts}},
        {"username": 1, "password": 1, "eventid": 1}
    ))
    nb_tentatives_auth    = len(auth_docs)
    nb_passwords_uniques  = len(set(
        d.get("password", "") for d in auth_docs if d.get("password")
    ))
    nb_usernames_uniques  = len(set(
        d.get("username", "") for d in auth_docs if d.get("username")
    ))
    succes_auth = db.auth.count_documents({
        "src_ip": ip,
        "eventid": "cowrie.login.success",
        "time": {"$gte": debut_ts}
    })

    # ── Commandes ─────────────────────────────────────────────────────────────
    input_docs = list(db.input.find(
        {"src_ip": ip, "time": {"$gte": debut_ts}},
        {"input": 1}
    ))
    nb_commandes = len(input_docs)
    commandes_sensibles = sum(
        1 for d in input_docs
        if any(c in d.get("input", "").lower() for c in COMMANDES_SENSIBLES)
    )

    # ── Fréquence ─────────────────────────────────────────────────────────────
    if fenetre_minutes > 0 and nb_tentatives_auth > 0:
        frequence_par_min = nb_tentatives_auth / fenetre_minutes
    else:
        frequence_par_min = 0.0

    return {
        "ip":                   ip,
        "nb_sessions":          nb_sessions,
        "nb_tentatives_auth":   nb_tentatives_auth,
        "nb_passwords_uniques": nb_passwords_uniques,
        "nb_usernames_uniques": nb_usernames_uniques,
        "duree_moyenne":        round(duree_moyenne, 2),
        "frequence_par_min":    round(frequence_par_min, 2),
        "nb_commandes":         nb_commandes,
        "commandes_sensibles":  commandes_sensibles,
        "succes_auth":          succes_auth,
    }


def get_toutes_ips_actives(fenetre_minutes: int = 60) -> list:
    """
    Retourne la liste de toutes les IPs actives
    dans la fenêtre temporelle.
    """
    debut_ts = (
        datetime.now(timezone.utc) - timedelta(minutes=fenetre_minutes)
    ).timestamp()

    ips = db.sessions.distinct("src_ip", {"time": {"$gte": debut_ts}})
    return list(ips)


def extraire_dataset_complet() -> pd.DataFrame:
    """
    Extrait TOUTES les IPs de MongoDB (pas de fenêtre temporelle)
    et calcule leurs features.
    Utilisé pour la génération du dataset d'entraînement.
    """
    toutes_ips = db.sessions.distinct("src_ip")
    print(f"IPs trouvées dans MongoDB : {len(toutes_ips)}")

    rows = []
    for ip in toutes_ips:
        features = calculer_features_ip(ip, fenetre_minutes=99999)
        rows.append(features)

    df = pd.DataFrame(rows)
    return df


def labelliser(df: pd.DataFrame) -> pd.DataFrame:
    """
    Labellise automatiquement les IPs par heuristiques.
    Utilisé pour créer le dataset d'entraînement.

    Labels :
        0 = normal
        1 = suspect
        2 = malveillant
    """
    def label_ip(row):
        score = 0

        # Brute force — tentatives massives
        if row["nb_tentatives_auth"] > 50:
            score += 40
        elif row["nb_tentatives_auth"] > 20:
            score += 20
        elif row["nb_tentatives_auth"] > 10:
            score += 10

        # Diversité passwords — signe d'automatisation
        if row["nb_passwords_uniques"] > 20:
            score += 25
        elif row["nb_passwords_uniques"] > 10:
            score += 15
        elif row["nb_passwords_uniques"] > 5:
            score += 8

        # Fréquence élevée
        if row["frequence_par_min"] > 30:
            score += 20
        elif row["frequence_par_min"] > 10:
            score += 12
        elif row["frequence_par_min"] > 5:
            score += 6

        # Commandes sensibles — post-exploitation
        if row["commandes_sensibles"] > 2:
            score += 20
        elif row["commandes_sensibles"] > 0:
            score += 10

        # Sessions très courtes — scan automatisé
        if row["duree_moyenne"] < 3 and row["nb_sessions"] > 2:
            score += 10

        # Succès auth — attaquant a réussi à entrer
        if row["succes_auth"] > 0 and row["nb_tentatives_auth"] > 10:
            score += 15

        # Label final
        if score >= 60:
            return 2   # malveillant
        elif score >= 25:
            return 1   # suspect
        else:
            return 0   # normal

    df["label"] = df.apply(label_ip, axis=1)
    df["label_nom"] = df["label"].map({
        0: "normal",
        1: "suspect",
        2: "malveillant"
    })
    return df


# ─── Test ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":

    print("=== Test features.py ===\n")

    # Test sur une IP connue
    ips = get_toutes_ips_actives(fenetre_minutes=99999)
    print(f"IPs actives dans MongoDB : {ips}\n")

    if ips:
        ip_test = ips[0]
        print(f"Calcul features pour {ip_test}...")
        f = calculer_features_ip(ip_test, fenetre_minutes=99999)
        for k, v in f.items():
            print(f"  {k:<25} : {v}")

        print("\n=== Dataset complet ===")
        df = extraire_dataset_complet()
        df = labelliser(df)
        print(df[["ip", "nb_tentatives_auth", "nb_passwords_uniques",
                   "frequence_par_min", "label_nom"]].to_string())
        print(f"\nDistribution des labels :")
        print(df["label_nom"].value_counts())

        # Sauvegarder
        df.to_csv("/opt/cowrie/ia/dataset/dataset_mongo.csv", index=False)
        print("\nDataset sauvegardé : /opt/cowrie/ia/dataset/dataset_mongo.csv")
    else:
        print("Aucune IP dans MongoDB — fais quelques connexions test d'abord")
