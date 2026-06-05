#!/usr/bin/env python3
"""
daemon.py — Boucle principale du Module IA
Tourne toutes les 30 secondes.
Orchestre : features → scorer → llm → decision → firewall → MongoDB
"""
# Ajouter le dossier ia au path
import sys
sys.path.insert(0, "/opt/cowrie/ia")

from telegram_alert import alerte_blocage, alerte_surveillance
import time
import logging
import sys
import os
from datetime import datetime, timezone
# Ajouter le dossier ia au path
sys.path.insert(0, "/opt/cowrie/ia")

from features  import get_toutes_ips_actives, calculer_features_ip
from scorer    import calculer_score, predire_classe
from llm       import ask_llm, test_connexion
from pymongo   import MongoClient

# ─── Config (Nettoyée pour GitHub) ──────────────────────────────────────────
MONGO_URI        = "mongodb://cowrie_user:VOTRE_MOT_DE_PASSE_BDD_ICI@127.0.0.1:27017/cowrie"
FIREWALL_API     = "http://10.188.107.198:5002"  # IP VM Firewall
FIREWALL_TOKEN   = "VOTRE_TOKEN_SECRET_FIREWALL_ICI"
SEUIL_SURVEILLER = 30
SEUIL_BLOQUER    = 70
INTERVALLE_SEC   = 30
FENETRE_MIN      = 60

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/opt/cowrie/var/log/cowrie-ia.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger(__name__)

# ─── MongoDB ─────────────────────────────────────────────────────────────────
client = MongoClient(MONGO_URI)
db     = client["cowrie"]


def is_whitelisted(ip: str) -> bool:
    """Vérifie si l'IP est en liste blanche."""
    return db.whitelist.find_one({"ip": ip}) is not None


def is_already_blocked(ip: str) -> bool:
    """Vérifie si l'IP est déjà bloquée."""
    doc = db.ip_scores.find_one({"ip": ip})
    return doc and doc.get("statut") == "bloquee"


def sauvegarder_score(ip: str, features: dict, score: float, 
                       classe: str, statut: str):
    """Met à jour ip_scores dans MongoDB."""
    db.ip_scores.update_one(
        {"ip": ip},
        {"$set": {
            "ip":                  ip,
            "score":               score,
            "categorie":           classe,
            "statut":              statut,
            "nb_sessions":         features.get("nb_sessions", 0),
            "nb_tentatives":       features.get("nb_tentatives_auth", 0),
            "derniere_mise_a_jour": datetime.now(timezone.utc),
        }},
        upsert=True
    )


def sauvegarder_decision(ip: str, score_rf: float, 
                          analyse_llm: dict, action: str):
    """Enregistre la décision dans MongoDB."""
    db.decisions.insert_one({
        "timestamp":    datetime.now(timezone.utc),
        "ip":           ip,
        "score_rf":     score_rf,
        "score_llm":    analyse_llm.get("score_llm", score_rf),
        "decision":     action,
        "confiance":    analyse_llm.get("confiance", 0),
        "raisonnement": analyse_llm.get("explication", f"Score RF {score_rf:.0f}/100"),
        "categorie":    analyse_llm.get("categorie", "unknown"),
    })


def bloquer_ip(ip: str, score: float, explication: str) -> bool:
    """Envoie l'ordre de blocage à la VM Firewall via API."""
    import requests
    try:
        r = requests.post(
            f"{FIREWALL_API}/block",
            json={"ip": ip, "score": score, "raison": explication},
            headers={"Authorization": f"Bearer {FIREWALL_TOKEN}"},
            timeout=10
        )
        if r.status_code == 200:
            log.info(f"BLOQUE {ip} (score={score})")
            # Enregistrer dans actions
            db.actions.insert_one({
                "timestamp":         datetime.now(timezone.utc),
                "type":              "BLOCAGE",
                "ip":                ip,
                "source":            "auto_ia",
                "score":             score,
                "raison":            explication,
                "succes":            True,
                "commande_nftables": f"nft add rule inet filter forward ip saddr {ip} drop",
            })
            return True
        else:
            log.error(f"Firewall erreur {r.status_code} pour {ip}")
            return False
    except Exception as e:
        log.error(f"Firewall injoignable pour {ip} : {e}")
        # Enregistrer l'échec
        db.actions.insert_one({
            "timestamp": datetime.now(timezone.utc),
            "type":      "BLOCAGE",
            "ip":        ip,
            "source":    "auto_ia",
            "score":     score,
            "raison":    explication,
            "succes":    False,
            "erreur":    str(e),
        })
        return False


def analyser_ip(ip: str):
    """Pipeline complet pour une IP : features → score → llm → décision."""
    # 1. Whitelist
    if is_whitelisted(ip):
        log.debug(f"IP {ip} en whitelist — ignorée")
        return

    # 2. Déjà bloquée
    if is_already_blocked(ip):
        log.debug(f"IP {ip} deja bloquee — ignoree")
        return
    from datetime import datetime, timezone, timedelta
    recent = db.decisions.find_one({
        "ip": ip,
        "timestamp": {
            "$gte": datetime.now(timezone.utc) - timedelta(minutes=5)
        }
    })
    if recent:
        log.debug(f"IP {ip} analysée il y a moins de 5min — ignorée")
        return

    # 3. Calculer features
    features = calculer_features_ip(ip, fenetre_minutes=FENETRE_MIN)

    # 4. Score Random Forest
    score_rf = calculer_score(features)
    classe   = predire_classe(features)

    log.info(
    f"IP {ip} → score={score_rf}/100 classe={classe} "
    f"| sessions={features.get('nb_sessions',0)} "
    f"tentatives={features.get('nb_tentatives_auth',0)} "
    f"succes={features.get('succes_auth',0)} "
    f"passwords={features.get('nb_passwords_uniques',0)} "
    f"freq={features.get('frequence_par_min',0):.1f}/min"
)
    # 5. Analyse LLM (uniquement si score > seuil)
    if score_rf >= SEUIL_SURVEILLER:
        analyse_llm = ask_llm(features, score_rf)
    else:
        analyse_llm = {
            "score_llm":   int(score_rf),
            "categorie":   classe,
            "confiance":   90,
            "action":      "IGNORER",
            "explication": f"Score {score_rf}/100 sous le seuil de surveillance."
        }

    # 6. Décision finale basée sur score RF
    if score_rf >= SEUIL_BLOQUER:
        action = "BLOQUER"
        statut = "bloquee"
    elif score_rf >= SEUIL_SURVEILLER:
        action = "SURVEILLER"
        statut = "surveillee"
    else:
        action = "IGNORER"
        statut = "normale"

    # 7. Sauvegarder score dans MongoDB
    sauvegarder_score(ip, features, score_rf, classe, statut)

     # 8. Telegram IMMÉDIAT — avant LLM
    explication_rapide = f"Score RF {score_rf:.0f}/100 — {features.get('nb_tentatives_auth',0)} tentatives, {features.get('succes_auth',0)} succès"
    if action == "BLOQUER":
        succes = bloquer_ip(ip, score_rf, explication_rapide)
        if succes:
            sauvegarder_score(ip, features, score_rf, classe, "bloquee")
            alerte_blocage(ip, score_rf, explication_rapide)
            log.info(f"[BLOCAGE] {ip} score={score_rf}/100 → nftables + Telegram")
    elif action == "SURVEILLER":
        try:
            alerte_surveillance(ip, score_rf, explication_rapide)
            log.info(f"[SURVEILLANCE] {ip} score={score_rf}/100 → Telegram envoyé")
        except Exception as e:
            log.error(f"Telegram erreur : {e}")

    # 9. LLM en arrière plan — enrichit MongoDB uniquement
    if score_rf >= SEUIL_SURVEILLER:
        sauvegarder_decision(ip, score_rf,
            ask_llm(features, score_rf) if score_rf >= SEUIL_SURVEILLER else
            {"explication": explication_rapide},
            action)

def boucle_principale():
    """Boucle infinie — analyse toutes les IPs actives toutes les 30s."""
    log.info("=== Daemon IA démarré ===")
    log.info(f"Seuil surveillance : {SEUIL_SURVEILLER} | Seuil blocage : {SEUIL_BLOQUER}")
    log.info(f"Intervalle : {INTERVALLE_SEC}s | Fenêtre analyse : {FENETRE_MIN}min")

    # Vérifier Ollama
    if test_connexion():
        log.info("Ollama : connecté")
    else:
        log.warning("Ollama : non disponible — fallback RF actif")

    while True:
        try:
            ips = get_toutes_ips_actives(fenetre_minutes=FENETRE_MIN)
            if ips:
                log.info(f"Analyse de {len(ips)} IP(s) actives...")
                for ip in ips:
                    analyser_ip(ip)
            else:
                log.debug("Aucune IP active dans la fenêtre")

        except Exception as e:
            log.error(f"Erreur boucle principale : {e}")

        time.sleep(INTERVALLE_SEC)


if __name__ == "__main__":
    boucle_principale()
