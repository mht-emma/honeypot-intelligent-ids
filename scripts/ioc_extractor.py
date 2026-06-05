#!/usr/bin/env python3
"""
IOC Extractor — Honeypot Distribué Intelligent
Extrait les Indicateurs de Compromission depuis MongoDB (logs Cowrie)
Auteurs : Anibar Taha & Mahamat Emma Aboubakar
EMSI Casablanca — 4ème année Cybersécurité (4CIRA G2) — 2025/2026
"""

from pymongo import MongoClient
from datetime import datetime
from collections import Counter
import json

MONGO_URI   = "mongodb://cowrie_user:CowrieMongo2026!@127.0.0.1:27017/cowrie"
OUTPUT_FILE = "/tmp/ioc_report.json"

def connect():
    return MongoClient(MONGO_URI)["cowrie"]

def top_ips(db):
    ips = [d["src_ip"] for d in db.sessions.find({}, {"src_ip": 1}) if "src_ip" in d]
    return [{"ip": ip, "connexions": c} for ip, c in Counter(ips).most_common(20)]

def top_credentials(db):
    creds = [
        f"{d.get('username','')}:{d.get('password','')}"
        for d in db.auth.find({}, {"username": 1, "password": 1})
        if d.get("username") and d.get("password")
    ]
    return [{"credential": c, "count": n} for c, n in Counter(creds).most_common(20)]

def top_commands(db):
    cmds = [d["input"] for d in db.input.find({"eventid": "cowrie.command.input"}, {"input": 1}) if "input" in d]
    return [{"command": c, "count": n} for c, n in Counter(cmds).most_common(20)]

def blocked_ips(db):
    return list(db.ip_scores.find(
        {"statut": "bloquee"},
        {"_id": 0, "ip": 1, "score": 1, "nb_tentatives": 1, "derniere_mise_a_jour": 1}
    ))

def ai_decisions(db):
    decisions = list(db.decisions.find(
        {},
        {"_id": 0, "timestamp": 1, "ip": 1, "decision": 1, "score_rf": 1, "raisonnement": 1}
    ).sort("timestamp", -1).limit(20))
    for d in decisions:
        if hasattr(d.get("timestamp"), "isoformat"):
            d["timestamp"] = d["timestamp"].isoformat()
    return decisions

def stats(db):
    return {
        "total_sessions":      db.sessions.count_documents({}),
        "total_auth_attempts": db.auth.count_documents({}),
        "total_commands":      db.input.count_documents({"eventid": "cowrie.command.input"}),
        "unique_ips":          len(db.sessions.distinct("src_ip")),
        "ips_bloquees":        db.ip_scores.count_documents({"statut": "bloquee"}),
        "faux_positifs":       db.faux_positifs.count_documents({}),
    }

def main():
    print("[*] Connexion MongoDB...")
    db = connect()

    print("[*] Extraction IOCs...")
    report = {
        "generated_at":    datetime.now().isoformat(),
        "project":         "Honeypot Distribué Intelligent — IDS SSH avec IA",
        "authors":         ["Anibar Taha", "Mahamat Emma Aboubakar"],
        "institution":     "EMSI Casablanca — 4CIRA G2 — 2025/2026",
        "statistics":      stats(db),
        "top_ips":         top_ips(db),
        "top_credentials": top_credentials(db),
        "top_commands":    top_commands(db),
        "blocked_ips":     blocked_ips(db),
        "ai_decisions":    ai_decisions(db),
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    print(f"[+] Rapport généré avec succès dans : {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
