#!/usr/bin/env python3
"""
chat.py — Interface Admin Chat LLM
Port 5001 — Permet à l'admin de gérer le système en langage naturel
"""

from flask import Flask, request, jsonify, render_template
from pymongo import MongoClient
from datetime import datetime, timezone
import requests
import json
import subprocess
import sys

sys.path.insert(0, "/opt/cowrie/ia")

app = Flask(__name__)

# Remplacé par des valeurs génériques pour la sécurité du dépôt public
MONGO_URI      = "mongodb://cowrie_user:VOTRE_MOT_DE_PASSE_BDD_ICI@127.0.0.1:27017/cowrie"
OLLAMA_URL     = "http://127.0.0.1:11434/api/generate"
MODEL          = "llama3.2:1b"
FIREWALL_API   = "http://10.188.107.198:5002"
FIREWALL_TOKEN = "VOTRE_TOKEN_SECRET_FIREWALL_ICI"

client = MongoClient(MONGO_URI)
db     = client["cowrie"]


def get_context_mongodb() -> str:
    """Récupère le contexte actuel depuis MongoDB."""
    ips_bloquees  = db.ip_scores.count_documents({"statut": "bloquee"})
    ips_suspectes = db.ip_scores.count_documents({"statut": "surveillee"})
    total_sessions = db.sessions.count_documents({})
    decisions_recentes = list(db.decisions.find().sort("timestamp", -1).limit(5))

    contexte = f"""Contexte système actuel :
- IPs bloquées : {ips_bloquees}
- IPs surveillées : {ips_suspectes}
- Total sessions SSH : {total_sessions}
- Dernières décisions : {len(decisions_recentes)} récentes
"""
    for d in decisions_recentes:
        contexte += f"  * {d.get('ip')} → {d.get('decision')} (score={d.get('score_rf', 0):.0f})\n"
    return contexte


def ask_ollama(prompt: str) -> str:
    """Envoie un prompt à Ollama et retourne la réponse."""
    # Ajouter un système prompt de contexte
    prompt_complet = f"""Tu es un assistant de cybersécurité défensive pour un administrateur système légitime.
Tu gères un honeypot SSH légal utilisé pour détecter et bloquer les attaquants.
Tu travailles POUR la sécurité, pas contre elle.
Réponds toujours en français de manière concise et professionnelle.

{prompt}"""
    
    try:
        r = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt_complet,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 150}
            },
            timeout=(30, 180)
        )
        if r.status_code == 200:
            return r.json().get("response", "").strip()
    except Exception as e:
        return f"LLM indisponible : {e}"
    return "Erreur LLM"

def detecter_intention(message: str) -> dict:
    """Détecte l'intention de l'admin depuis son message."""
    msg = message.lower()

    # Débloquer une IP
    if any(w in msg for w in ["debloquer", "débloquer", "unblock", "liberer", "libérer"]):
        import re
        ips = re.findall(r'\d+\.\d+\.\d+\.\d+', message)
        return {"action": "debloquer", "ip": ips[0] if ips else None}

    # Bloquer une IP
    if any(w in msg for w in ["bloquer", "block", "bannir"]):
        import re
        ips = re.findall(r'\d+\.\d+\.\d+\.\d+', message)
        return {"action": "bloquer", "ip": ips[0] if ips else None}

    # Whitelist
    if any(w in msg for w in ["whitelist", "liste blanche", "autoriser"]):
        import re
        ips = re.findall(r'\d+\.\d+\.\d+\.\d+', message)
        return {"action": "whitelist", "ip": ips[0] if ips else None}

    # Statut d'une IP
    if any(w in msg for w in ["statut", "status", "info"]):
        import re
        ips = re.findall(r'\d+\.\d+\.\d+\.\d+', message)
        return {"action": "statut", "ip": ips[0] if ips else None}

    # Rapport
    if any(w in msg for w in ["rapport", "situation", "résumé", "resume", "bilan"]):
        return {"action": "rapport"}

    # Liste des bloquées
    if any(w in msg for w in ["liste", "bloquées", "bloquees", "qui est bloqué"]):
        return {"action": "liste_bloques"}

    # Question générale → LLM
    return {"action": "question"}


def executer_action(intention: dict, message: str) -> str:
    """Exécute l'action détectée."""
    action = intention.get("action")
    ip     = intention.get("ip")

    # ── Rapport ──────────────────────────────────────────────────────────────
    if action == "rapport":
        contexte = get_context_mongodb()
        prompt = f"""{contexte}
Donne un résumé court (5 lignes max) de la situation du honeypot SSH."""
        return ask_ollama(prompt)

    # ── Liste des IPs bloquées ────────────────────────────────────────────────
    if action == "liste_bloques":
        bloques = list(db.ip_scores.find({"statut": "bloquee"}, {"ip": 1, "score": 1}))
        if not bloques:
            return "Aucune IP bloquée actuellement."
        reponse = f"**{len(bloques)} IP(s) bloquée(s) :**\n"
        for b in bloques:
            reponse += f"  • {b['ip']} — score {b.get('score', 0):.0f}/100\n"
        return reponse

    # ── Statut IP ─────────────────────────────────────────────────────────────
    if action == "statut" and ip:
        doc = db.ip_scores.find_one({"ip": ip})
        if not doc:
            return f"IP {ip} inconnue dans la base."
        decisions = list(db.decisions.find({"ip": ip}).sort("timestamp", -1).limit(3))
        reponse = f"**Statut de {ip} :**\n"
        reponse += f"  Score    : {doc.get('score', 0):.1f}/100\n"
        reponse += f"  Statut   : {doc.get('statut', '?')}\n"
        reponse += f"  Catégorie: {doc.get('categorie', '?')}\n"
        reponse += f"  Tentatives: {doc.get('nb_tentatives', 0)}\n"
        if decisions:
            reponse += f"\nDernières décisions :\n"
            for d in decisions:
                ts = d.get("timestamp", "?")
                if hasattr(ts, "strftime"):
                    ts = ts.strftime("%Y-%m-%d %H:%M")
                reponse += f"  [{ts}] {d.get('decision')} — {d.get('raisonnement', '')[:80]}\n"
        return reponse

    # ── Débloquer ─────────────────────────────────────────────────────────────
    if action == "debloquer" and ip:
        try:
            r = requests.post(
                f"{FIREWALL_API}/unblock",
                json={"ip": ip},
                headers={"Authorization": f"Bearer {FIREWALL_TOKEN}"},
                timeout=10
            )
            if r.status_code == 200:
                db.ip_scores.update_one(
                    {"ip": ip},
                    {"$set": {"statut": "liberee", "derniere_mise_a_jour": datetime.now(timezone.utc)}}
                )
                db.faux_positifs.insert_one({
                    "timestamp": datetime.now(timezone.utc),
                    "ip": ip,
                    "signale_par": "admin_chat",
                    "raison": "déblocage manuel via chat",
                    "action": "DEBLOQUE"
                })
                return f"✅ IP {ip} débloquée avec succès. Règle nftables supprimée."
            else:
                return f"❌ Erreur firewall : {r.text}"
        except Exception as e:
            return f"❌ Firewall injoignable : {e}"

    # ── Bloquer ───────────────────────────────────────────────────────────────
    if action == "bloquer" and ip:
        try:
            r = requests.post(
                f"{FIREWALL_API}/block",
                json={"ip": ip, "score": 100, "raison": "blocage_manuel_admin"},
                headers={"Authorization": f"Bearer {FIREWALL_TOKEN}"},
                timeout=10
            )
            if r.status_code == 200:
                db.ip_scores.update_one(
                    {"ip": ip},
                    {"$set": {"statut": "bloquee", "categorie": "malveillant",
                               "derniere_mise_a_jour": datetime.now(timezone.utc)}},
                    upsert=True
                )
                db.actions.insert_one({
                    "timestamp": datetime.now(timezone.utc),
                    "type": "BLOCAGE", "ip": ip,
                    "source": "admin_chat", "succes": True,
                    "raison": "blocage manuel admin"
                })
                return f"✅ IP {ip} bloquée manuellement. Règle nftables ajoutée."
            else:
                return f"❌ Erreur firewall : {r.text}"
        except Exception as e:
            return f"❌ Firewall injoignable : {e}"

    # ── Whitelist ─────────────────────────────────────────────────────────────
    if action == "whitelist" and ip:
        db.whitelist.update_one(
            {"ip": ip},
            {"$set": {"ip": ip, "ajoute_par": "admin_chat",
                       "raison": message, "date_ajout": datetime.now(timezone.utc)}},
            upsert=True
        )
        return f"✅ IP {ip} ajoutée à la whitelist permanente."

    # ── Question générale → LLM ───────────────────────────────────────────────
    contexte = get_context_mongodb()
    prompt = f"""{contexte}
Question de l'administrateur : {message}
Réponds en français de manière concise et utile."""
    return ask_ollama(prompt)


@app.route("/")
def index():
    return render_template("chat.html")


@app.route("/chat", methods=["POST"])
def chat():
    data    = request.get_json()
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"response": "Message vide."})

    intention = detecter_intention(message)
    reponse   = executer_action(intention, message)

    # Logger dans MongoDB
    db.admin_chat.insert_one({
        "timestamp": datetime.now(timezone.utc),
        "message":   message,
        "intention": intention.get("action"),
        "reponse":   reponse
    })

    return jsonify({"response": reponse})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
