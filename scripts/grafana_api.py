#!/usr/bin/env python3
"""
API Flask — Bridge MongoDB → Grafana
Expose les données Cowrie en JSON pour Grafana Infinity datasource
"""

from flask import Flask, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime, timezone
import re

app = Flask(__name__)
CORS(app)

# ─── Config (Nettoyée pour GitHub) ─────────────────────────────────────────
MONGO_URI = "mongodb://cowrie_user:VOTRE_MOT_DE_PASSE_BDD_ICI@127.0.0.1:27017/cowrie"
client = MongoClient(MONGO_URI)
db = client["cowrie"]

def serialize(doc):
    """Convertit les types MongoDB en types JSON sérialisables."""
    if isinstance(doc, dict):
        return {k: serialize(v) for k, v in doc.items() if k != '_id'}
    elif isinstance(doc, list):
        return [serialize(i) for i in doc]
    elif isinstance(doc, datetime):
        return doc.strftime("%Y-%m-%d %H:%M:%S")
    else:
        return doc

# ─── Endpoints ──────────────────────────────────────────────────────────────

@app.route('/health')
def health():
    return jsonify({"status": "ok"})

@app.route('/sessions')
def sessions():
    """Toutes les sessions SSH récentes."""
    data = list(db.sessions.find(
        {},
        {"src_ip":1, "dst_port":1, "timestamp":1,
         "starttime":1, "endtime":1, "sshversion":1}
    ).sort("timestamp", -1).limit(500))
    return jsonify(serialize(data))

@app.route('/sessions/stats')
def sessions_stats():
    """Connexions SSH groupées par heure."""
    pipeline = [
        {"$group": {
            "_id": {"$dateToString": {
                "format": "%Y-%m-%d %H:00",
                "date": {"$toDate": {"$multiply": ["$time", 1000]}}
            }},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}},
        {"$limit": 48}
    ]
    data = list(db.sessions.aggregate(pipeline))
    return jsonify([{"heure": d["_id"], "connexions": d["count"]} for d in data])

@app.route('/top_ips')
def top_ips():
    """Top 20 IPs les plus actives."""
    pipeline = [
        {"$group": {
            "_id": "$src_ip",
            "nb_connexions": {"$sum": 1},
            "derniere_vue": {"$max": "$timestamp"}
        }},
        {"$sort": {"nb_connexions": -1}},
        {"$limit": 20}
    ]
    data = list(db.sessions.aggregate(pipeline))
    return jsonify([{
        "ip": d["_id"],
        "connexions": d["nb_connexions"],
        "derniere_vue": serialize(d["derniere_vue"])
    } for d in data])

@app.route('/commands')
def commands():
    """Top commandes exécutées."""
    pipeline = [
        {"$match": {"eventid": "cowrie.command.input"}},
        {"$group": {
            "_id": "$input",
            "count": {"$sum": 1}
        }},
        {"$sort": {"count": -1}},
        {"$limit": 20}
    ]
    data = list(db.input.aggregate(pipeline))
    return jsonify([{"commande": d["_id"], "count": d["count"]} for d in data])

@app.route('/auth/attempts')
def auth_attempts():
    """Tentatives d'authentification récentes."""
    data = list(db.auth.find(
        {"eventid": "cowrie.login.failed"},
        {"src_ip":1, "username":1, "password":1, "timestamp":1}
    ).sort("timestamp", -1).limit(200))
    return jsonify(serialize(data))

@app.route('/auth/stats')
def auth_stats():
    """Stats globales d'authentification."""
    total = db.auth.count_documents({})
    echecs = db.auth.count_documents({"eventid": "cowrie.login.failed"})
    succes = db.auth.count_documents({"eventid": "cowrie.login.success"})
    return jsonify({
        "total": total,
        "echecs": echecs,
        "succes": succes
    })

@app.route('/ip_scores')
def ip_scores():
    """Scores de risque de toutes les IPs."""
    data = list(db.ip_scores.find(
        {},
        {"ip":1, "score":1, "categorie":1,
         "statut":1, "nb_tentatives":1, "derniere_mise_a_jour":1}
    ).sort("score", -1))
    return jsonify(serialize(data))

@app.route('/ip_scores/bloques')
def ip_scores_bloques():
    """IPs actuellement bloquées."""
    data = list(db.ip_scores.find(
        {"statut": "bloquee"},
        {"ip":1, "score":1, "nb_tentatives":1, "derniere_mise_a_jour":1}
    ).sort("score", -1))
    return jsonify(serialize(data))

@app.route('/ip_scores/stats')
def ip_scores_stats():
    """Compteurs par catégorie."""
    return jsonify({
        "total":      db.ip_scores.count_documents({}),
        "normales":   db.ip_scores.count_documents({"categorie": "normal"}),
        "suspectes":  db.ip_scores.count_documents({"categorie": "suspect"}),
        "malveillantes": db.ip_scores.count_documents({"categorie": "malveillant"}),
        "bloquees":   db.ip_scores.count_documents({"statut": "bloquee"}),
        "whitelist":  db.whitelist.count_documents({})
    })

@app.route('/decisions')
def decisions():
    """Journal des décisions du LLM."""
    data = list(db.decisions.find(
        {},
        {"timestamp":1, "ip":1, "decision":1,
         "score_apres":1, "confiance":1, "raisonnement":1}
    ).sort("timestamp", -1).limit(100))
    return jsonify(serialize(data))

@app.route('/actions')
def actions():
    """Journal des actions réseau (blocages/déblocages)."""
    data = list(db.actions.find(
        {},
        {"timestamp":1, "type":1, "ip":1,
         "source":1, "succes":1, "raison":1}
    ).sort("timestamp", -1).limit(100))
    return jsonify(serialize(data))

@app.route('/faux_positifs')
def faux_positifs():
    """Faux positifs signalés."""
    data = list(db.faux_positifs.find(
        {},
        {"timestamp":1, "ip":1, "raison":1, "action":1}
    ).sort("timestamp", -1).limit(50))
    return jsonify(serialize(data))

@app.route('/whitelist')
def whitelist():
    """IPs en liste blanche."""
    data = list(db.whitelist.find(
        {},
        {"ip":1, "raison":1, "date_ajout":1, "ajoute_par":1}
    ).sort("date_ajout", -1))
    return jsonify(serialize(data))

@app.route('/summary')
def summary():
    """Résumé global pour le dashboard."""
    return jsonify({
        "total_sessions":    db.sessions.count_documents({}),
        "total_commandes":   db.input.count_documents({"eventid": "cowrie.command.input"}),
        "total_tentatives":  db.auth.count_documents({}),
        "ips_uniques":       len(db.sessions.distinct("src_ip")),
        "ips_bloquees":      db.ip_scores.count_documents({"statut": "bloquee"}),
        "faux_positifs":     db.faux_positifs.count_documents({}),
        "whitelist":         db.whitelist.count_documents({})
    })

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
