#!/usr/bin/env python3
"""
telegram.py — Alertes Telegram pour le daemon IA
"""

import requests
import logging

log = logging.getLogger(__name__)

# Remplacé par des valeurs génériques pour la sécurité du dépôt public
BOT_TOKEN = "8625041210:AAH_VOTRE_TOKEN_BOT_TELEGRAM_ICI"
CHAT_ID   = "123456789"
API_URL   = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

def envoyer(message: str) -> bool:
    """Envoie un message Telegram."""
    try:
        r = requests.post(
            API_URL,
            json={"chat_id": CHAT_ID, "text": message, "parse_mode": "HTML"},
            timeout=10
        )
        return r.status_code == 200
    except Exception as e:
        log.error(f"Telegram erreur : {e}")
        return False


def alerte_blocage(ip: str, score: float, explication: str):
    """Alerte quand une IP est bloquée automatiquement."""
    msg = (
        f"🚨 <b>IP BLOQUÉE AUTOMATIQUEMENT</b>\n\n"
        f"🔴 IP : <code>{ip}</code>\n"
        f"📊 Score : <b>{score:.0f}/100</b>\n"
        f"🤖 Analyse : {explication}\n\n"
        f"✅ Règle nftables appliquée sur VM Firewall"
    )
    envoyer(msg)


def alerte_surveillance(ip: str, score: float, explication: str):
    """Alerte quand une IP passe en surveillance."""
    msg = (
        f"⚠️ <b>IP SUSPECTE DÉTECTÉE</b>\n\n"
        f"🟡 IP : <code>{ip}</code>\n"
        f"📊 Score : <b>{score:.0f}/100</b>\n"
        f"🤖 Analyse : {explication}\n\n"
        f"👁️ Surveillance active — pas encore bloquée"
    )
    envoyer(msg)


def alerte_demarrage():
    """Alerte au démarrage du daemon."""
    envoyer(
        "🟢 <b>Cowrie IDS démarré</b>\n"
        "Le daemon de détection SSH est opérationnel.\n"
        "Surveillance active 24/7 🛡️"
    )


if __name__ == "__main__":
    print("Test Telegram...")
    ok = envoyer("🧪 Test depuis telegram.py — système opérationnel")
    print("✅ Envoyé" if ok else "❌ Erreur")
