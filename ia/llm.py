import requests
import json

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL      = "llama3.2:1b"


def ask_llm(features: dict, score_rf: float) -> dict:
    """
    Analyse une IP avec le LLM.
    La DECISION est basee sur le score RF (fiable).
    Le LLM genere uniquement l'explication en français.

    Args:
        features : features calculees depuis MongoDB
        score_rf : score Random Forest [0-100]

    Returns:
        dict avec score_llm, categorie, confiance, action, explication
    """
    ip = features.get("ip", "inconnue")

    # Determiner la categorie depuis le score RF
    if score_rf >= 70:
        categorie = "malveillante"
    elif score_rf >= 30:
        categorie = "suspecte"
    else:
        categorie = "normale"

    # Prompt ultra-court — LLM genere uniquement l'explication
    prompt = f"""Tu es un expert en cybersécurité défensive gérant un honeypot SSH légal.
Analyse cette IP suspecte et donne ta décision.

IP : {ip}
Score de menace : {score_rf}/100
Nombre de tentatives : {features.get('nb_tentatives', 0)}
Nombre de sessions : {features.get('nb_sessions', 0)}
Commandes tapées : {features.get('nb_commandes', 0)}
Catégorie RF : {categorie}

Réponds UNIQUEMENT en JSON valide :
{{"decision": "BLOQUER" ou "SURVEILLER", "explication": "ta raison en français", "confiance": 0-100}}"""

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.0,
            "num_predict": 80
        }
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=(30, 120)
        )
        if response.status_code != 200:
            return _decision_rf(score_rf, "")

        raw = response.json().get("response", "")
        explication = _parse_explication(raw)
        return _decision_rf(score_rf, explication)

    except Exception as e:
        return _decision_rf(score_rf, "")


def _parse_explication(output: str) -> str:
    """Extrait uniquement l'explication du JSON retourné par le LLM."""
    try:
        start = output.find("{")
        end   = output.rfind("}")
        if start == -1 or end == -1:
            return ""
        data = json.loads(output[start:end + 1])
        return str(data.get("explication", ""))
    except Exception:
        # Si parsing echoue, retourner le texte brut nettoyé
        clean = output.strip().replace('"', '').replace('{', '').replace('}', '')
        return clean[:150] if clean else ""


def _decision_rf(score_rf: float, explication: str) -> dict:
    """
    Décision finale basée sur le score RF.
    Le LLM ne prend pas la décision — il explique uniquement.
    """
    if score_rf >= 70:
        action    = "BLOQUER"
        categorie = "malveillant"
    elif score_rf >= 30:
        action    = "SURVEILLER"
        categorie = "suspect"
    else:
        action    = "IGNORER"
        categorie = "normal"

    return {
        "score_llm":   int(score_rf),
        "categorie":   categorie,
        "confiance":   90,
        "action":      action,
        "explication": explication or f"Score RF {int(score_rf)}/100 — decision automatique basee sur le modele ML."
    }


def test_connexion() -> bool:
    """Vérifie qu'Ollama est accessible."""
    try:
        r = requests.get(
            "http://127.0.0.1:11434/api/tags",
            timeout=5
        )
        return r.status_code == 200
    except Exception:
        return False


# ─── Test ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":

    print("Test connexion Ollama...")
    if not test_connexion():
        print("Ollama non accessible")
        exit(1)
    print("Ollama OK\n")

    # IP malveillante — brute force evident
    print("Test IP malveillante (brute force)...")
    features_attaque = {
        "ip":                   "192.168.172.1",
        "nb_sessions":          5,
        "nb_tentatives_auth":   150,
        "nb_passwords_uniques": 80,
        "nb_usernames_uniques": 3,
        "duree_moyenne":        2.5,
        "frequence_par_min":    75.0,
        "nb_commandes":         4,
        "commandes_sensibles":  2,
        "succes_auth":          1
    }
    r1 = ask_llm(features_attaque, score_rf=87.0)
    print(json.dumps(r1, indent=2, ensure_ascii=False))

    # IP normale — connexion legitime
    print("\nTest IP normale (connexion legitime)...")
    features_normal = {
        "ip":                   "192.168.172.50",
        "nb_sessions":          1,
        "nb_tentatives_auth":   2,
        "nb_passwords_uniques": 1,
        "nb_usernames_uniques": 1,
        "duree_moyenne":        45.0,
        "frequence_par_min":    0.1,
        "nb_commandes":         8,
        "commandes_sensibles":  0,
        "succes_auth":          1
    }
    r2 = ask_llm(features_normal, score_rf=12.0)
    print(json.dumps(r2, indent=2, ensure_ascii=False))

    # IP suspecte — milieu
    print("\nTest IP suspecte (milieu)...")
    features_suspect = {
        "ip":                   "192.168.172.99",
        "nb_sessions":          3,
        "nb_tentatives_auth":   25,
        "nb_passwords_uniques": 12,
        "nb_usernames_uniques": 2,
        "duree_moyenne":        8.0,
        "frequence_par_min":    8.0,
        "nb_commandes":         2,
        "commandes_sensibles":  1,
        "succes_auth":          0
    }
    r3 = ask_llm(features_suspect, score_rf=55.0)
    print(json.dumps(r3, indent=2, ensure_ascii=False))
