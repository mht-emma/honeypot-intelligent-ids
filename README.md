# 🐝 CyberHive

Système intelligent de détection et de réponse aux attaques SSH, basé sur un honeypot et l'intelligence artificielle.

**Projet de Fin d'Année — Filière Cybersécurité et Infrastructure Réseau (4IIR)**
**EMSI Casablanca — Année universitaire 2025-2026**

Réalisé par **Taha Anibar** & **Mahammat Emma Aboubakar**
Encadrant pédagogique : **M. Chiba**

---

## 📌 Description

CyberHive est une infrastructure distribuée de détection et de blocage automatique des intrusions SSH, pensée pour les PME marocaines qui n'ont ni le budget ni l'équipe pour s'offrir un SOC managé classique.

Le système combine :

- un **honeypot SSH (Cowrie)** qui piège l'attaquant et capture sa session en détail ;
- un **module d'intelligence artificielle à deux étages** — un classifieur Random Forest qui calcule un score de criticité comportementale, et un LLM local (Ollama / Llama 3.2) qui traduit ce score en explication lisible pour un opérateur ;
- un **pare-feu programmable (nftables)** qui isole l'IP attaquante dès que le score dépasse un seuil critique ;
- une **restitution multicanal** : tableau de bord Grafana, bot Telegram (« Jarvis »), interface web d'administration.

Le système ne distingue pas un trafic « légitime » d'un trafic « malveillant » au sens classique : toute connexion au honeypot est par construction suspecte. Le rôle du modèle est d'évaluer la sévérité du comportement observé, pour décider si l'attaquant doit être bloqué immédiatement ou simplement surveillé.

---

## 🏗️ Architecture technique

```
Internet / VM Kali (attaquant)
        │  SSH :22
        ▼
VM Firewall — nftables + API REST Flask (:5002, auth par token)
        │  DNAT : port 22 → port 2222
        ▼
VM Cowrie — Honeypot + stack analytique
 ├─ Cowrie SSH Honeypot          :2222
 ├─ MongoDB 7.0 (persistance)    :27017
 ├─ Daemon IA (cycle 30s)
 │   ├─ Random Forest (model.pkl) — scoring 0-100
 │   └─ Ollama / Llama 3.2 (1B)  — explication en langage naturel
 ├─ API Flask → Grafana          :5000
 ├─ API Flask → Chat admin       :5001
 └─ Grafana (dashboard)          :3000
        │
        ▼
Telegram Bot « Jarvis » — alerte si score > 70

VM SSH légitime (port 2224) — accès admin réel, hors chemin du honeypot
```

Les 4 machines virtuelles (Ubuntu 22.04) sont interconnectées via un réseau privé chiffré **ZeroTier**, ce qui évite d'avoir à gérer des tunnels SSH manuels entre elles.

> ℹ️ Le score de risque est recalculé toutes les 30 secondes pour chaque IP active. Une fois le seuil de 70/100 dépassé, la propagation de la règle de blocage vers nftables prend moins de 3 secondes. En pire cas (détection juste après un cycle de scoring), le délai total entre la première intrusion et le blocage effectif peut atteindre ~50 secondes.

---

## 🛠️ Stack technique

| Composant | Technologie | Rôle |
|---|---|---|
| Honeypot | Cowrie (installé depuis les sources Git) | Émulation SSH interactive, capture des sessions et des TTY logs |
| Conteneurisation | Docker | Isolation du honeypot par rapport à l'hôte |
| Persistance | MongoDB 7.0 | Stockage des sessions, authentifications, commandes, ttylogs |
| Machine learning | scikit-learn — Random Forest (200 estimateurs) | Scoring comportemental [0-100] |
| LLM local | Ollama + Llama 3.2 (1B) | Génération d'explications en langage naturel, 100 % local |
| API / backend | Flask (Python) | Endpoints REST : pare-feu, alimentation Grafana, chat admin |
| Pare-feu | nftables | DNAT + liste de blocage dynamique, sur VM dédiée |
| Supervision | Grafana 10.x | Tableaux de bord temps réel (dashboard exporté en JSON) |
| Alerting | API Telegram Bot (« Jarvis ») | Notifications instantanées |
| Réseau | ZeroTier | Réseau privé virtuel chiffré entre les 4 VMs |
| Tests d'intrusion | Kali Linux — Hydra, Nmap | Génération de trafic d'attaque contrôlé pour validation |

---

## 📊 Fonctionnalités principales

- Capture passive des sessions SSH (authentification, commandes saisies, flux binaires de terminal).
- Évaluation comportementale périodique (cycle de 30 s) plutôt qu'une analyse événement par événement.
- Explication en langage naturel des décisions de scoring, via le module LLM local.
- Blocage automatique au niveau noyau dès que le score dépasse 70/100.
- Interface conversationnelle d'administration : whitelist, levée de faux positifs, état du système.
- Génération de rapports d'IOC (indicateurs de compromission) à partir des sessions capturées.

---

## 🗂️ Structure du dépôt

```
cyberhive/
├── cowrie/
│   └── cowrie.cfg                 ← configuration et durcissement du honeypot
├── grafana/
│   └── cowrie-ids-dashboard.json  ← dashboard exporté (dashboard-as-code)
├── ia/
│   ├── daemon.py                  ← boucle d'analyse (cycle 30 s)
│   ├── features.py                ← extraction des variables comportementales depuis MongoDB
│   ├── scorer.py                  ← inférence Random Forest
│   ├── llm.py                     ← intégration Ollama / prompt engineering
│   ├── telegram_alert.py          ← notifications vers le bot Jarvis
│   ├── train_model.py             ← (ré)entraînement du modèle
│   └── generate_dataset.py        ← génération du jeu de données d'entraînement
├── scripts/
│   ├── grafana_api.py             ← endpoint d'alimentation Grafana (:5000)
│   ├── chat.py                    ← backend de la console conversationnelle (:5001)
│   ├── firewall_api.py            ← API du pare-feu, sur la VM dédiée (:5002)
│   └── ioc_extractor.py           ← génération des rapports d'IOC
├── samples/
│   ├── cowrie_sample.json         ← sessions anonymisées, à titre d'exemple
│   └── ioc_report.json            ← rapport d'IOC généré
└── docs/
    ├── mongodb_schema.md          ← schéma des collections MongoDB
    ├── ia_logs_sample.txt         ← exemple de sortie du module IA
    └── screenshots/               ← captures d'écran de validation
```

> 📝 **État réel de la documentation** (à la date de rédaction de ce README) : seuls ce README et `docs/mongodb_schema.md` constituent une documentation à jour. Un guide d'installation détaillé, une documentation formelle de l'API pare-feu et un journal des bugs structuré sont prévus mais pas encore rédigés en tant que documents séparés — la section Installation ci-dessous fait office de guide de démarrage en attendant.

---

## ⚙️ Installation

### Prérequis

- 4 machines virtuelles Ubuntu 22.04 (ou équivalent), reliées par un réseau ZeroTier commun
- Python 3.8+ sur la VM Cowrie
- Docker sur la VM Cowrie (pour le conteneur honeypot)
- Accès root sur la VM Firewall (pour nftables)
- Un token de bot Telegram et l'identifiant du chat de destination

### 1. Réseau ZeroTier

```bash
curl -s https://install.zerotier.com | sudo bash
sudo zerotier-cli join <NETWORK_ID>
# autoriser chaque VM depuis my.zerotier.com, puis vérifier :
zerotier-cli listpeers
```

### 2. VM Cowrie — honeypot

```bash
git clone https://github.com/cowrie/cowrie.git
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install -r requirements.txt
cp ../cyberhive/cowrie/cowrie.cfg etc/cowrie.cfg
bin/cowrie start
```

### 3. MongoDB

```bash
sudo apt install -y mongodb-org
sudo systemctl enable --now mongod
# créer la base et l'utilisateur applicatif dédié avant de lancer le daemon IA
```

### 4. Module IA

```bash
cd cyberhive/ia
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# installer Ollama et récupérer le modèle local
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:1b

python3 train_model.py     # entraîne et sérialise le modèle (model.pkl)
python3 daemon.py          # lance la boucle d'analyse (cycle 30 s)
```

### 5. APIs Flask (Grafana, chat admin, pare-feu)

```bash
# sur la VM Cowrie
python3 scripts/grafana_api.py     # :5000
python3 scripts/chat.py            # :5001

# sur la VM Firewall (privilèges restreints via sudoers à la commande nft uniquement)
python3 scripts/firewall_api.py    # :5002
```

### 6. Grafana

```bash
sudo apt install -y grafana
sudo systemctl enable --now grafana-server
# importer grafana/cowrie-ids-dashboard.json depuis l'interface web (:3000)
# configurer la source de données JSON pointant vers l'API :5000
```

### 7. Alertes Telegram

```bash
export TELEGRAM_BOT_TOKEN="<token>"
export TELEGRAM_CHAT_ID="<chat_id>"
```

### 8. Pare-feu (VM Firewall)

```bash
sudo nft add table inet filter
sudo nft add set inet filter blocklist '{ type ipv4_addr; }'
sudo nft add chain inet filter input '{ type filter hook input priority 0; }'
sudo nft add rule inet filter input ip saddr @blocklist drop
```

---

## 📸 Captures d'écran

Les captures de validation de l'environnement de production SOC sont répertoriées ci-dessous :

1. Vue d'ensemble du tableau de bord Grafana
2. Suivi des scores de risque et des IP bloquées
3. Alertes Telegram (bot Jarvis) reçues en temps réel
4. Interface de chat administrateur (LLM)

---

## 🧪 Tests

La validation fonctionnelle repose sur des scénarios d'attaque simulés depuis une VM Kali (Hydra pour la force brute SSH, Nmap pour le scan), ainsi que sur des tests unitaires des fonctions de scoring. Le détail des cas de test, des résultats obtenus et des deux bugs corrigés en cours de développement (sérialisation binaire MongoDB côté Cowrie, absence de connecteur Grafana-MongoDB stable) est documenté dans le rapport de PFA, chapitre Réalisation et Implémentation.

---

## 🗺️ Roadmap

- **V1 (en cours)** — MVP : honeypot, scoring IA, blocage automatique, dashboard, alertes. Livraison visée : 30 juin 2026.
- **V2** — Validation terrain auprès de PME pilotes, migration vers un hébergement cloud en production, mise en conformité réglementaire (CNDP), premiers clients payants.
- **V3** — Extension géographique, montée en gamme Enterprise, distribution via des partenaires IT locaux.

---

## 👥 Auteurs

- **Taha Anibar** — lead technique, infrastructure et pare-feu
- **Mahammat Emma Aboubakar** — module IA, intégration et tests
- Encadrant pédagogique : **M. Chiba** — EMSI Casablanca

---

## 📄 Licence

Projet académique réalisé dans le cadre d'un Projet de Fin d'Année à l'EMSI Casablanca. Licence à définir avant toute diffusion publique du dépôt.
