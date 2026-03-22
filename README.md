# 🛡️ Plateforme SOC – SOAR & Veille CTI (Environnement Assurantiel Simulé)

> Projet de simulation d'un SOC de groupe assurantiel intégrant un SIEM (Wazuh), un moteur d'automatisation SOAR (Shuffle) et un module de veille Cyber Threat Intelligence (CTI) développé en Python.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      PLATEFORME SOC SIMULÉE                             │
│                                                                         │
│   [Scripts Python/PS]  ──logs──►  [Wazuh SIEM]  ──alertes──►  [Shuffle SOAR] │
│   (Générateur d'incidents)        (Détection)               (Playbooks)  │
│                                       │                          │       │
│                                  [Module CTI]                [Rapports]  │
│                              (APIs: OTX, AbuseIPDB)        (Markdown/PDF)│
└─────────────────────────────────────────────────────────────────────────┘
```

## 📁 Structure du Projet

```
.
├── docker-compose.yml        # Orchestration Wazuh + Shuffle
├── config/                   # Configurations Wazuh (règles, décodeurs)
│   ├── wazuh/
│   └── shuffle/
├── scripts/                  # Simulateurs d'incidents
│   ├── simulators/           # Générateurs de logs (Python, PowerShell)
│   └── cti/                  # Module de Veille CTI (Python)
├── playbooks/                # Playbooks SOAR Shuffle (JSON/YAML)
│   ├── phishing/
│   ├── ransomware/
│   └── account_compromise/
├── reports/                  # Rapports d'incidents générés
│   ├── templates/
│   └── generated/
└── docs/                     # Documentation SOC (SOP, Architecture)
```

## 🚀 Démarrage Rapide

### Prérequis
- Docker Desktop (Windows)
- Python 3.10+
- Git

### Lancement de l'Infrastructure

```bash
# Cloner le dépôt
git clone <repo_url>
cd soc-platform

# Démarrer Wazuh + Shuffle
docker-compose up -d

# Installer les dépendances Python
pip install -r requirements.txt
```

### Accès aux Interfaces

| Service | URL | Identifiants par défaut |
|---|---|---|
| Wazuh Dashboard | https://localhost:443 | admin / SecretPassword1 |
| Shuffle SOAR | http://localhost:3001 | admin@example.com / password |

### Simuler un Incident

```bash
# Simuler une attaque Ransomware
python scripts/simulators/ransomware_sim.py

# Simuler un Phishing
python scripts/simulators/phishing_sim.py

# Simuler une compromission de compte
python scripts/simulators/account_compromise_sim.py
```

## 🎯 Scénarios d'Incidents Couverts

| Scénario | Tactique MITRE ATT&CK | Playbook SOAR |
|---|---|---|
| Ransomware | T1486 - Data Encrypted for Impact | Isolation + Alerte Crise |
| Spear-Phishing | T1566.001 - Spearphishing Attachment | Suppression Email + Reset MDP |
| Compromission VIP | T1078 - Valid Accounts (Impossible Travel) | Blocage IP + Alerte N1/N2 |

## 📊 Module CTI

Le module de veille CTI interroge automatiquement :
- **AlienVault OTX** : Réputation IP/Domaine/Hash
- **AbuseIPDB** : Score de réputation des IPs
- **VirusTotal** : Analyse de Hash (mode gratuit)

## 📄 Licence

Usage éducatif – Projet de stage en cybersécurité.
