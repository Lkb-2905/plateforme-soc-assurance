# 🌍 DOSSIER DE CONFIGURATION D'EXPLOITATION (DCE)

## ⚡ PLATEFORME SOC — SIEM Python · SOAR Automatisé · Threat Intelligence · Microsoft Sentinel · Dashboard Exécutif

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/FastAPI-Mock%20EDR-009688?style=for-the-badge&logo=fastapi&logoColor=white"/>
  <img src="https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white"/>
  <img src="https://img.shields.io/badge/Microsoft%20Sentinel-Azure%20Cloud-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white"/>
  <img src="https://img.shields.io/badge/Sigma%20Rules-YAML%20Standards-yellow?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-T1486%20%7C%20T1566%20%7C%20T1078-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/AlienVault%20OTX-Threat%20Intel-00ADEF?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/CISA%20KEV-Live%20Feed-blue?style=for-the-badge"/>
  <img src="https://github.com/Lkb-2905/plateforme-soc-assurance/actions/workflows/test_playbooks.yml/badge.svg" alt="SOC CI/CD Status"/>
</p>

> ⚠️ **NB IMPORTANT :** Il s'agit d'un projet **personnel/étudiant**. Le contexte assurantiel est utilisé uniquement pour donner un cadre d'entreprise réaliste à cette simulation. Aucune donnée réelle ou privée n'est exploitée. Tous les événements, logs, adresses IP et rapports sont entièrement fictifs.

---

**Version :** `4.0.0 Enterprise` &nbsp;|&nbsp; **Date :** Mars 2026 &nbsp;|&nbsp; **Auteur :** KAMENI TCHOUATCHEU GAETAN BRUNEL
**Contact :** [gaetanbrunel.kamenitchouatcheu@et.esiea.fr](mailto:gaetanbrunel.kamenitchouatcheu@et.esiea.fr)

---

## 📋 TABLE DES MATIÈRES

1. [🎯 Vue d'ensemble](#-vue-densemble-du-projet)
2. [🏗️ Architecture Globale](#-architecture-du-projet)
3. [📈 Scénarios d'Incidents & Playbooks SOAR](#-scénarios-dincidents--playbooks-soar)
4. [📊 Fonctionnalités Clés & Dashboard](#-fonctionnalités-clés--dashboard-exécutif)
5. [📡 Module CTI Open-Source](#-module-cti-open-source)
6. [⚖️ Scoring Assurantiel & Compliance RGPD](#️-scoring-assurantiel--compliance-rgpd)
7. [☁️ Module Cloud — Microsoft Sentinel & Sigma Rules](#️-module-cloud--microsoft-sentinel--sigma-rules)
8. [🌪️ Défis & Intempéries Rencontrées](#️-défis--intempéries-rencontrées)
9. [🛠️ Technologies Utilisées](#️-technologies-utilisées)
10. [🚀 Guide d'Installation & Run Book](#-guide-dinstallation--run-book)
11. [✨ Qualité & Best Practices](#-qualité--best-practices)
12. [🗺️ Roadmap & Évolutions](#️-roadmap--évolutions)

---

## 🎯 Vue d'ensemble du Projet

### Contexte & Objectifs

Ce projet est un **démonstrateur complet d'ingénierie Cybersécurité** orienté Détection et Réponse à Incident. Il simule une plateforme SOC de bout-en-bout : depuis la génération de logs d'attaques, leur détection par un moteur SIEM basé sur MITRE ATT&CK, jusqu'à l'éradication automatisée de la menace par un moteur SOAR interagissant avec de vraies APIs d'entreprise simulées (EDR, Active Directory, Messagerie).

| Dimension | Ce que ça démontre |
| :--- | :--- |
| **Détection (SIEM)** | Moteur d'analyse de logs Python avec règles de corrélation inspirées du standard Sigma |
| **Automatisation (SOAR)** | Playbooks Python faisant de vrais appels HTTP de remédiation (Isolation réseau, Reset MDP, Révocation token AD) |
| **Mocking d'Infrastructure** | Serveur FastAPI simulant EDR / Active Directory / Messagerie — prêt à brancher sur de vrais outils |
| **Threat Intelligence (CTI)** | Interrogation en direct de l'API AlienVault OTX et des bulletins gouvernementaux CISA KEV |
| **Case Management** | Export structuré au format JSON TheHive avec Observables, Tasks et Custom Fields |
| **Compliance Assurantielle** | Scoring du risque métier (contrats exposés, RGPD, délai CNIL 72h) automatisé par playbook |
| **Tableau de Bord Exécutif** | Application Streamlit localhost affichant MTTD, MTTR, alertes CTI et rapports en temps réel |

---

## 🏗️ Architecture du Projet

> **Lecture du diagramme :** Le schéma ci-dessous représente l'**architecture de référence industrielle** (ce que ce projet deviendrait en production). Le tableau de correspondance qui suit explique comment chaque composant du schéma a été **implémenté ou substitué** dans ce démonstrateur Python.

<p align="center">
  <img src="soc_architecture_globale.svg" alt="Architecture de Référence SOC" width="850">
</p>

### Correspondance Architecture Cible ↔ Implémentation Réelle

| Couche SVG | Composant Industriel (Schéma) | ✅ Implémentation du Projet | Fichier(s) |
| :--- | :--- | :--- | :--- |
| **Couche 1** | Sources métier assurantielles | Simulateurs Python injectant des Payloads JSON réalistes | `scripts/simulators/` |
| **Couche 2** | Wazuh SIEM (Docker + Kibana) | **Moteur SIEM Python** avec règles de corrélation Sigma-like | `scripts/soc_engine.py` |
| **Couche 3 — CTI** | OpenCTI / MISP + CERT-FR | **AlienVault OTX** (API publique) + **CISA KEV** (Gouvernement US) | `scripts/cti/` |
| **Couche 3 — SOAR** | Shuffle SOAR / n8n | **SOAREngine Python** avec 3 Playbooks métier complets | `scripts/soc_engine.py` |
| **Couche 3 — ITSM** | ServiceNow (Ticket auto) | **Export TheHive JSON** (format ITSM standard SOC) | `scripts/generate_report.py` |
| **Couche 4** | Playbooks SOAR visuels | **Playbooks Python** appelant l'API Mock via HTTP | `scripts/soc_engine.py` |
| **Couche 5 — Dashboard** | Grafana / Kibana | **Streamlit** (Dashboard Web localhost interactif) | `scripts/dashboard_soc.py` |
| **Couche 5 — ATT&CK** | MITRE ATT&CK Navigator | **Layer JSON prêt à l'emploi** (14 techniques scorées) | `attck/coverage_layer.json` |

> 💡 **Pourquoi cette substitution ?** L'objectif est de prouver la **faisabilité technique complète** de chaque couche sans dépendances lourdes (Docker, licences). Chaque substitution est réversible : brancher le SIEM Python sur Wazuh ou le SOAR sur Shuffle ne demande qu'un changement de l'endpoint HTTP.

### Les 5 Couches de l'Implémentation

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  COUCHE 1 — SOURCES DE DONNÉES (Simulation assurantielle)   ┃
┃  [Portail Courtiers] [Gestion Sinistres] [AD/IAM] [Firewall]┃
┗━━━━━━━━━━━━━━━━━━━━━┫ Payloads JSON ┣━━━━━━━━━━━━━━━━━━━━━━┛
                              ┃
                              ▼
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  COUCHE 2 — SIEM Python  [= Wazuh en production]            ┃
┃  • Parsing des logs • Règles de corrélation MITRE ATT&CK    ┃
┃  • Détection Bruteforce (fréquence) • Génération d'Alertes  ┃
┗━━━━┫ Alerte ┣━━━━━━━━━━━━━━━┫ CTI OTX ┣━━━━━━━━━━━━━━━━━━━┛
          ┃                             ┃
          ▼                             ▼
┏━━━━━━━━━━━━━━━━━┓   ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  COUCHE 3A      ┃   ┃  COUCHE 3B — SOAR  [= Shuffle SOAR] ┃
┃  CTI / OTX      ┃   ┃  • Playbook Ransomware T1486         ┃
┃  CISA KEV       ┃↔┃  • Playbook Phishing T1566            ┃
┃  IOC Lookup     ┃   ┃  • Playbook Compromission IAM T1078  ┃
┗━━━━━━━━━━━━━━━━━┛   ┗━━━━━━━━━┫ HTTP POST ┣━━━━━━━━━━━━━━┛
                                         ┃
                                         ▼
                    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
                    ┃  COUCHE 4 — API MOCK (FastAPI)  ┃
                    ┃  [= CrowdStrike / Okta / M365]  ┃
                    ┃  :8080  EDR | AD/IAM | Mail GW  ┃
                    ┗━━━━━━━━━━┫ 200 OK ┣━━━━━━━━━━━┛
                                         ┃
                                         ▼
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  COUCHE 5 — REPORTING & OBSERVABILITÉ  [= Grafana / Kibana] ┃
┃  [Rapport MD] [Ticket TheHive JSON] [Dashboard Streamlit]   ┃
┃  [MITRE ATT&CK Navigator]  [SOP]  [KPIs MTTD/MTTR]         ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

---


## 📈 Scénarios d'Incidents & Playbooks SOAR

Trois scénarios majeurs entièrement automatisés, contextualisés au secteur assurantiel :

| Scénario | Tactique MITRE ATT&CK | Actions Automatisées du Playbook SOAR |
| :--- | :--- | :--- |
| **🔴 Ransomware** | `T1486` — Data Encrypted for Impact | Isolement EDR (API POST) + Arrêt du partage réseau `/data/contrats/` + Alerte P1 RSSI/Cellule Crise |
| **🟠 Phishing / Spear-Phishing** | `T1566.001` — Spearphishing Link | Analyse de réputation URL via CTI OTX + Suppression du mail (API) + Reset MDP préventif |
| **🟡 Compromission de Compte (VIP)** | `T1078` — Valid Accounts / Impossible Travel | Révocation du token AD (API) + Enforce MFA + Notification niveau P1 + Audit Trail |

---

## 📊 Fonctionnalités Clés & Dashboard Exécutif

### Portail SOC de Supervision (Streamlit — Localhost)

*Dashboard Web interactif à deux onglets : Gestion des Incidents SOC d'un côté, Flux de Threat Intelligence de l'autre.*

<p align="center">
  <img src="Capture d'écran_23-3-2026_184310_localhost.jpeg" alt="SOC Executive Dashboard" width="900" style="border-radius:10px;">
</p>

> 📥 **[Télécharger le Rapport Exécutif Complet (Export PDF)](<SOC Executive Dashboard.pdf>)**

### 1. 🤖 Moteur SOAR Interactif (API EDR Mock)
Contrairement aux simulations classiques opérant avec de simples `print()`, ce SOAR utilise la librairie `requests` pour attaquer un serveur FastAPI local simulant un vrai EDR. Cela **prouve la viabilité totale des scripts en production** sur des outils comme CrowdStrike, SentinelOne ou Microsoft Defender. Un mécanisme de *fallback gracieux* évite tout crash si l'API est indisponible.

### 2. 🎫 Export Automatisé TheHive (Case Management)
À la fin de chaque exécution, le SOAR extrait tous les IOC (IPs, hashes, URLs), TLP, PAP et TTPs MITRE pour forger dynamiquement un ticket `.json` au format TheHive. Ce ticket contient les tâches structurées pour l'analyste N1/N2, les métriques de performance et les champs RGPD.

### 4. 🗺️ MITRE ATT&CK Navigator — Heatmap de Couverture
Le fichier [`attck/coverage_layer.json`](attck/coverage_layer.json) est un layer ATT&CK Navigator prêt à l'emploi. Il mappe toutes les techniques détectées avec leur niveau de couverture (score 0→100).

> **💡 Pour visualiser la heatmap :**
> 1. Ouvrir [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/)
> 2. Cliquer **"Open Existing Layer"** → **"Upload from local"**
> 3. Sélectionner `attck/coverage_layer.json`

| Technique | Tactique | Score |
| :--- | :--- | :--- |
| T1566 / T1566.001 | Initial Access — Phishing | 🔴 95/100 |
| T1486 | Impact — Ransomware | 🔴 90/100 |
| T1078 | Initial Access — Valid Accounts | 🔴 90/100 |
| T1110 | Credential Access — Bruteforce | 🟠 80/100 |
| T1190 | Initial Access — Exploit (CISA KEV) | 🟠 70/100 |

---

## 🤖 Intégration Continue (CI/CD DevSecOps)

Chaque `git push` sur la branche `main` déclenche automatiquement le pipeline **GitHub Actions** (`.github/workflows/test_playbooks.yml`) qui vérifie :
- ✅ L'importabilité de tous les modules Python (SIEM, SOAR, CTI, Dashboard)
- ✅ La présence et structure de tous les fichiers critiques
- ✅ La conformité du format JSON des rapports TheHive
- ✅ La validité du fichier MITRE ATT&CK Navigator

---

## 📡 Module CTI Open-Source

Le projet intègre deux connecteurs de renseignement sur les menaces en temps réel :

### 🌍 AlienVault OTX (`scripts/cti/otx_ioc_lookup.py`)
- Interroge l'API publique AlienVault Open Threat Exchange en direct.
- Analyse n'importe quel IOC (IP, domaine, hash) et retourne le nombre de **campagnes d'attaques mondiales** dans lesquelles il apparaît.
- Visualisé dans l'onglet CTI du Dashboard Streamlit avec code couleur Rouge/Vert.

### 🇺🇸 CISA KEV — Gouvernement US (`scripts/cti/cisa_kev_puller.py`)
- Télécharge en direct le catalogue des **Known Exploited Vulnerabilities** du CISA (Agence de Cybersécurité du gouvernement américain).
- Corrèle automatiquement les CVEs avec le **parc applicatif simulé du secteur assurantiel** (FortiOS, Exchange Server, Guidewire...).
- Génère une alerte si une faille activement exploitée par des ransomwares cible ton SI.

---

## ⚖️ Scoring Assurantiel & Compliance RGPD

Module critique et différenciant pour le secteur Assurance/Banque :

- **Calcul du risque métier** : Nombre de contrats potentiellement exposés par type d'incident.
- **Détection automatique de Fuite RGPD** : Le playbook SOAR évalue si les données compromises sont des données personnelles (santé, habitation, auto).
- **Notification CNIL obligatoire** : Si une fuite est confirmée, le ticket TheHive génère automatiquement la tâche `⚖️ Déclaration CNIL sous 72H`, respectant l'article 33 du RGPD.
- **KPIs de Performance SOC** : MTTD (Temps Moyen de Détection) et MTTR (Temps Moyen de Réponse) calculés et exposés dans le Dashboard et les tickets TheHive.

---

## 🌪️ Défis & Intempéries Rencontrées

La construction de cette plateforme sans Docker ni solutions pré-packagées a soulevé plusieurs complexités techniques :

- **Conflit d'Environnements Windows (Python) :** Windows interceptait les appels Python via une installation MinGW/MSYS64 dépourvue de `pip`. Résolution : forçage du chemin absolu de l'interpréteur `pyenv-win` pour garantir l'exécution propre du serveur FastAPI.

- **Compatibilité Pydantic v1 vs Python 3.12+ :** Le démarrage du serveur FastAPI crashait sur `TypeError: ForwardRef._evaluate() missing 1 required keyword-only argument`. Ce bug venait du changement de signature interne du cache de typage dans Python 3.12.4+. **Résolution :** Diagnostic à chaud et upgrade vers Pydantic v2.

- **Mocking d'orchestration réseau asynchrone :** Simuler le SOAR sans bloquer la boucle principale du SIEM au moment des appels HTTP externes nécessite une rigueur algorithmique stricte pour ne pas perdre les événements en attente dans la queue.

- **Gestion des exports en doublon :** L'exécution répétée du moteur générait des centaines de rapports quasi-identiques dans `reports/generated/`. Résolution : nettoyage automatisé et politique de rétention (1 rapport par type de scénario).

---

## ☁️ Module Cloud — Microsoft Sentinel & Sigma Rules

> Ce module élève le projet au niveau **Cloud-Native SOC** en intégrant une couche Azure réelle et les standards industriels de détection.

### 🔵 Microsoft Sentinel — Ingestion d'Alertes Cloud (`scripts/cloud/azure_sentinel_connector.py`)

- Connecteur Python vers **Azure Log Analytics REST API** avec authentification **HMAC-SHA256** (même mécanisme que les outils Microsoft enterprise).
- Envoie les alertes SOC directement dans un workspace **Microsoft Sentinel** (ou Log Analytics) réel.
- Compatible avec un **compte Azure Free Tier** (90 jours gratuits) — zéro Go logiciel à installer.
- Requête KQL pour visualiser les alertes : `SOC_SecurityEvents_CL | order by TimeGenerated desc`

```python
# Exemple d'utilisation
from scripts.cloud.azure_sentinel_connector import send_to_sentinel, build_soc_event

event = build_soc_event(
    incident_type   = "Ransomware",
    severity        = "Critical",
    source_ip       = "185.220.101.5",
    target_host     = "SRV-CONTRATS-01",
    mitre_tactic    = "Impact",
    mitre_technique = "T1486 - Data Encrypted for Impact",
    description     = "Chiffrement massif sur /data/contrats/ — EDR isolé",
)
send_to_sentinel([event])   # → Push vers Azure Sentinel via REST API
```

### 🟡 Sigma Rules YAML — Standard Industriel de Détection (`sigma_rules/`)

Les règles de détection du SIEM sont formalisées dans le standard **Sigma** (open-source, utilisable sur Splunk, Sentinel, QRadar, Elastic SIEM).

| Fichier | Tactique MITRE | Niveau | Cible |
| :--- | :--- | :--- | :--- |
| `phishing_detection.yml` | `T1566 / T1566.001` | 🔴 High | Proxy Web + M365 Defender |
| `ransomware_detection.yml` | `T1486 / T1490` | 🚨 Critical | Sysmon + Windows Security |
| `account_compromise_detection.yml` | `T1078 / T1110` | 🔴 High | Azure AD SignIn Logs |

### 🟢 Ingestion de Logs Réels Windows/Sysmon (`scripts/cloud/winlog_parser.py`)

- Parse des **logs Windows réels** (Event IDs standard : 4625, 4688, 4698, 1102...)
- Catalogue de **19 Event IDs critiques** annotés MITRE ATT&CK.
- Détection automatique des **indicateurs Ransomware** dans les lignes de commande.
- Export JSON au format Sentinel pour ingestion cloud.

```bash
# Analyser une séquence de Kill Chain Ransomware en logs Windows réels
python scripts/cloud/winlog_parser.py

# Envoyer les alertes vers Microsoft Sentinel
python scripts/cloud/azure_sentinel_connector.py
```

---

## 🛠️ Technologies Utilisées

| Composant | Technologie | Usage |
| :--- | :--- | :--- |
| **Core SIEM/SOAR** | Python 3.12+ | Moteur de détection, playbooks de remédiation, files d'attente d'événements |
| **API de Sécurité (Mock)** | FastAPI + Uvicorn | Simulation d'EDR / Active Directory / Messagerie corporate |
| **Dashboard Analytique** | Streamlit | Portail Web interactif avec onglets Incidents + CTI |
| **Threat Intelligence** | AlienVault OTX · CISA KEV | Enrichissement IOC et veille vulnérabilités en temps réel |
| **Cloud SIEM** | Microsoft Sentinel / Azure Log Analytics | Ingestion d'alertes SOC via REST API HMAC-SHA256 |
| **Détection Standard** | Sigma Rules YAML | Règles de détection portables (Splunk, Sentinel, QRadar, Elastic) |
| **Logs Réels** | Windows Event Log · Sysmon | Parsing + corrélation MITRE ATT&CK de logs Windows réels |
| **Reporting / Templates** | Jinja2 + Markdown | Rapports d'incident de niveau exécutif générés automatiquement |
| **Case Management** | JSON (Format TheHive) | Tickets structurés avec Custom Fields MTTD/MTTR/RGPD |
| **Documentation SOC** | Markdown (SOP) | Standard Operating Procedures selon les normes SOC de Groupe |

---

## 🚀 Guide d'Installation & Run Book

> 💡 **Pré-requis :** Python 3.10+ installé. Assurez-vous que la commande `python` pointe bien vers votre installation Python officielle, et non vers un sous-système (ex: Msys64/MinGW). En cas de doute, remplacez `python` par le chemin absolu de votre exécutable (ex: `C:\\...\\python.exe`).

### 📦 Étape 1 — Activation de l'environnement virtuel & Installation (une seule fois)

**Important :** Il est fortement recommandé d'utiliser l'environnement virtuel du projet. Sur Windows (avec PowerShell), activez-le avant toute chose :

```powershell
.\.venv\Scripts\Activate.ps1
```
*(En cas d'erreur de politique d'exécution, lancez d'abord : `Set-ExecutionPolicy Unrestricted -Scope Process`)*

Ensuite, installez les dépendances requises :

```bash
python -m pip install -r requirements.txt
```

### 🌐 Étape 2 — Démarrage de l'infrastructure de défense (Terminal 1)

L'API Mock simule les réponses HTTP de l'EDR, de l'Active Directory, et de la Gateway Mail.

```bash
python scripts/mock_edr_api.py
```
*Le serveur tourne sur `http://127.0.0.1:8080` — laissez ce terminal ouvert.*

### 🛡️ Étape 3 — Simulation & Mitigation des Incidents (Terminal 2)

Le SIEM détecte les attaques JSON, le SOAR applique les playbooks et déclenche l'isolation via l'API.

```bash
# Scénario 1 : Ransomware (Chiffrement massif / T1486)
python scripts/soc_engine.py --scenario ransomware

# Scénario 2 : Phishing Assurantiel (T1566.001)
python scripts/soc_engine.py --scenario phishing

# Scénario 3 : Compromission VIP / AD (T1078)
python scripts/soc_engine.py --scenario account_compromise
```

### 📊 Étape 4 — SOC Executive Dashboard (Terminal 3)

Visualisez les alertes, le reporting réglementaire et la Threat Intelligence en temps réel.

```bash
python -m streamlit run scripts/dashboard_soc.py
```
👉 *Ouvrez **`http://localhost:8501`** dans votre navigateur.*

<p align="center">
  <img src="Capture%20d%E2%80%99%C3%A9cran_25-3-2026_113845_localhost.jpeg" alt="Dashboard SOC Streamlit" width="850">
</p>

### ☁️ Étape 5 — Data Engineering Cloud & Sentinel (N'importe quel terminal)

Montrez l'ingestion de logs industriels réels et le transfert vers le Cloud via HMAC-SHA256 :

```bash
# 1. Ingestion & Corrélation depuis des logs Windows/Sysmon
python scripts/cloud/winlog_parser.py

# 2. Push Cloud via API REST Microsoft Sentinel
python scripts/cloud/azure_sentinel_connector.py
```

### 📡 Étape 6 — Threat Intelligence en ligne de commande (Bonus)

```bash
# Requête API publique OTX (AlienVault) sur une IP ciblée
python scripts/cti/otx_ioc_lookup.py

# Aspiration du catalogue de failles critiques CISA KEV
python scripts/cti/cisa_kev_puller.py
```

---

## ✨ Qualité & Best Practices

- **Ingénierie Logicielle :** Utilisation intensive des `dataclasses` Python pour modéliser précisément les objets de sécurité (Alerte, IOC, Observable, PlaybookAction).
- **Logging Professionnel :** `colorlog` avec niveaux de criticité lisibles par la supervision (DEBUG/INFO/WARNING/CRITICAL).
- **Dégradation Gracieuse :** Mode *Fail-Safe* sur tous les Playbooks — si l'API EDR est indisponible, le SOAR continue son exécution sans crash (`try/except` exhaustif).
- **Résilience CTI :** Les scripts de veille gèrent proprement les erreurs réseau (timeout, 404, 502) sans interrompre le pipeline SIEM principal.
- **Documentation Procédurale :** Les Standard Operating Procedures (SOP) complètes sont disponibles dans [`docs/SOP_Reponse_Incident.md`](docs/SOP_Reponse_Incident.md) — reproduisant les standards documentaires d'un SOC de Groupe assurantiel.
- **Portabilité :** `requirements.txt` strict, commandes génériques (`python`, pas de chemin absolu hard-codé) — le projet tourne sur n'importe quel poste.

---

## 🗺️ Roadmap & Évolutions

<p align="center">
  <img src="roadmap_implementation.svg" alt="Roadmap d'implémentation" width="850">
</p>

### Sprint 1 — Crédibilité immédiate `✅ 100% TERMINÉ`

| Élément | Statut | Fichier |
| :--- | :---: | :--- |
| Feed CISA KEV + CTI OTX en temps réel | ✅ | `scripts/cti/cisa_kev_puller.py` |
| Scénarios Assurance (Portail Courtier, RGPD, CNIL 72h) | ✅ | `scripts/simulators/` |
| Dashboard visuel MTTD/MTTR localhost | ✅ | `scripts/dashboard_soc.py` |

### Sprint 2 — Profondeur technique `🟡 75% EN COURS`

| Élément | Statut | Commentaire |
| :--- | :---: | :--- |
| SIEM Python collège avec règles Sigma-like | ✅ | Implémenté en natif Python (sans Wazuh) |
| SOAR avec Playbooks automatiques | ✅ | 3 Playbooks complets avec appels API |
| Enrichissement OTX (IOC lookup) | ✅ | `scripts/cti/otx_ioc_lookup.py` |
| MITRE ATT&CK mapping + Heatmap Navigator | ✅ | `attck/coverage_layer.json` (14 techniques) |
| Wazuh Docker (SIEM réel) | ⏳ | Archivé en `legacy_docker_infrastructure/` |
| Shuffle SOAR / n8n | ⏳ | Remplacé par SOAR Python (plus agile) |

### Sprint 3 — Industrialisation ITSM & Scoring `🟠 80% EN COURS`

| Élément | Statut | Commentaire |
| :--- | :---: | :--- |
| Scoring assurantiel (Contrats / RGPD / Exposition) | ✅ | Intégré dans les Playbooks |
| Notification CNIL 72h (Playbook réglementaire) | ✅ | Tâche auto dans TheHive JSON |
| Export TheHive JSON (Custom Fields MTTD/MTTR) | ✅ | `scripts/generate_report.py` |
| Push ServiceNow ITSM (Ticket auto) | 🔲 | Vision : remplacer l'export TheHive |

### Sprint 4 — Maturité ingénierie DevSecOps `🟠 70% EN COURS`

| Élément | Statut | Commentaire |
| :--- | :---: | :--- |
| CI/CD GitHub Actions (tests intégrité Playbooks) | ✅ | `.github/workflows/test_playbooks.yml` |
| KPIs mesurés MTTD/MTTR | ✅ | Dashboard + Custom Fields TheHive |
| Standard CACAO (Format industriel Playbooks) | 🔲 | Vision : formaliser en JSON CACAO/OASIS |
| Sigma Rules YAML | 🔲 | Vision : migrer les règles Python vers YAML |

---

> **Légende :** ✅ Terminé &nbsp;|&nbsp; ⏳ Remplacé / Alt Alternative imprémentée &nbsp;|&nbsp; 🔲 Vision long terme

---

## 🤝 Contribution
Les contributions sont les bienvenues pour enrichir ce démonstrateur (nouveaux scénarios MITRE ATT&CK, nouveaux connecteurs CTI, etc.).

## 📄 Licence
Projet développé dans un cadre académique et professionnel. Droits réservés.

## 👨‍💻 Auteur

**KAMENI TCHOUATCHEU GAETAN BRUNEL**
*Futur Ingénieur Cybersécurité | Analyste SOC | Étudiant ESIEA*

📧 [gaetanbrunel.kamenitchouatcheu@et.esiea.fr](mailto:gaetanbrunel.kamenitchouatcheu@et.esiea.fr) &nbsp;·&nbsp; 🐙 [@Lkb-2905](https://github.com/Lkb-2905)

---

🙏 **Remerciements**
- **L'Écosystème des Mutuelles et Assurances** — Pour l'inspiration des standards opérationnels de la menace Cyber en milieu critique.
- **ESIEA** — Pour l'excellence de la formation ingénieur.

---

⭐ *Si ce projet vous semble pertinent pour la protection des systèmes de demain, laissez une étoile !*
*Fait avec ❤️, Python, et une bonne dose d'Investigation Numérique.*

© 2026 Kameni Tchouatcheu Gaetan Brunel — Tous droits réservés.
