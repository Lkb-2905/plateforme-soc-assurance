🌍 DOSSIER DE CONFIGURATION D'EXPLOITATION (DCE)

⚡ PLATEFORME SOC — Cybersécurité : SIEM Python, SOAR Asynchrone & Intégration CTI
Python | SOAR | SIEM | API REST (FastAPI) | MITRE ATT&CK | TheHive

⚠️ NB IMPORTANT : Il s'agit d'un projet personnel/étudiant. Le contexte de groupe assurantiel est utilisé uniquement pour donner un cadre d'entreprise réaliste à cette simulation (Inspiré des exigences d'un acteur majeur de l'assurance). Aucune donnée réelle ou privée n'est exploitée. Tous les événements, logs, adresses IP et rapports d'incidents présentés ici sont intégralement fictifs et créés de toutes pièces pour simuler un SOC ("Security Operations Center").

Version: 3.0.0 Enterprise | Date: Février/Mars 2026
Auteur: KAMENI TCHOUATCHEU GAETAN BRUNEL
Contact: gaetanbrunel.kamenitchouatcheu@et.esiea.fr

🚀 Architecture • 🛡️ Playbooks • 📈 Scénarios Cybersécurité • 🛠️ Utilisation

📋 TABLE DES MATIÈRES
1.  [Vue d'ensemble du projet](#🎯-vue-densemble-du-projet)
2.  [Architecture du projet](#🏗️-architecture-du-projet)
3.  [Scénarios d'Incidents & Playbooks](#📈-scénarios-dincidents--playbooks)
4.  [Fonctionnalités Clés](#📊-fonctionnalités-clés)
5.  [Défis & Intempéries Rencontrées](#🌪️-défis--intempéries-rencontrées)
6.  [Technologies Utilisées](#🛠️-technologies-utilisées)
7.  [Comment utiliser ce projet](#🚀-comment-utiliser-ce-projet)
8.  [Qualité & Best Practices](#✨-qualité--best-practices)
9.  [Roadmap & Évolutions](#🗺️-roadmap--évolutions)

---

## 🎯 VUE D'ENSEMBLE DU PROJET

### Contexte & Objectifs
Ce projet est un démonstrateur complet d'ingénierie Cybersécurité orienté **Détection et Réponse à Incident**. Il simule une plateforme SOC de bout-en-bout : depuis la génération des logs d'attaques, leur détection par un moteur SIEM (basé sur MITRE ATT&CK), jusqu'à l'éradication de la menace par un moteur SOAR asynchrone interagissant avec de fausses APIs d'entreprise (EDR, Messagerie, Annuaire).

Il illustre la maîtrise des compétences suivantes :

*   ✅ **Détection (SIEM)** : Création d'un moteur d'analyse de logs en Python appliquant des règles de corrélation inspirées du standard Sigma.
*   ✅ **Automatisation (SOAR)** : Développement de playbooks avancés pour l'endiguement automatique (isolation réseau, reset mot de passe).
*   ✅ **Mocking d'API REST** : Simulation d'environnements d'entreprise via FastAPI pour que le SOAR exécute de véritables requêtes HTTP de remédiation en conditions réelles.
*   ✅ **Veille CTI** : Agrégation de la menace (AbuseIPDB, AlienVault) pour scorer la criticité des Observables en direct.
*   ✅ **Case Management** : Exportation structurée au format JSON pour **TheHive**, prête pour les analystes N1/N2.

### Pourquoi ce projet ?
| Aspect | Démonstration |
| :--- | :--- |
| **Opérationnel (RUN)** | Génération de rapports d'incidents (PDF/Markdown) et tickets TheHive exploitables immédiatement. |
| **Ingénierie (BUILD)** | Conception complète d'un moteur asynchrone en Python contournant la lourdeur des stacks Docker. |
| **Réalisme** | Le SOAR tape sur de vraies APIs (Mock) pour isoler les machines critiques, prouvant la faisabilité technique en production. |
| **Analyse Temporelle** | Gestion des logs par file d'attente (Queues) mimant le flux de data en temps réel d'un véritable SOC. |

---

## 🏗️ ARCHITECTURE DU PROJET

### Flux de traitement des incidents (Detect → Respond)

1.  **Génération** : Les scripts `simulators` injectent des événements malveillants simulés (Payloads JSON).
2.  **Ingestion SIEM** : Le `SIEMEngine` parse les logs, vérifie les fréquences (ex: Bruteforce) et compare à la matrice MITRE ATT&CK. S'il y a match → Création d'une **Alerte**.
3.  **Triage SOAR** : Le `SOAREngine` intercepte l'alerte, identifie le Playbook adéquat et lance sa routine de traitement.
4.  **Enrichissement CTI** : Extraction des IPs/Hash/URLs et validation auprès des bases de renseignement externe.
5.  **Endiguement (Action API)** : Le SOAR effectue un `POST` HTTP vers le `mock_edr_api.py` pour isoler la machine correspondante ou forcer un MFA côté AD.
6.  **Clôture & Reporting** : Un rapport complet de crise est généré et un "Case" au format TheHive JSON est exporté.

---

## 📈 SCÉNARIOS D'INCIDENTS & PLAYBOOKS

Scénarios majeurs couverts par les règles de détection et traités automatiquement :

| Scénario | Tactique MITRE ATT&CK | Action du Playbook SOAR |
| :--- | :--- | :--- |
| **Ransomware** | T1486 (Data Encrypted for Impact) | Isolement EDR via API + Arrêt du partage de fichier + Alerte RSSI/Crise. |
| **Phishing / Spear-Phishing** | T1566.001 (Malicious Link/Attachment) | Analyse CTI de l'URL + Suppression du mail via API + Reset MDP si cliqué. |
| **Compromission de Compte (VIP)** | T1078 (Valid Accounts / Impossible Travel) | Blocage AD via API (révocation token) + Enforce MFA + Notification niveau P1. |

---

## 📊 FONCTIONNALITÉS CLÉS

### 1. Moteur SOAR Interactif (API EDR Mock)
Contrairement à des simulations classiques qui font de simples `print`, ce SOAR utilise la librairie `requests` pour attaquer un serveur FastAPI local (`mock_edr_api.py`). Cela prouve la viabilité totale des scripts dans un vrai SI/SOC équipé de CrowdStrike, SentinelOne ou Microsoft Defender. Le SOAR intègre même un mécanisme de "fallback" gracieux au cas où l'API soit indisponible.

### 2. Export Automatisé TheHive (Case Management)
À la fin de l'exécution, le système parse tous les IOC (Indicators of Compromise), la TLP, le Pap et les TTPs, pour forger dynamiquement un modèle de ticket `.json`. Ce ticket structure les tâches de l'analyste SOC afin de standardiser le post-mortem de l'incident.

---

## 🌪️ DÉFIS & INTEMPÉRIES RENCONTRÉES

La construction de cette plateforme sans reposer sur des solutions pré-packagées a soulevé plusieurs complexités techniques enrichissantes :

*   **Conflit d'Environnements Windows (Python) :**
    Lors du déploiement serveur de l'API Mock, Windows "interceptait" les appels via d'autres installations de Python (MinGW/MSYS64) dépourvues de modules comme `pip`. Il a fallu forcer l'usage du chemin absolu de l'interpréteur `pyenv` (`C:\Users\pc\.pyenv\pyenv-win\...`) pour garantir une exécution stable et propre du serveur API.
*   **Compatibilité Typage & Pydantic v1 vs Python 3.12+ :**
    Le démarrage du serveur FastAPI a crashé sur une erreur bloquante (`TypeError: ForwardRef._evaluate() missing 1 required keyword-only argument`). Ce bug très pointu venait du changement de signature interne du cache de typage natif dans Python 3.12.4+, rendant Pydantic 1.10.x inopérant. **Résolution** : Diagnostic à chaud et upgrade manuel de l'environnement vers `Pydantic v2`.
*   **Mocking d'une infrastructure réseau asynchrone :**
    Simuler l'orchestration SOAR sans bloquer la boucle principale du SIEM (notamment au moment des appels réseaux externes `time.sleep` ou requêtes HTTP à l'API) nécessite une grande rigueur algorithmique pour éviter que les événements de logs entrants ne soient pas ignorés.

---

## 🛠️ TECHNOLOGIES UTILISÉES

| Composant | Technologie | Usage |
| :--- | :--- | :--- |
| **Core SIEM/SOAR** | Python 3.12+ | Scripting avancé, parsing, requêtages HTTP, classes de données. |
| **API de Sécurité (Mock)** | FastAPI / Uvicorn | Création de fausses routes d'EDR / AD / Firewall locales. |
| **Reporting / Templates** | Jinja2 / Markdown | Rendu automatisé des rapports Cyber de niveau exécutif. |
| **Case Management** | JSON (Format TheHive) | Interopérabilité logicielle avec des systèmes ITSM réels. |
| **Terminal & Batch** | CLI / PowerShell | Déploiement logiciel de simulation réseau. |

---

## 🚀 COMMENT UTILISER CE PROJET

### 1. Lancement du Serveur de Sécurité (EDR/IAM Mock)
Dans un **premier terminal**, amorcez le simulateur d'équipements de sécurité de l'entreprise :
```bash
# Vérifiez vos modules
python -m pip install fastapi uvicorn requests jinja2 colorlog pydantic

# Lancez l'API
python scripts/mock_edr_api.py
```
*Le serveur écoutera sur `http://127.0.0.1:8080`.*

### 2. Démarrage de la Plateforme SOC (Terminal 2)
Dans un **second terminal**, lancez le pipeline complet SIEM/SOAR pour le scénario de votre choix :
```bash
# Simulation d'une attaque Ransomware
python scripts/soc_engine.py --scenario ransomware

# Simulation de Phishing
python scripts/soc_engine.py --scenario phishing
```
*Observez la console : le SOAR détectera la menace et fera appel, en direct, au Terminal 1 pour bloquer la machine.*

---

## ✨ QUALITÉ & BEST PRACTICES

*   **Ingénierie Logicielle :** Utilisation intensive des `dataclasses` Python pour modéliser précisément les objets de sécurité (Alerte, IOC, Observables).
*   **Logging Professionnel :** Implémentation de `colorlog` pour des niveaux de criticité lisibles par la supervision.
*   **Dégradation Gracieuse :** Mise en place d'un mode "hors-ligne" sur les Playbooks si l'API vient à tomber ("Fail-Safe").

---

## 🗺️ ROADMAP & ÉVOLUTIONS

**Version Actuelle : 3.0.0 Enterprise ✅**
*   Moteur SIEM/SOAR Python complet.
*   API réseau simulée (FastAPI).
*   Génération de Rapports PDf/MD + Tickets TheHive.

**Version 4.0.0 (Vision Long Terme) 🔮**
*   Refonte des règles Python pures vers un parseur YAML "Sigma Rules".
*   Génération d'Exports STIX 2.1 complets pour l'Intelligence Threat.
*   Passage à la librairie `asyncio` pour la totalité du SIEM afin de supporter >100.000 EPS.

---

## 🤝 CONTRIBUTION
Les contributions sont les bienvenues pour faire évoluer ce démonstrateur. Les idées d'ajout de nouveaux scénarios MITRE ATT&CK sont encouragées.

## 📄 LICENCE
Ce projet est développé dans un cadre académique et professionnel. Droits réservés.

## 👨‍💻 AUTEUR
**KAMENI TCHOUATCHEU GAETAN BRUNEL**
*Futur Ingénieur Cybersécurité / Analyste SOC | Étudiant ESIEA*

📧 Email : gaetanbrunel.kamenitchouatcheu@et.esiea.fr
🐙 GitHub : @Lkb-2905

🙏 **REMERCIEMENTS**
*   **Covéa & L'Écosystème Assurantiel** : Pour l'inspiration des standards d'opération de la menace Cyber en milieu critique.
*   **ESIEA** : Pour l'excellence de la formation ingénieur.

⭐ *Si ce projet vous semble pertinent pour protéger les systèmes de demain, laissez une étoile ! Fait avec ❤️, Python, et une bonne dose d'Investigation Numérique.*

© 2026 Kameni Tchouatcheu Gaetan Brunel — Tous droits réservés.
