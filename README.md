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

<p align="center">
  <img src="soc_architecture_globale.svg" alt="Architecture Globale SOC" width="850">
</p>

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

## 📊 FONCTIONNALITÉS CLÉS & TABLEAUX DE BORD

### Portail SOC de Supervision (Dashboard Exécutif)
*(Aperçu de l'interface `localhost` générée par Streamlit et affichant dynamiquement les KPIs et remontées JSON de la matrice TheHive)*

<p align="center">
  <img src="Capture d’écran_23-3-2026_184310_localhost.jpeg" alt="SOC Dashboard" width="900" style="border-radius:10px;">
</p>

> 📥 **[Ouvrir et Télécharger l'intégralité du Rapport Exécutif (Export PDF)](<SOC Executive Dashboard.pdf>)**

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

## 🚀 COMMENT UTILISER CE PROJET (RUN BOOK)

⚠️ **Pré-requis Windows :** Afin d'éviter les conflits avec `MinGW` ou d'autres installations de Python, toutes les commandes ci-dessous utilisent consciencieusement l'interpréteur virtuel `pyenv` pour une exécution parfaite.

### 1. Préparation de l'environnement
Installez l'ensemble des dépendances (FastAPI, Streamlit, etc.) en une commande :
```powershell
C:\Users\pc\.pyenv\pyenv-win\versions\3.12.10\python.exe -m pip install fastapi uvicorn requests jinja2 colorlog pydantic streamlit
```

### 2. Démarrage du Serveur de Sécurité Mock (Terminal 1)
Ouvrez un premier terminal pour allumer l'API EDR / Pare-feu qui va recevoir les ordres tactiques de coupure venant du SOAR :
```powershell
C:\Users\pc\.pyenv\pyenv-win\versions\3.12.10\python.exe scripts\mock_edr_api.py
```
*(Le serveur doit rester ouvert en arrière-plan et écoute sur le port 8080)*

### 3. Exécution d'une Cyberattaque et de la Réponse Automatisée (Terminal 2)
Ouvrez un second terminal pour simuler une tentative d'intrusion ("Ransomware" ou "Phishing"). Le système SIEM va générer l'alerte en temps réel, et le SOAR prendra les mesures correctives via l'API :
```powershell
# Au choix : Actionner le Ransomware T1486
C:\Users\pc\.pyenv\pyenv-win\versions\3.12.10\python.exe scripts\soc_engine.py --scenario ransomware

# Au choix : Actionner le Phishing Assurantiel T1566.001
C:\Users\pc\.pyenv\pyenv-win\versions\3.12.10\python.exe scripts\soc_engine.py --scenario phishing
```

### 4. Lancement du SOC Executive Dashboard (Terminal 3)
Ouvrez un troisième terminal pour lancer l'interface web de votre "Centre de Contrôle" qui agrège les JSON générés par TheHive :
```powershell
C:\Users\pc\.pyenv\pyenv-win\versions\3.12.10\python.exe -m streamlit run scripts\dashboard_soc.py
```
*(Le navigateur web s'ouvrira automatiquement sur http://localhost:8501)*

### 5. Exécution de la Cyber-Veille Ouverte / CTI (N'importe quel terminal)
Pour interroger les bases d'Intel et peupler le second onglet de votre application Web en analysant mondialement vos IOCs :
```powershell
# Renseignement IP / Campagnes avec l'API publique AlienVault OTX
C:\Users\pc\.pyenv\pyenv-win\versions\3.12.10\python.exe scripts\cti\otx_ioc_lookup.py

# Alerte Vulnérabilités gouvernementales The CISA KEV (Known Exploited Vulnerabilities)
C:\Users\pc\.pyenv\pyenv-win\versions\3.12.10\python.exe scripts\cti\cisa_kev_puller.py
```

---

## ✨ QUALITÉ & BEST PRACTICES

*   **Ingénierie Logicielle :** Utilisation intensive des `dataclasses` Python pour modéliser précisément les objets de sécurité (Alerte, IOC, Observables).
*   **Logging Professionnel :** Implémentation de `colorlog` pour des niveaux de criticité lisibles par la supervision.
*   **Dégradation Gracieuse :** Mise en place d'un mode "hors-ligne" sur les Playbooks si l'API vient à tomber ("Fail-Safe").

---

## 🗺️ ROADMAP & ÉVOLUTIONS

<p align="center">
  <img src="roadmap_implementation.svg" alt="Roadmap d'implémentation" width="850">
</p>

**Version Actuelle : 4.0.0 (Release Entretien) ✅**
*   **Moteur SIEM/SOAR Python** asynchrone fonctionnel.
*   **Mocking API REST (FastAPI)** simulant un EDR et l'Active Directory.
*   **Executive Dashboard Web (Streamlit)** avec calculs de MTTD/MTTR.
*   **Module de Risque Assurantiel** (Détection Fuite RGPD & Déclaration CNIL 72h).
*   **Threat Intelligence Active** (Interrogation API AlienVault OTX & CISA KEV).

**Prochains Sprints (Vision Industrielle) 🔮**
*   **ITSM ServiceNow** : Remplacer l'export TheHive actuel par un push API direct vers un vrai ServiceNow.
*   **Standardisation CACAO / STIX 2.1** : Pousser la formalisation des playbooks vers le standard CACAO de l'OASIS.
*   **CI/CD DevSecOps** : Intégration de tests de non-régression (GitHub Actions) validant la résilience des Playbooks.

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
*   **L'Écosystème des Mutuelles et Assurances** : Pour l'inspiration des standards d'opération de la menace Cyber en milieu critique.
*   **ESIEA** : Pour l'excellence de la formation ingénieur.

⭐ *Si ce projet vous semble pertinent pour protéger les systèmes de demain, laissez une étoile ! Fait avec ❤️, Python, et une bonne dose d'Investigation Numérique.*

© 2026 Kameni Tchouatcheu Gaetan Brunel — Tous droits réservés.
