# 📋 SOP – Procédure de Réponse à Incident (SOC Assurantiel)

> **Document :** Standard Operating Procedure – Réponse aux Incidents de Sécurité  
> **Classification :** CONFIDENTIEL – Équipes SOC  
> **Version :** 1.0

---

## 1. Objectif

Ce document décrit les procédures standardisées à appliquer lors de la détection d'un incident de sécurité sur l'infrastructure du groupe assurantiel simulée. Il est conçu pour guider les analystes SOC de niveaux N1, N2 et N3.

---

## 2. Niveaux de Sévérité

| Niveau | Nom     | Description                                                  | Délai de réponse |
|--------|---------|--------------------------------------------------------------|------------------|
| **P1** | Critique| Compromission avérée, ransomware actif, exfiltration de PII  | < 15 minutes     |
| **P2** | Haute   | Tentative de compromission détectée, phishing utilisateur    | < 1 heure        |
| **P3** | Moyenne | Alerte anomalie, scan réseau interne, bruteforce faible      | < 4 heures       |
| **P4** | Faible  | Alerte informationnelle, événement non critique              | < 24 heures      |

---

## 3. Procédure Générale (PICERL)

La réponse à incident suit le cycle **PICERL** (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned) :

```
[1] PRÉPARATION     → Environnement Docker démarré, Rules Wazuh actives
        ↓
[2] IDENTIFICATION   → Alerte Wazuh déclenchée → SOAR notifié (Webhook)
        ↓
[3] ENDIGUEMENT      → Playbook SOAR : isolation hôte, blocage IP, suspension compte
        ↓
[4] ÉRADICATION      → Suppression du malware / email / session compromise
        ↓
[5] RÉTABLISSEMENT   → Restauration depuis backup, vérification intégrité
        ↓
[6] RETOUR D'EXP.   → Rapport d'incident, mise à jour des règles Wazuh / playbooks
```

---

## 4. Procédures Spécifiques par Scénario

### 4.1 Ransomware

**Détection :** Règles Wazuh 100001 → 100003  
**Déclencheur SOAR :** Règle 100002 (>20 fichiers chiffrés en 60s)

| Étape | Action                          | Responsable    | Outil              |
|-------|---------------------------------|----------------|--------------------|
| 1     | Vérifier l'alerte dans Wazuh   | N1             | Dashboard Wazuh    |
| 2     | Vérifier CTI : IP + Hash       | Shuffle (Auto) | AbuseIPDB / VT     |
| 3     | Isoler l'hôte du réseau         | Shuffle (Auto) | Wazuh Active Resp. |
| 4     | Alerter RSSI + cellule de crise | Shuffle (Auto) | Email / Ticket     |
| 5     | Analyser la souche malveillante | N2/N3          | Sandbox            |
| 6     | Restaurer depuis backup         | N2 + Sysadmin  | Backup J-1         |
| 7     | Générer le rapport d'incident   | N1             | `generate_report.py` |

**Commande de simulation :**
```bash
python scripts/simulators/ransomware_sim.py
```

---

### 4.2 Phishing / Spear-Phishing

**Détection :** Règles Wazuh 100010 → 100012  
**Déclencheur SOAR :** Règle 100012 (clic utilisateur confirmé)

| Étape | Action                              | Responsable    | Outil           |
|-------|-------------------------------------|----------------|-----------------|
| 1     | Confirmer la réception de l'email   | N1             | Dashboard Wazuh |
| 2     | Vérifier URL / Domaine via CTI      | Shuffle (Auto) | OTX AlienVault  |
| 3     | Supprimer l'email des boîtes        | Shuffle (Auto) | API Messagerie  |
| 4     | Réinitialiser le MDP si clic        | Shuffle (Auto) | API Active Dir. |
| 5     | Sensibiliser l'utilisateur          | N1 + RH        | Email / Verbal  |
| 6     | Générer rapport d'incident          | N1             | `generate_report.py` |

**Commande de simulation :**
```bash
python scripts/simulators/phishing_sim.py
```

---

### 4.3 Compromission de Compte (Impossible Travel)

**Détection :** Règles Wazuh 100020 → 100022  
**Déclencheur SOAR :** Règle 100021 (Impossible Travel confirmé)

| Étape | Action                                 | Responsable    | Outil            |
|-------|----------------------------------------|----------------|------------------|
| 1     | Identifier les deux géolocalisations   | N1             | Dashboard Wazuh  |
| 2     | Bloquer la session/IP suspecte         | Shuffle (Auto) | Wazuh Active Resp |
| 3     | Alerter P1 si compte VIP (RSSI/CEO)    | Shuffle (Auto) | Email / Ticket   |
| 4     | Contacter l'utilisateur pour vérif.    | N2             | Téléphone        |
| 5     | Forcer MFA + Reset MDP                 | N2             | Active Directory |
| 6     | Analyser les accès post-compromission  | N3             | Wazuh / Logs     |
| 7     | Générer rapport d'incident             | N1             | `generate_report.py` |

**Commande de simulation :**
```bash
python scripts/simulators/account_compromise_sim.py
```

---

## 5. Génération d'un Rapport d'Incident

```bash
# Rapport Ransomware
python scripts/generate_report.py --type ransomware --analyst "Jean Dupont"

# Rapport Phishing
python scripts/generate_report.py --type phishing --analyst "Marie Martin"
```

Les rapports sont générés dans `reports/generated/` au format Markdown.

---

## 6. Contacts d'Urgence (Simulation)

| Rôle              | Nom               | Contact (simulé)              |
|-------------------|-------------------|-------------------------------|
| RSSI              | Sophie Bernard    | rssi@assurance-demo.fr        |
| SOC N2            | Lucas Moreau      | soc-n2@assurance-demo.fr      |
| Cellule de crise  | Jean-Claude Mercier | dg@assurance-demo.fr         |
| Astreinte IT      | Thomas Lefort     | +33 6 00 00 00 00             |

---

*Document vivant – Mise à jour à chaque retour d'expérience post-incident.*
