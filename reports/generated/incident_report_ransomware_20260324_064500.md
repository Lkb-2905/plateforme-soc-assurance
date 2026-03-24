# ================================================================
# RAPPORT D'INCIDENT DE SÉCURITÉ – RANSOMWARE
# Généré le : 2026-03-24T06:45:00Z
# Référence : INC-2026-0324-70047C
# ================================================================

---

## 🏢 INFORMATIONS GÉNÉRALES

| Champ                    | Valeur                                            |
|--------------------------|---------------------------------------------------|
| **Référence Incident**   | `INC-2026-0324-70047C`                              |
| **Classification**       | CONFIDENTIEL                              |
| **Sévérité**             | 5 / 5                                |
| **Statut**               | Résolu                                      |
| **Date de détection**    | 2026-03-24 06:45 UTC                              |
| **Date de résolution**   | En cours |
| **Analyste assigné**     | SOC Engine (Automatisé)                                |
| **Équipe**               | SOC Groupe Assurantiel                                   |

---

## 🎯 RÉSUMÉ EXÉCUTIF

Une attaque ransomware a été détectée et contenue sur le serveur de fichiers SRVFILE-22 hébergeant des données de contrats et de sinistres. Le malware, identifié comme une variante de CONTI, a chiffré 23 fichiers avant d'être stoppé par l'action de confinement automatisée déclenchée par le playbook SOAR. Aucune donnée n'a été exfiltrée. Le vecteur d'entrée initial était une macro malveillante dans un document Word reçu par email.

> **Impact Métier** : Interruption temporaire d'accès au partage /data/contrats/ (47 min). Données de 12 dossiers sinistres affectées, sauvegardées et restaurées.

---

## 📋 CHRONOLOGIE DES ÉVÉNEMENTS

| Heure (UTC)       | MITRE ATT&CK     | Description                                  | Hôte             | IP Source          |
|-------------------|------------------|----------------------------------------------|------------------|--------------------|
| 08:14:32  | `T1566.001` | Réception email avec macro malveillante            | `PC-FINANCE-142` | `185.220.101.3` |
| 08:17:08  | `T1204.002` | Exécution de la macro – lancement de svchost32.exe            | `PC-FINANCE-142` | `127.0.0.1` |
| 08:19:44  | `T1486` | Début du chiffrement des fichiers (.CONTI)            | `SRVFILE-22` | `192.168.4.142` |
| 08:20:11  | `T1486` | Règle Wazuh 100002 déclenchée (20+ fichiers / 60s)            | `WAZUH-MANAGER` | `-` |
| 08:20:13  | `-` | Playbook SOAR Ransomware déclenché automatiquement            | `SHUFFLE-SOAR` | `-` |
| 08:20:45  | `-` | Isolation réseau SRVFILE-22 simulée + Alerte cellule de crise            | `SHUFFLE-SOAR` | `-` |
| 09:08:00  | `-` | Restauration des fichiers depuis backup J-1 – Incident clôturé            | `SRVFILE-22` | `-` |

---

## 🖥️ SYSTÈMES COMPROMIS / AFFECTÉS

- **PC-FINANCE-142** (`192.168.4.142`) — Rôle : *Poste de travail – Responsable Comptabilité* — Statut : `Isolé puis réintégré`
- **SRVFILE-22** (`192.168.2.22`) — Rôle : *Serveur de fichiers – Contrats & Sinistres* — Statut : `Restauré`

---

## 👤 COMPTES UTILISATEURS IMPLIQUÉS

- **Marie Dupont** (`m.dupont`) — Département : Finance — Action : Session terminée de force, MDP réinitialisé

---

## 🔬 INDICATEURS DE COMPROMISSION (IoCs)

| **Type** | **Valeur** | **Score menace** | **Sources CTI** |
|----------|------------|------------------|-----------------|
| Hash (MD5) | `44d88612fea8a8f36de82e1278abb02f` | 95/100 | VirusTotal, AlienVault OTX |
| **Type** | **Valeur** | **Score menace** | **Sources CTI** |
|----------|------------|------------------|-----------------|
| IP | `185.220.101.3` | 87/100 | AbuseIPDB |
| **Type** | **Valeur** | **Score menace** | **Sources CTI** |
|----------|------------|------------------|-----------------|
| Extension | `.CONTI` | 98/100 | Wazuh Custom Rule |

---

## ⚔️ MAPPING MITRE ATT&CK

| Tactique          | Technique              | ID Technique |
|-------------------|------------------------|--------------|
| Initial Access | Spearphishing Attachment | `T1566.001` |
| Execution | User Execution: Malicious File | `T1204.002` |
| Impact | Data Encrypted for Impact | `T1486` |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | `T1021.002` |

---

## 🛡️ ACTIONS DE RÉPONSE SOAR EFFECTUÉES

### 1. Vérification CTI Hash & IP

- **Statut** : `✅ Succès`
- **Exécuté par** : Playbook `playbook_ransomware_v1`
- **Horodatage** : 08:20:15 UTC
- **Détail** : Hash confirmé comme CONTI par VirusTotal (95/100). IP blacklistée sur AbuseIPDB.
### 2. Isolation réseau de l'hôte

- **Statut** : `✅ Succès`
- **Exécuté par** : Playbook `playbook_ransomware_v1`
- **Horodatage** : 08:20:45 UTC
- **Détail** : Requête d'isolation envoyée au firewall segmentation (simulation). Hôte SRVFILE-22 mis en quarantaine réseau.
### 3. Notification cellule de crise

- **Statut** : `✅ Succès`
- **Exécuté par** : Playbook `playbook_ransomware_v1`
- **Horodatage** : 08:20:48 UTC
- **Détail** : Email d'alerte envoyé au RSSI, DSI et équipe SOC N2.
### 4. Création du ticket d'incident

- **Statut** : `✅ Succès`
- **Exécuté par** : Playbook `playbook_ransomware_v1`
- **Horodatage** : 08:20:50 UTC
- **Détail** : Ticket P1-2024-0312 créé dans le système ITSM avec toutes les preuves collectées.

---

## 📊 ÉVALUATION DE LA MENACE CTI

**Rapport de Veille Threat Intelligence :**

| Indicateur | Score | Malveillant | Tags |
|------------|-------|-------------|------|
| `44d88612...` | 95/100 | 🔴 Oui | ransomware, conti |
| `185.220.101.3` | 87/100 | 🔴 Oui | botnet, tor-exit-node |

---

## 🔧 RECOMMANDATIONS

1. **Désactiver les macros Office par GPO** *(Priorité : 🔴 CRITIQUE)*
   > Déployer une GPO bloquant l'exécution des macros VBA pour l'ensemble des postes hors whitelist validée.
2. **Renforcer les sauvegardes (backup 3-2-1)** *(Priorité : 🟠 HAUTE)*
   > Vérifier que les backups sont offline ou immuables pour résister à une attaque ransomware visant les systèmes de backup.
3. **Sensibilisation phishing & macro utilisateurs** *(Priorité : 🟡 MOYENNE)*
   > Organiser une session de sensibilisation SOC + RH trimestrielle sur les risques liés aux pièces jointes.

---

## 📁 PIÈCES JOINTES & PREUVES

- `wazuh_alerts_export.json` – Export des alertes Wazuh brutes liées à l'incident *(48 KB)*
- `cti_report_incident.json` – Rapport CTI complet des IoCs analysés *(12 KB)*

---

## ✍️ VALIDATION

| Rôle              | Nom                | Signature      | Date       |
|-------------------|--------------------|----------------|------------|
| Analyste N2 | SOC Engine (Automatisé) | *(électronique)* | 2026-03-24 |
| Responsable SOC   | Sophie Bernard  | *(électronique)* | 2026-03-24 |

---

*Document généré automatiquement par la plateforme SOC – SOC Groupe Assurantiel*
*Classification : CONFIDENTIEL – Ne pas diffuser hors des équipes SOC/RSI*