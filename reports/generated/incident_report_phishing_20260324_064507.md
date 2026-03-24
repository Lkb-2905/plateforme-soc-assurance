# ================================================================
# RAPPORT D'INCIDENT DE SÉCURITÉ – PHISHING
# Généré le : 2026-03-24T06:45:07Z
# Référence : INC-2026-0324-936B58
# ================================================================

---

## 🏢 INFORMATIONS GÉNÉRALES

| Champ                    | Valeur                                            |
|--------------------------|---------------------------------------------------|
| **Référence Incident**   | `INC-2026-0324-936B58`                              |
| **Classification**       | INTERNE                              |
| **Sévérité**             | 3 / 5                                |
| **Statut**               | Résolu                                      |
| **Date de détection**    | 2026-03-24 06:45 UTC                              |
| **Date de résolution**   | En cours |
| **Analyste assigné**     | SOC Engine (Automatisé)                                |
| **Équipe**               | SOC Groupe Assurantiel                                   |

---

## 🎯 RÉSUMÉ EXÉCUTIF

Une campagne de spear-phishing a été détectée ciblant le département Finance. Un email contenant une URL malveillante a été reçu par 3 utilisateurs. L'analyse CTI a confirmé le domaine malveillant. Un utilisateur a cliqué sur le lien. Le playbook SOAR a déclenché la suppression automatique de l'email et la réinitialisation préventive du mot de passe.

> **Impact Métier** : Aucune exfiltration de données confirmée. Réinitialisation du mot de passe pour 1 utilisateur.

---

## 📋 CHRONOLOGIE DES ÉVÉNEMENTS

| Heure (UTC)       | MITRE ATT&CK     | Description                                  | Hôte             | IP Source          |
|-------------------|------------------|----------------------------------------------|------------------|--------------------|
| 10:31:00  | `T1566.001` | Email de phishing reçu par m.dupont@assurance-demo.fr            | `MAIL-GW-01` | `185.220.101.5` |
| 10:31:02  | `T1566.001` | URL malveillante détectée et vérifiée par CTI (Score: 92/100)            | `CTI-MODULE` | `-` |
| 10:45:18  | `T1204.001` | Utilisateur m.dupont a cliqué sur le lien de phishing            | `PC-FINANCE-142` | `192.168.4.142` |
| 10:45:20  | `-` | Playbook SOAR Phishing déclenché            | `SHUFFLE-SOAR` | `-` |
| 10:45:35  | `-` | Email supprimé des boîtes de réception, MDP réinitialisé            | `SHUFFLE-SOAR` | `-` |

---

## 🖥️ SYSTÈMES COMPROMIS / AFFECTÉS

- **MAIL-GW-01** (`192.168.1.5`) — Rôle : *Passerelle de messagerie* — Statut : `Opérationnel`
- **PC-FINANCE-142** (`192.168.4.142`) — Rôle : *Poste de travail Finance* — Statut : `Analysé – Aucune compromission`

---

## 👤 COMPTES UTILISATEURS IMPLIQUÉS

- **Marie Dupont** (`m.dupont`) — Département : Finance — Action : MDP réinitialisé – Sensibilisation effectuée

---

## 🔬 INDICATEURS DE COMPROMISSION (IoCs)

| **Type** | **Valeur** | **Score menace** | **Sources CTI** |
|----------|------------|------------------|-----------------|
| URL | `http://portail-assurance-signin.evil.com/reset` | 92/100 | AlienVault OTX |
| **Type** | **Valeur** | **Score menace** | **Sources CTI** |
|----------|------------|------------------|-----------------|
| Domain | `portail-assurance-signin.evil.com` | 88/100 | AlienVault OTX |
| **Type** | **Valeur** | **Score menace** | **Sources CTI** |
|----------|------------|------------------|-----------------|
| IP | `185.220.101.5` | 81/100 | AbuseIPDB |

---

## ⚔️ MAPPING MITRE ATT&CK

| Tactique          | Technique              | ID Technique |
|-------------------|------------------------|--------------|
| Initial Access | Spearphishing Attachment | `T1566.001` |
| Execution | User Execution: Malicious Link | `T1204.001` |

---

## 🛡️ ACTIONS DE RÉPONSE SOAR EFFECTUÉES

### 1. Vérification CTI URL

- **Statut** : `✅ Succès`
- **Exécuté par** : Playbook `playbook_phishing_v1`
- **Horodatage** : 10:31:03 UTC
- **Détail** : URL scorée 92/100 sur AlienVault OTX – domaine de phishing connu.
### 2. Suppression email

- **Statut** : `✅ Succès`
- **Exécuté par** : Playbook `playbook_phishing_v1`
- **Horodatage** : 10:45:22 UTC
- **Détail** : Email supprimé des boîtes des 3 destinataires via API messagerie.
### 3. Réinitialisation MDP

- **Statut** : `✅ Succès`
- **Exécuté par** : Playbook `playbook_phishing_v1`
- **Horodatage** : 10:45:30 UTC
- **Détail** : Réinitialisation de mot de passe forcée pour m.dupont.

---

## 📊 ÉVALUATION DE LA MENACE CTI

**Rapport de Veille Threat Intelligence :**

| Indicateur | Score | Malveillant | Tags |
|------------|-------|-------------|------|
| `portail-assurance-signin.evil.com` | 88/100 | 🔴 Oui | phishing, credential-harvesting |

---

## 🔧 RECOMMANDATIONS

1. **Activer DMARC/DKIM/SPF sur le domaine** *(Priorité : 🔴 CRITIQUE)*
   > Déployer les enregistrements DNS anti-usurpation pour réduire les emails de phishing par spoofing du domaine.
2. **Déployer un filtre anti-phishing IA** *(Priorité : 🟠 HAUTE)*
   > Évaluer une solution de protection messagerie avancée (ex: Proofpoint, Microsoft Defender for Office 365).

---

## 📁 PIÈCES JOINTES & PREUVES

- `email_header_analysis.txt` – Analyse des entêtes de l'email de phishing *(4 KB)*
- `cti_url_report.json` – Rapport CTI de l'URL malveillante *(8 KB)*

---

## ✍️ VALIDATION

| Rôle              | Nom                | Signature      | Date       |
|-------------------|--------------------|----------------|------------|
| Analyste N1 | SOC Engine (Automatisé) | *(électronique)* | 2026-03-24 |
| Responsable SOC   | Sophie Bernard  | *(électronique)* | 2026-03-24 |

---

*Document généré automatiquement par la plateforme SOC – SOC Groupe Assurantiel*
*Classification : INTERNE – Ne pas diffuser hors des équipes SOC/RSI*