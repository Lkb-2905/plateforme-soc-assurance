"""
================================================================
GÉNÉRATEUR DE RAPPORTS D'INCIDENT
Plateforme SOC Assurantielle – scripts/generate_report.py
================================================================
Génère automatiquement des rapports d'incident au format
Markdown à partir des alertes Wazuh et des actions SOAR.

Usage :
  python scripts/generate_report.py --type ransomware
  python scripts/generate_report.py --type phishing
  python scripts/generate_report.py --type account_compromise

Le rapport est sauvegardé dans reports/generated/
================================================================
"""

import os
import json
import argparse
import hashlib
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader

# ─── Configuration ─────────────────────────────────────────────
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "reports", "templates")
OUTPUT_DIR    = os.path.join(os.path.dirname(__file__), "..", "reports", "generated")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─── Données simulées par scénario ─────────────────────────────
SCENARIO_DATA = {

    "ransomware": {
        "incident_type": "Ransomware",
        "classification": "CONFIDENTIEL",
        "severity": 5,
        "status": "Résolu",
        "executive_summary": (
            "Une attaque ransomware a été détectée et contenue sur le serveur de fichiers SRVFILE-22 "
            "hébergeant des données de contrats et de sinistres. Le malware, identifié comme une variante "
            "de CONTI, a chiffré 23 fichiers avant d'être stoppé par l'action de confinement automatisée "
            "déclenchée par le playbook SOAR. Aucune donnée n'a été exfiltrée. Le vecteur d'entrée initial "
            "était une macro malveillante dans un document Word reçu par email."
        ),
        "business_impact": "Interruption temporaire d'accès au partage /data/contrats/ (47 min). Données de 12 dossiers sinistres affectées, sauvegardées et restaurées depuis les backups J-1.",
        "timeline": [
            {"time": "08:14:32", "mitre_id": "T1566.001", "description": "Réception email avec macro malveillante", "host": "PC-FINANCE-142", "source_ip": "185.220.101.3"},
            {"time": "08:17:08", "mitre_id": "T1204.002", "description": "Exécution de la macro – lancement de svchost32.exe", "host": "PC-FINANCE-142", "source_ip": "127.0.0.1"},
            {"time": "08:19:44", "mitre_id": "T1486", "description": "Début du chiffrement des fichiers (.CONTI)", "host": "SRVFILE-22", "source_ip": "192.168.4.142"},
            {"time": "08:20:11", "mitre_id": "T1486", "description": "Règle Wazuh 100002 déclenchée (20+ fichiers / 60s)", "host": "WAZUH-MANAGER", "source_ip": "-"},
            {"time": "08:20:13", "mitre_id": "-", "description": "Playbook SOAR Ransomware déclenché automatiquement", "host": "SHUFFLE-SOAR", "source_ip": "-"},
            {"time": "08:20:45", "mitre_id": "-", "description": "Isolation réseau SRVFILE-22 simulée + Alerte cellule de crise", "host": "SHUFFLE-SOAR", "source_ip": "-"},
            {"time": "09:08:00", "mitre_id": "-", "description": "Restauration des fichiers depuis backup J-1 – Incident clôturé", "host": "SRVFILE-22", "source_ip": "-"},
        ],
        "affected_systems": [
            {"hostname": "PC-FINANCE-142", "ip": "192.168.4.142", "role": "Poste de travail – Responsable Comptabilité", "status": "Isolé puis réintégré"},
            {"hostname": "SRVFILE-22",      "ip": "192.168.2.22",  "role": "Serveur de fichiers – Contrats & Sinistres",  "status": "Restauré"},
        ],
        "affected_accounts": [
            {"name": "Marie Dupont", "username": "m.dupont", "dept": "Finance", "action": "Session terminée de force, MDP réinitialisé"},
        ],
        "iocs": [
            {"type": "Hash (MD5)", "value": "44d88612fea8a8f36de82e1278abb02f", "score": 95, "sources": ["VirusTotal", "AlienVault OTX"]},
            {"type": "IP",        "value": "185.220.101.3",                    "score": 87, "sources": ["AbuseIPDB"]},
            {"type": "Extension", "value": ".CONTI",                            "score": 98, "sources": ["Wazuh Custom Rule"]},
        ],
        "mitre_techniques": [
            {"tactic": "Initial Access",    "name": "Spearphishing Attachment", "id": "T1566.001"},
            {"tactic": "Execution",         "name": "User Execution: Malicious File", "id": "T1204.002"},
            {"tactic": "Impact",            "name": "Data Encrypted for Impact", "id": "T1486"},
            {"tactic": "Lateral Movement",  "name": "Remote Services: SMB/Windows Admin Shares", "id": "T1021.002"},
        ],
        "soar_actions": [
            {"name": "Vérification CTI Hash & IP", "status": "✅ Succès", "playbook": "playbook_ransomware_v1", "timestamp": "08:20:15 UTC", "detail": "Hash confirmé comme CONTI par VirusTotal (95/100). IP blacklistée sur AbuseIPDB."},
            {"name": "Isolation réseau de l'hôte", "status": "✅ Succès", "playbook": "playbook_ransomware_v1", "timestamp": "08:20:45 UTC", "detail": "Requête d'isolation envoyée au firewall segmentation (simulation). Hôte SRVFILE-22 mis en quarantaine réseau."},
            {"name": "Notification cellule de crise", "status": "✅ Succès", "playbook": "playbook_ransomware_v1", "timestamp": "08:20:48 UTC", "detail": "Email d'alerte envoyé au RSSI, DSI et équipe SOC N2."},
            {"name": "Création du ticket d'incident", "status": "✅ Succès", "playbook": "playbook_ransomware_v1", "timestamp": "08:20:50 UTC", "detail": "Ticket P1-2024-0312 créé dans le système ITSM avec toutes les preuves collectées."},
        ],
        "cti_results": [
            {"value": "44d88612...", "score": 95, "is_malicious": True, "tags": ["ransomware", "conti"]},
            {"value": "185.220.101.3", "score": 87, "is_malicious": True, "tags": ["botnet", "tor-exit-node"]},
        ],
        "recommendations": [
            {"title": "Désactiver les macros Office par GPO",      "priority": "🔴 CRITIQUE",  "detail": "Déployer une GPO bloquant l'exécution des macros VBA pour l'ensemble des postes hors whitelist validée."},
            {"title": "Renforcer les sauvegardes (backup 3-2-1)",   "priority": "🟠 HAUTE",     "detail": "Vérifier que les backups sont offline ou immuables pour résister à une attaque ransomware visant les systèmes de backup."},
            {"title": "Sensibilisation phishing & macro utilisateurs", "priority": "🟡 MOYENNE", "detail": "Organiser une session de sensibilisation SOC + RH trimestrielle sur les risques liés aux pièces jointes."},
        ],
        "artifacts": [
            {"name": "wazuh_alerts_export.json", "description": "Export des alertes Wazuh brutes liées à l'incident", "size": "48 KB"},
            {"name": "cti_report_incident.json",  "description": "Rapport CTI complet des IoCs analysés",            "size": "12 KB"},
        ],
        "analyst_level": 2,
        "soc_manager": "Sophie Bernard",
    },

    "phishing": {
        "incident_type": "Phishing",
        "classification": "INTERNE",
        "severity": 3,
        "status": "Résolu",
        "executive_summary": "Une campagne de spear-phishing a été détectée ciblant le département Finance. Un email contenant une URL malveillante a été reçu par 3 utilisateurs. L'analyse CTI a confirmé le domaine malveillant. Un utilisateur a cliqué sur le lien. Le playbook SOAR a déclenché la suppression automatique de l'email et la réinitialisation préventive du mot de passe.",
        "business_impact": "Aucune exfiltration de données confirmée. Réinitialisation du mot de passe pour 1 utilisateur.",
        "timeline": [
            {"time": "10:31:00", "mitre_id": "T1566.001", "description": "Email de phishing reçu par m.dupont@assurance-demo.fr", "host": "MAIL-GW-01", "source_ip": "185.220.101.5"},
            {"time": "10:31:02", "mitre_id": "T1566.001", "description": "URL malveillante détectée et vérifiée par CTI (Score: 92/100)", "host": "CTI-MODULE", "source_ip": "-"},
            {"time": "10:45:18", "mitre_id": "T1204.001", "description": "Utilisateur m.dupont a cliqué sur le lien de phishing", "host": "PC-FINANCE-142", "source_ip": "192.168.4.142"},
            {"time": "10:45:20", "mitre_id": "-", "description": "Playbook SOAR Phishing déclenché", "host": "SHUFFLE-SOAR", "source_ip": "-"},
            {"time": "10:45:35", "mitre_id": "-", "description": "Email supprimé des boîtes de réception, MDP réinitialisé", "host": "SHUFFLE-SOAR", "source_ip": "-"},
        ],
        "affected_systems": [
            {"hostname": "MAIL-GW-01",    "ip": "192.168.1.5",   "role": "Passerelle de messagerie", "status": "Opérationnel"},
            {"hostname": "PC-FINANCE-142","ip": "192.168.4.142", "role": "Poste de travail Finance",  "status": "Analysé – Aucune compromission"},
        ],
        "affected_accounts": [
            {"name": "Marie Dupont", "username": "m.dupont", "dept": "Finance", "action": "MDP réinitialisé – Sensibilisation effectuée"},
        ],
        "iocs": [
            {"type": "URL",    "value": "http://portail-assurance-signin.evil.com/reset", "score": 92, "sources": ["AlienVault OTX"]},
            {"type": "Domain", "value": "portail-assurance-signin.evil.com",               "score": 88, "sources": ["AlienVault OTX"]},
            {"type": "IP",     "value": "185.220.101.5",                                  "score": 81, "sources": ["AbuseIPDB"]},
        ],
        "mitre_techniques": [
            {"tactic": "Initial Access", "name": "Spearphishing Attachment", "id": "T1566.001"},
            {"tactic": "Execution",      "name": "User Execution: Malicious Link", "id": "T1204.001"},
        ],
        "soar_actions": [
            {"name": "Vérification CTI URL", "status": "✅ Succès", "playbook": "playbook_phishing_v1", "timestamp": "10:31:03 UTC", "detail": "URL scorée 92/100 sur AlienVault OTX – domaine de phishing connu."},
            {"name": "Suppression email",    "status": "✅ Succès", "playbook": "playbook_phishing_v1", "timestamp": "10:45:22 UTC", "detail": "Email supprimé des boîtes des 3 destinataires via API messagerie."},
            {"name": "Réinitialisation MDP", "status": "✅ Succès", "playbook": "playbook_phishing_v1", "timestamp": "10:45:30 UTC", "detail": "Réinitialisation de mot de passe forcée pour m.dupont."},
        ],
        "cti_results": [
            {"value": "portail-assurance-signin.evil.com", "score": 88, "is_malicious": True, "tags": ["phishing", "credential-harvesting"]},
        ],
        "recommendations": [
            {"title": "Activer DMARC/DKIM/SPF sur le domaine", "priority": "🔴 CRITIQUE",  "detail": "Déployer les enregistrements DNS anti-usurpation pour réduire les emails de phishing par spoofing du domaine."},
            {"title": "Déployer un filtre anti-phishing IA",    "priority": "🟠 HAUTE",     "detail": "Évaluer une solution de protection messagerie avancée (ex: Proofpoint, Microsoft Defender for Office 365)."},
        ],
        "artifacts": [
            {"name": "email_header_analysis.txt", "description": "Analyse des entêtes de l'email de phishing", "size": "4 KB"},
            {"name": "cti_url_report.json",        "description": "Rapport CTI de l'URL malveillante",          "size": "8 KB"},
        ],
        "analyst_level": 1,
        "soc_manager": "Sophie Bernard",
    },
}


def generate_incident_report(incident_type: str, analyst_name: str = "Analyste SOC") -> str:
    """
    Génère un rapport d'incident Markdown à partir du template Jinja2.

    Args:
        incident_type: Type d'incident ("ransomware", "phishing", "account_compromise")
        analyst_name: Nom de l'analyste à mentionner dans le rapport

    Returns:
        Chemin du fichier rapport généré
    """
    if incident_type not in SCENARIO_DATA:
        raise ValueError(f"Type d'incident inconnu: {incident_type}. Valeurs possibles: {list(SCENARIO_DATA.keys())}")

    # Chargement des données du scénario
    data = SCENARIO_DATA[incident_type].copy()

    # Métadonnées du rapport
    now = datetime.now(timezone.utc)
    data["generated_at"]  = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    data["detection_time"] = now.strftime("%Y-%m-%d %H:%M UTC")
    data["analyst_name"]  = analyst_name
    data["team_name"]     = os.getenv("SOC_TEAM_NAME", "SOC Groupe Assurantiel")
    data["incident_ref"]  = f"INC-{now.year}-{now.strftime('%m%d')}-{hashlib.md5(incident_type.encode()).hexdigest()[:6].upper()}"

    # Rendu du template Jinja2
    env  = Environment(loader=FileSystemLoader(TEMPLATES_DIR), trim_blocks=True)
    tmpl = env.get_template("incident_report.md.j2")
    rendered = tmpl.render(**data)

    # Sauvegarde du fichier
    filename    = f"incident_report_{incident_type}_{now.strftime('%Y%m%d_%H%M%S')}.md"
    output_path = os.path.join(OUTPUT_DIR, filename)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)

    print(f"\n✅ Rapport généré → {output_path}")
    print(f"   Référence  : {data['incident_ref']}")
    print(f"   Type       : {data['incident_type']}")
    print(f"   Sévérité   : {data['severity']}/5")
    return output_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Générateur de rapports d'incident SOC")
    parser.add_argument("--type",     required=True, choices=list(SCENARIO_DATA.keys()), help="Type d'incident")
    parser.add_argument("--analyst",  default="Analyste SOC", help="Nom de l'analyste")
    args = parser.parse_args()
    generate_incident_report(args.type, args.analyst)
