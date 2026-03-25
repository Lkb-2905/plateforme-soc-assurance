#!/usr/bin/env python3
"""
=======================================================================
 MODULE — Ingestion de Logs Réels (Formats Windows Event Log / Sysmon)
=======================================================================
 Ce script parse des logs Windows réels (JSON/EVTX) au format Sysmon
 et les corrèle avec les règles de détection MITRE ATT&CK du projet.
 Il simule ce que ferait Wazuh ou Sentinel en ingestion continue.

 Auteur : KAMENI TCHOUATCHEU GAETAN BRUNEL — ESIEA 2026
=======================================================================
"""

import json
import datetime
from dataclasses import dataclass, field
from typing import Optional


# ─── Modèle de Log Windows (format Sysmon/WinEventLog réel) ──────────────
@dataclass
class WindowsSecurityEvent:
    """Modèle de log Windows Event au format standard (compatible Sysmon/EVTX)."""
    EventID:           int
    TimeCreated:       str
    Computer:          str
    Channel:           str
    Provider:          str
    EventData:         dict = field(default_factory=dict)

    # Champs MITRE ATT&CK enrichis après corrélation
    mitre_technique:   Optional[str] = None
    mitre_tactic:      Optional[str] = None
    severity:          Optional[str] = None
    soc_alert:         bool = False

    def to_sentinel_format(self) -> dict:
        """Convertit l'événement au format JSON compatible Azure Sentinel."""
        return {
            "TimeGenerated":    self.TimeCreated,
            "Computer":         self.Computer,
            "EventID":          self.EventID,
            "Channel":          self.Channel,
            "Provider":         self.Provider,
            "EventData":        json.dumps(self.EventData),
            "MitreTechnique":   self.mitre_technique or "N/A",
            "MitreTactic":      self.mitre_tactic or "N/A",
            "Severity":         self.severity or "Informational",
            "AlertTriggered":   self.soc_alert,
        }


# ─── Catalogue des Event IDs critiques (Windows Security / Sysmon) ────────
CRITICAL_EVENT_IDS = {
    # ── Authentification & Accès ──────────────────────────────────────────
    4624: {"description": "Connexion réussie",              "severity": "Low",      "mitre": None},
    4625: {"description": "Échec d'authentification",       "severity": "Medium",   "mitre": ("T1110", "Credential Access")},
    4648: {"description": "Tentative de connexion explicite","severity": "Medium",   "mitre": ("T1078", "Initial Access")},
    4672: {"description": "Privilèges spéciaux assignés",   "severity": "High",     "mitre": ("T1078.002", "Privilege Escalation")},
    4720: {"description": "Compte utilisateur créé",        "severity": "High",     "mitre": ("T1136", "Persistence")},
    4726: {"description": "Compte utilisateur supprimé",    "severity": "High",     "mitre": ("T1531", "Impact")},
    4740: {"description": "Compte verrouillé",              "severity": "Medium",   "mitre": ("T1110", "Credential Access")},
    # ── Exécution & Processus ─────────────────────────────────────────────
    4688: {"description": "Processus créé",                 "severity": "Low",      "mitre": ("T1059", "Execution")},
    4698: {"description": "Tâche planifiée créée",          "severity": "High",     "mitre": ("T1053.005", "Persistence")},
    # ── Sysmon (Microsoft Sysinternals) ───────────────────────────────────
    1:    {"description": "Sysmon - Création processus",    "severity": "Low",      "mitre": ("T1059", "Execution")},
    3:    {"description": "Sysmon - Connexion réseau",      "severity": "Low",      "mitre": ("T1071", "Command and Control")},
    11:   {"description": "Sysmon - Création de fichier",   "severity": "Medium",   "mitre": ("T1486", "Impact")},
    23:   {"description": "Sysmon - Suppression fichier",   "severity": "High",     "mitre": ("T1485", "Impact")},
    # ── Système ───────────────────────────────────────────────────────────
    7045: {"description": "Nouveau service installé",       "severity": "High",     "mitre": ("T1543.003", "Persistence")},
    1102: {"description": "Journal d'audit effacé ⚠️",     "severity": "Critical", "mitre": ("T1070.001", "Defense Evasion")},
}

# ─── Règles de Détection Ransomware (correspondant aux Sigma Rules YAML) ──
RANSOMWARE_INDICATORS = [
    "vssadmin delete shadows",
    "bcdedit /set recoveryenabled no",
    "wbadmin delete catalog",
    "cipher /w:",
    "schtasks /delete",
]

PHISHING_EXTENSIONS = [".exe", ".js", ".vbs", ".hta", ".iso", ".lnk", ".docm", ".xlsm"]


def correlate_with_mitre(event: WindowsSecurityEvent) -> WindowsSecurityEvent:
    """
    Enrichit un événement Windows avec la technique MITRE ATT&CK correspondante.
    Implémente la logique de corrélation du moteur SIEM Python.
    """
    catalog = CRITICAL_EVENT_IDS.get(event.EventID)
    if catalog:
        event.severity = catalog["severity"]
        if catalog["mitre"]:
            event.mitre_technique, event.mitre_tactic = catalog["mitre"]

    # Détection spécifique Ransomware (Event 4688 - Commandes suspectes)
    if event.EventID == 4688:
        cmd = event.EventData.get("CommandLine", "").lower()
        for indicator in RANSOMWARE_INDICATORS:
            if indicator.lower() in cmd:
                event.mitre_technique = "T1486 / T1490"
                event.mitre_tactic    = "Impact"
                event.severity        = "Critical"
                event.soc_alert       = True
                break

    # Déclencher une alerte SOC si haute/critique
    if event.severity in ("High", "Critical"):
        event.soc_alert = True

    return event


def generate_realistic_log_sample() -> list:
    """
    Génère un échantillon de logs Windows réalistes reproduisant
    une séquence d'attaque Ransomware complète (Kill Chain).
    """
    now = datetime.datetime.now(datetime.timezone.utc)

    def ts(offset_sec=0):
        return (now + datetime.timedelta(seconds=offset_sec)).isoformat().replace("+00:00", "Z")

    return [
        # 1. Phishing initial — connexion réseau suspecte
        WindowsSecurityEvent(
            EventID=3, TimeCreated=ts(0), Computer="PC-MARIE-DUPONT",
            Channel="Microsoft-Windows-Sysmon/Operational",
            Provider="Microsoft-Windows-Sysmon",
            EventData={"Image": "C:\\Users\\marie.dupont\\Downloads\\facture.exe",
                       "DestinationIp": "185.220.101.5", "DestinationPort": "443",
                       "Protocol": "tcp"}
        ),
        # 2. Exécution malveillante (Event 4688)
        WindowsSecurityEvent(
            EventID=4688, TimeCreated=ts(5), Computer="PC-MARIE-DUPONT",
            Channel="Security", Provider="Microsoft-Windows-Security-Auditing",
            EventData={"NewProcessName": "C:\\Users\\marie.dupont\\Downloads\\facture.exe",
                       "CommandLine": "facture.exe --install-silently",
                       "ParentProcessName": "explorer.exe",
                       "SubjectUserName": "marie.dupont"}
        ),
        # 3. Tentative destruction sauvegardes (Event 4688 - Ransomware indicator)
        WindowsSecurityEvent(
            EventID=4688, TimeCreated=ts(30), Computer="PC-MARIE-DUPONT",
            Channel="Security", Provider="Microsoft-Windows-Security-Auditing",
            EventData={"NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                       "CommandLine": "vssadmin delete shadows /all /quiet",
                       "SubjectUserName": "marie.dupont"}
        ),
        # 4. Création de fichier chiffré (Event Sysmon 11)
        WindowsSecurityEvent(
            EventID=11, TimeCreated=ts(45), Computer="SRV-CONTRATS-01",
            Channel="Microsoft-Windows-Sysmon/Operational",
            Provider="Microsoft-Windows-Sysmon",
            EventData={"TargetFilename": "\\\\SRV-CONTRATS-01\\data\\contrats\\client_001.ENCRYPTED",
                       "CreationUtcTime": ts(45)}
        ),
        # 5. Journaux effacés (Event 1102 - Defense Evasion)
        WindowsSecurityEvent(
            EventID=1102, TimeCreated=ts(60), Computer="PC-MARIE-DUPONT",
            Channel="Security", Provider="Microsoft-Windows-Security-Auditing",
            EventData={"SubjectUserName": "marie.dupont",
                       "SubjectDomainName": "ASSURANCE-CORP"}
        ),
    ]


def parse_and_analyze_logs(raw_logs: list) -> dict:
    """
    Pipeline complet d'analyse SIEM :
    1. Parsing → 2. Corrélation MITRE → 3. Scoring → 4. Export Sentinel
    """
    print("\n" + "="*60)
    print("  PIPELINE SIEM — Ingestion & Analyse de Logs Réels")
    print("="*60)

    results = {"total": len(raw_logs), "alerts": 0, "critical": 0, "events": []}

    for i, event in enumerate(raw_logs, 1):
        enriched = correlate_with_mitre(event)
        sentinel_format = enriched.to_sentinel_format()
        results["events"].append(sentinel_format)

        icon = "🔴" if enriched.severity == "Critical" else \
               "🟠" if enriched.severity == "High"     else \
               "🟡" if enriched.severity == "Medium"   else "🟢"

        print(f"\n  [{i}/{len(raw_logs)}] EventID: {enriched.EventID} {icon} [{enriched.severity}]")
        print(f"    Host      : {enriched.Computer}")
        print(f"    Desc      : {CRITICAL_EVENT_IDS.get(enriched.EventID, {}).get('description', 'Inconnu')}")
        if enriched.mitre_technique:
            print(f"    MITRE     : {enriched.mitre_technique} [{enriched.mitre_tactic}]")
        if enriched.soc_alert:
            print(f"    ⚠️  ALERTE SOC DÉCLENCHÉE — Playbook activé automatiquement")
            results["alerts"] += 1
        if enriched.severity == "Critical":
            results["critical"] += 1

    print(f"\n{'='*60}")
    print(f"  Résumé : {results['total']} logs analysés")
    print(f"           {results['alerts']} alertes SOC déclenchées")
    print(f"           {results['critical']} événements CRITIQUES")
    print("="*60)

    return results


if __name__ == "__main__":
    print("Génération d'une séquence de logs Windows réalistes (Kill Chain Ransomware)...")
    sample_logs = generate_realistic_log_sample()
    analysis_results = parse_and_analyze_logs(sample_logs)

    # Export JSON pour ingestion via azure_sentinel_connector.py
    import os
    os.makedirs("reports/generated", exist_ok=True)
    output_path = "reports/generated/winlog_analysis.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(analysis_results, f, indent=2, ensure_ascii=False)
    print(f"\n  📄 Export JSON Sentinel : {output_path}")
    print("  ➡️  Envoi vers Sentinel : python scripts/cloud/azure_sentinel_connector.py")
