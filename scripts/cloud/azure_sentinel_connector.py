#!/usr/bin/env python3
"""
=======================================================================
 MODULE CLOUD — Connecteur Microsoft Sentinel / Azure Log Analytics
=======================================================================
 Ce script envoie des alertes SOC vers un vrai workspace Azure Log Analytics
 via l'API Data Collector (REST) avec authentification HMAC-SHA256 réelle.

 Prérequis (gratuit) :
   1. Compte Azure Free Tier : https://azure.microsoft.com/free
   2. Créer un "Log Analytics Workspace" dans Azure
   3. Copier le "Workspace ID" et la "Primary Key" dans votre .env

 Une fois connecté, les logs sont visibles dans Microsoft Sentinel
 avec la requête KQL : SOC_SecurityEvents_CL | order by TimeGenerated desc

 Auteur : KAMENI TCHOUATCHEU GAETAN BRUNEL — ESIEA 2026
=======================================================================
"""

import requests
import hashlib
import hmac
import base64
import json
import datetime
import os
from dotenv import load_dotenv

load_dotenv()

# ─── Configuration Azure ───────────────────────────────────────────────────
# Renseignez ces valeurs dans votre fichier .env
# (cf. .env.example pour le modèle)
AZURE_WORKSPACE_ID = os.getenv("AZURE_WORKSPACE_ID", "YOUR_WORKSPACE_ID")
AZURE_WORKSPACE_KEY = os.getenv("AZURE_WORKSPACE_KEY", "YOUR_PRIMARY_KEY")
LOG_TYPE             = "SOC_SecurityEvents"          # Nom de la table dans Sentinel
API_VERSION          = "2016-04-01"
# ───────────────────────────────────────────────────────────────────────────


def _build_signature(workspace_id: str, workspace_key: str, date: str,
                     content_length: int, method: str,
                     content_type: str, resource: str) -> str:
    """
    Construit la signature HMAC-SHA256 requise par l'API Azure Log Analytics.
    C'est le même mécanisme d'authentification que les APIs Microsoft enterprise.
    """
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash   = bytes(string_to_hash, encoding="utf-8")
    decoded_key     = base64.b64decode(workspace_key)
    encoded_hash    = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    return f"SharedKey {workspace_id}:{encoded_hash}"


def send_to_sentinel(events: list, dry_run: bool = False) -> dict:
    """
    Envoie un ou plusieurs événements SOC vers Azure Log Analytics / Sentinel.

    :param events:  Liste de dicts représentant les événements de sécurité.
    :param dry_run: Si True, affiche la requête sans l'envoyer (mode hors-ligne).
    :return:        Dictionnaire contenant le statut HTTP et les détails.
    """
    body = json.dumps(events)
    content_length = len(body)
    rfc1123_date   = datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    resource       = "/api/logs"
    content_type   = "application/json"

    print(f"\n{'='*60}")
    print("  MICROSOFT SENTINEL — Ingestion d'Alertes SOC")
    print(f"{'='*60}")
    print(f"  Workspace  : {AZURE_WORKSPACE_ID[:8]}... (masqué)")
    print(f"  Table      : {LOG_TYPE}_CL")
    print(f"  Événements : {len(events)}")
    print(f"  Date UTC   : {rfc1123_date}")
    print(f"  Auth       : HMAC-SHA256 ✅")

    if AZURE_WORKSPACE_ID == "YOUR_WORKSPACE_ID" or AZURE_WORKSPACE_KEY == "YOUR_PRIMARY_KEY":
        print("\n  ⚠️  Mode DÉMONSTRATION : configurez AZURE_WORKSPACE_ID et Key dans .env")
        print("      pour activer l'envoi réel vers Microsoft Sentinel.")
        print(f"  [DRY RUN APPLIQUÉ] Payload : {body[:200]}...")
        return {"status": "demo_mode", "events_count": len(events)}

    # On ne construit la signature que s'il y a une vraie clé configurée
    signature = _build_signature(
        AZURE_WORKSPACE_ID, AZURE_WORKSPACE_KEY,
        rfc1123_date, content_length,
        "POST", content_type, resource
    )

    uri = (
        f"https://{AZURE_WORKSPACE_ID}.ods.opinsights.azure.com"
        f"{resource}?api-version={API_VERSION}"
    )
    headers = {
        "Content-Type":  content_type,
        "Authorization": signature,
        "Log-Type":      LOG_TYPE,
        "x-ms-date":     rfc1123_date,
    }

    if dry_run:
        print("\n  [DRY RUN] Requête construite — aucun envoi effectif.")
        print(f"  Endpoint : {uri}")
        print(f"  Payload  : {body[:200]}...")
        return {"status": "dry_run", "events_count": len(events)}

    try:
        response = requests.post(uri, data=body, headers=headers, timeout=10)
        if response.status_code == 200:
            print(f"\n  ✅ Succès ! {len(events)} événements ingérés dans Sentinel.")
            print(f"  🔍 Requête KQL : {LOG_TYPE}_CL | order by TimeGenerated desc")
        else:
            print(f"\n  ❌ Erreur HTTP {response.status_code} : {response.text}")
        return {"status": response.status_code, "events_count": len(events)}
    except requests.RequestException as e:
        print(f"\n  ❌ Erreur réseau : {e}")
        return {"status": "error", "error": str(e)}


def build_soc_event(incident_type: str, severity: str, source_ip: str,
                    target_host: str, mitre_tactic: str, mitre_technique: str,
                    description: str) -> dict:
    """
    Formate un événement SOC au standard Azure Log Analytics / Sentinel.
    Ce format est compatible avec les règles d'Analytics de Microsoft Sentinel.
    """
    return {
        "TimeGenerated":     datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "IncidentType":      incident_type,
        "Severity":          severity,                  # High / Medium / Low / Critical
        "SourceIP":          source_ip,
        "TargetHost":        target_host,
        "MitreTactic":       mitre_tactic,
        "MitreTechnique":    mitre_technique,
        "Description":       description,
        "PlaybookTriggered": True,
        "Platform":          "SOC-Assurance-Platform-v4",
        "Sector":            "Insurance",
        "RGPDExposed":       severity in ("High", "Critical"),
    }


# ─── Programme de démonstration ────────────────────────────────────────────
if __name__ == "__main__":
    print("Génération des événements SOC au format Microsoft Sentinel...")

    # Simuler les 3 scénarios du SOC
    events = [
        build_soc_event(
            incident_type    = "Ransomware",
            severity         = "Critical",
            source_ip        = "185.220.101.5",
            target_host      = "SRV-CONTRATS-01",
            mitre_tactic     = "Impact",
            mitre_technique  = "T1486 - Data Encrypted for Impact",
            description      = "Chiffrement massif détecté sur le partage /data/contrats/. "
                               "Isolation EDR déclenchée. Cellule de crise notifiée.",
        ),
        build_soc_event(
            incident_type    = "Phishing",
            severity         = "High",
            source_ip        = "91.213.50.24",
            target_host      = "MAIL-GW-01",
            mitre_tactic     = "Initial Access",
            mitre_technique  = "T1566.001 - Spearphishing Link",
            description      = "Email de phishing ciblant le portail courtiers. "
                               "URL malveillante supprimée. Score OTX : 75/100.",
        ),
        build_soc_event(
            incident_type    = "Account Compromise",
            severity         = "High",
            source_ip        = "203.0.113.42",
            target_host      = "DC-AD-01",
            mitre_tactic     = "Initial Access",
            mitre_technique  = "T1078 - Valid Accounts / Impossible Travel",
            description      = "Connexion VIP depuis deux pays simultanés. "
                               "Token AD révoqué. MFA enforced.",
        ),
    ]

    # Envoi vers Sentinel (dry_run=True en l'absence de workspace configuré)
    result = send_to_sentinel(events, dry_run=False)
    print(f"\nRésultat : {result}")
