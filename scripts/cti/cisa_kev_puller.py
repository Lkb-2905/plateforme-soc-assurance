import requests
import json
import os
from datetime import datetime

# URL officielle du flux CISA KEV (Known Exploited Vulnerabilities)
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Définition du parc applicatif simulé de l'assurance (pour contextualisation)
# Si une vulnérabilité touche l'un de ces produits, c'est une alerte P1
ASSURANCE_ASSETS = [
    "FortiOS",          # Utilisé pour les VPN des courtiers
    "Exchange Server",  # Messagerie corporate
    "Windows Server",   # Serveurs AD et fichiers contrats
    "Confluence",       # Wiki interne projets
    "Guidewire"         # Simulateur : Logiciel métier Assurance
]

def pull_and_analyze_kev():
    """
    Télécharge le catalogue CISA KEV et vérifie si des CVE récemment exploitées
    touchent le SI de l'entreprise d'assurance.
    """
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [CTI] 📡 Téléchargement du flux officiel CISA KEV...")
    
    try:
        response = requests.get(CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        kev_data = response.json()
    except Exception as e:
        print(f"❌ Erreur lors du téléchargement : {e}")
        return

    vulnerabilities = kev_data.get("vulnerabilities", [])
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [CTI] ✅ {len(vulnerabilities)} vulnérabilités connues exploitées analysées.")

    alerts_generated = []

    # On parcours les vulnérabilités pour voir si elles touchent notre SI
    for vuln in vulnerabilities:
        product = vuln.get("product", "")
        vendor = vuln.get("vendorProject", "")
        
        # Vérification si le produit est dans notre liste d'actifs critiques
        for asset in ASSURANCE_ASSETS:
            if asset.lower() in product.lower() or asset.lower() in vendor.lower():
                # On ne garde que les CVE ajoutées récemment (simulation: post-2023 pour limiter le bruit)
                date_added = vuln.get("dateAdded", "1970-01-01")
                if date_added >= "2023-01-01":
                    alert = {
                        "cve_id": vuln.get("cveID"),
                        "asset_impacted": asset,
                        "vulnerability_name": vuln.get("vulnerabilityName"),
                        "action_due_date": vuln.get("dueDate"),
                        "ransomware_campaign_use": vuln.get("knownRansomwareCampaignUse", "Unknown")
                    }
                    alerts_generated.append(alert)

    # Filtrer les doublons potentiels et générer un rapport
    _generate_cti_bulletin(alerts_generated)

def _generate_cti_bulletin(alerts):
    """
    Génère un bulletin CTI structuré pour l'équipe SOC si des menaces sont détectées.
    """
    if not alerts:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [CTI] 🟢 Aucun actif de l'assurance n'est actuellement ciblé dans le KEV.")
        return

    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] [CTI] 🚨 ALERTE : {len(alerts)} CVE critiques nécessitent une action immédiate !")
    
    # On prend juste le Top 3 pour l'affichage terminal
    print("-" * 60)
    for alert in alerts[:3]:
        print(f"🔴 CVE        : {alert['cve_id']}")
        print(f"🏢 Actif ciblé: {alert['asset_impacted']} (Utilisation Métier Critique)")
        print(f"🐛 Menace     : {alert['vulnerability_name']}")
        print(f"💀 Ransomware : {'⚠️ CONNU POUR RANSOMWARE' if alert['ransomware_campaign_use'] == 'Known' else 'Non qualifié'}")
        print(f"⏰ Patch exigé: {alert['action_due_date']}")
        print("-" * 60)
        
    # Enregistrer un log json simulé pour intégration SIEM/Dashboard
    report_path = os.path.join(os.path.dirname(__file__), "..", "..", "reports", "generated", "cisa_kev_bulletin.json")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump({"timestamp": datetime.now().isoformat(), "critical_assets_at_risk": len(alerts), "cve_list": alerts}, f, indent=4)
        
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [CTI] 📄 Bulletin JSON généré pour ingestion SIEM : cisa_kev_bulletin.json")

if __name__ == "__main__":
    pull_and_analyze_kev()
