import requests
import sys
import json
from datetime import datetime

# AlienVault OTX (Open Threat Exchange) Public API
# C'est l'un des réseaux de renseignement sur les menaces les plus utilisés par les SOC.
OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

def check_otx_reputation(ioc: str, ioc_type: str = "IPv4"):
    """
    Interroge l'API OTX d'AlienVault pour vérifier la réputation d'un Indicateur de Compromission (IOC).
    Type supporté ici : IPv4, domain, file (hash)
    """
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [CTI-OTX] 🔍 Analyse de l'Indicateur : {ioc} (Type: {ioc_type})")
    
    url = f"{OTX_BASE_URL}/{ioc_type}/{ioc}/general"
    
    # Header requis par l'API (Même en requête publique, de simples User-Agents suffisent souvent)
    headers = {
        "User-Agent": "Assurance-SOC-Simulation-Client/1.0"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        # Alienvault renvoie 404 si l'IP n'a jamais été analysée (ce qui est bon signe)
        if response.status_code == 404:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [CTI-OTX] 🟢 IOC Inconnu d'AlienVault. Aucun risque identifié.")
            return {"ioc": ioc, "malicious": False, "score": 0, "pulses": 0}
            
        response.raise_for_status()
        data = response.json()
        
    except requests.exceptions.RequestException as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [CTI-OTX] ❌ Erreur d'API OTX : {e}")
        return {"ioc": ioc, "malicious": False, "score": -1, "error": str(e)}

    # AlienVault compte la menace en "Pulses" (Campagnes d'attaques remontées par la commnauté)
    pulse_info = data.get("pulse_info", {})
    pulse_count = pulse_info.get("count", 0)
    
    if pulse_count > 0:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [CTI-OTX] 🔴 ALERTE CTI : L'IOC est présent dans {pulse_count} campagnes d'attaques (Pulses) !")
        
        # On extrait les noms des campagnes pour contextualiser
        pulses = pulse_info.get("pulses", [])
        tags_found = set()
        for p in pulses[:3]: # Prendre les 3 dernières
            tags_found.update(p.get("tags", []))
            print(f"   ↳ Campagne identifiée : {p.get('name')}")
            
        print(f"   ↳ Tags Malveillants : {', '.join(list(tags_found)[:5])}")
        
        return {
            "ioc": ioc,
            "malicious": True,
            "score": min(100, pulse_count * 15), # Simulation de score de risque (15 pts par campagne)
            "pulses": pulse_count,
            "tags": list(tags_found)
        }
    else:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [CTI-OTX] 🟢 L'IOC est connu mais n'est lié à aucune campagne malveillante active.")
        return {"ioc": ioc, "malicious": False, "score": 0, "pulses": 0}

if __name__ == "__main__":
    # Test avec une IP connue des hackers (Cobalt Strike, Scanners, etc) ou une IP inoffensive
    
    test_ips = [
        "185.220.101.5",  # IP souvent impliquée dans les menaces (Tor/Scanners)
        "8.8.8.8"         # IP inoffensive (Google DNS)
    ]
    
    print("="*60)
    print("LANCEMENT DU MODULE D'ENRICHISSEMENT CTI - ALIENVAULT OTX")
    print("="*60)
    
    results = []
    for ip in test_ips:
        res = check_otx_reputation(ip, "IPv4")
        results.append(res)
        print("-" * 60)
        
    # Exporter le résultat pour le SOAR
    with open("reports/generated/otx_cti_lookup.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
        
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [CTI-OTX] 📄 Résultat de l'enrichissement exporté dans otx_cti_lookup.json")
