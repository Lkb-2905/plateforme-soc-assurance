"""
================================================================
SIMULATEUR D'INCIDENT – COMPROMISSION DE COMPTE (IMPOSSIBLE TRAVEL)
Plateforme SOC Assurantielle
scripts/simulators/account_compromise_sim.py
================================================================
Simule une compromission de compte VIP (DSI, CFO, RSSI) via
l'exploitation d'un mécanisme "Impossible Travel" :
  → Connexion normale depuis Paris
  → puis connexion depuis un pays différent 10 minutes après

Ce scénario est particulièrement réaliste dans le contexte
assurantiel où les comptes VIP ont accès aux données de 
réassurance, actuariat et contrats stratégiques.

Tactique MITRE : T1078 – Valid Accounts (T1078.002 : Domain Accounts)
================================================================
"""

import socket
import time
import random
import logging
import json
from datetime import datetime, timezone, timedelta
from faker import Faker

WAZUH_HOST = "localhost"
WAZUH_PORT = 514

fake = Faker("fr_FR")
logging.basicConfig(format="%(asctime)s [ACCOUNT-SIM] %(levelname)s – %(message)s", level=logging.INFO)
logger = logging.getLogger()

# ─── Profils VIP ciblés ───────────────────────────────────────
VIP_ACCOUNTS = [
    {"name": "Jean-Claude Mercier", "username": "jc.mercier",    "role": "ceo",      "dept": "Direction Générale"},
    {"name": "Dr. Isabelle Renard", "username": "i.renard",      "role": "rssi",     "dept": "SSI"},
    {"name": "Thomas Lefort",       "username": "t.lefort",      "role": "cfo",      "dept": "Finance"},
    {"name": "Amandine Petit",      "username": "a.petit",       "role": "admin",    "dept": "DSI"},
    {"name": "François Garnier",    "username": "f.garnier",     "role": "director", "dept": "Actuariat"},
]

# ─── Géolocalisation simulée ───────────────────────────────────
LOCATIONS = {
    "Paris, France":    {"ip": "82.64.50.12",    "country": "FR", "risk": False},
    "Lyon, France":     {"ip": "80.12.45.200",   "country": "FR", "risk": False},
    "Moscou, Russie":   {"ip": "95.142.46.8",    "country": "RU", "risk": True},
    "Lagos, Nigeria":   {"ip": "105.112.7.33",   "country": "NG", "risk": True},
    "Pékin, Chine":     {"ip": "125.64.94.194",  "country": "CN", "risk": True},
    "Pyongyang, RPDC":  {"ip": "175.45.176.3",   "country": "KP", "risk": True},
    "Bucarest, Roumanie": {"ip": "79.112.86.4",  "country": "RO", "risk": True},
}

KNOWN_LOCATIONS = ["Paris, France", "Lyon, France"]
HIGH_RISK_LOCATIONS = [k for k, v in LOCATIONS.items() if v["risk"]]


def send_syslog(message: str):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        syslog_msg = f"<14>1 {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} AD-SRV-01 account-sim - - - {message}"
        sock.sendto(syslog_msg.encode("utf-8"), (WAZUH_HOST, WAZUH_PORT))
        sock.close()
    except Exception:
        pass


def log_event(event: dict):
    log_line = json.dumps(event, ensure_ascii=False)
    logger.info(log_line)
    send_syslog(log_line)


def simulate_normal_login(account: dict, location_name: str) -> datetime:
    """Phase 1 : Connexion légitime depuis l'emplacement habituel."""
    location = LOCATIONS[location_name]
    login_time = datetime.now(timezone.utc)

    logger.info(f"\n✅ Connexion normale : {account['name']} depuis {location_name}")
    event = {
        "event_type": "authentication_success",
        "host": "AD-SRV-01",
        "user.name": account["name"],
        "user.username": account["username"],
        "user.role": account["role"],
        "user.department": account["dept"],
        "source_ip": location["ip"],
        "source_geo_city": location_name.split(",")[0],
        "source_geo_country": location["country"],
        "auth_method": "NTLM",
        "mfa_used": True,
        "description": f"Connexion Active Directory réussie pour {account['username']}",
        "mitre_technique": "T1078",
        "timestamp": login_time.isoformat(),
    }
    log_event(event)
    return login_time


def simulate_impossible_travel_login(account: dict, attack_location_name: str, normal_login_time: datetime):
    """Phase 2 : Connexion depuis un pays à risque peu de temps après la connexion normale."""
    location = LOCATIONS[attack_location_name]

    # Calcul du temps depuis la connexion normale (simulé à 10-15 min après)
    travel_minutes = random.randint(10, 20)
    attack_time = datetime.now(timezone.utc)
    travel_time = travel_minutes  # Simulé

    logger.info(f"\n🔴 IMPOSSIBLE TRAVEL : {account['name']} depuis {attack_location_name} ({travel_minutes} min après Paris !)")

    # Connexion depuis pays à risque
    event_geo = {
        "event_type": "LOGIN_FROM_HIGH_RISK_COUNTRY",
        "host": "AD-SRV-01",
        "user.name": account["name"],
        "user.username": account["username"],
        "user.role": account["role"],
        "user.department": account["dept"],
        "source_ip": location["ip"],
        "source_geo.country_name": attack_location_name.split(",")[-1].strip(),
        "source_geo_country": location["country"],
        "description": f"Connexion depuis pays à risque élevé pour compte {account['username']}",
        "mitre_technique": "T1078",
        "timestamp": attack_time.isoformat(),
    }
    log_event(event_geo)
    time.sleep(0.5)

    # Déclenchement de la règle Impossible Travel
    event_it = {
        "event_type": "IMPOSSIBLE_TRAVEL_DETECTED",
        "host": "ANALYTICS-SOC",
        "user.name": account["name"],
        "user.username": account["username"],
        "user.role": account["role"],
        "src_city_1": "Paris",
        "src_city_2": attack_location_name.split(",")[0],
        "travel_time_minutes": travel_time,
        "first_login_ip": LOCATIONS["Paris, France"]["ip"],
        "second_login_ip": location["ip"],
        "second_login_country": location["country"],
        "mfa_used": False,      # Attaquant n'a pas le MFA → connexion sans 2FA
        "description": f"IMPOSSIBLE TRAVEL : {account['name']} – Paris → {attack_location_name.split(',')[0]} en {travel_time} min",
        "mitre_technique": "T1078.002",
        "timestamp": attack_time.isoformat(),
    }
    log_event(event_it)
    time.sleep(0.3)


def simulate_data_access(account: dict):
    """Phase 3 : Simulation d'accès à des données sensibles après compromission."""
    sensitive_data = [
        "/data/actuariat/modeles_reserving_2024.xlsx",
        "/data/reassurance/traites_2024_2025.pdf",
        "/data/rh/grilles_salaires_cadres.xlsx",
        "/data/direction/pv_conseil_administration.docx",
    ]

    for path in random.sample(sensitive_data, 2):
        event = {
            "event_type": "sensitive_data_access",
            "host": "SRVFILE-01",
            "user.name": account["name"],
            "user.username": account["username"],
            "file.path": path,
            "access_type": "READ",
            "description": f"Accès à donnée sensible par compte potentiellement compromis : {path}",
            "data_classification": "CONFIDENTIEL",
            "mitre_technique": "T1083",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        log_event(event)
        time.sleep(0.2)


def run_simulation():
    """Exécute la simulation complète du scénario Impossible Travel."""
    logger.info("=" * 60)
    logger.info("👤 SIMULATION COMPROMISSION DE COMPTE – DÉBUT")
    logger.info("=" * 60)

    account     = random.choice(VIP_ACCOUNTS)
    normal_loc  = random.choice(KNOWN_LOCATIONS)
    attack_loc  = random.choice(HIGH_RISK_LOCATIONS)

    logger.info(f"   Compte VIP ciblé  : {account['name']} ({account['role'].upper()})")
    logger.info(f"   Connexion normale : {normal_loc}")
    logger.info(f"   Connexion suspecte: {attack_loc}")

    # Phases du scénario
    login_time = simulate_normal_login(account, normal_loc)
    time.sleep(1.5)
    simulate_impossible_travel_login(account, attack_loc, login_time)
    time.sleep(0.5)
    simulate_data_access(account)

    logger.info("\n" + "=" * 60)
    logger.info("👤 SIMULATION COMPROMISSION DE COMPTE TERMINÉE")
    logger.info("   → Vérifiez Wazuh (règles 100020, 100021, 100022)")
    logger.info("   → Un incident P1 devrait être créé dans Shuffle")
    logger.info("=" * 60)


if __name__ == "__main__":
    run_simulation()
