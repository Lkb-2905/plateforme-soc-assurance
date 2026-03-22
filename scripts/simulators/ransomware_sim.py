"""
================================================================
SIMULATEUR D'INCIDENT – RANSOMWARE
Plateforme SOC Assurantielle
scripts/simulators/ransomware_sim.py
================================================================
Simule une attaque ransomware sur un serveur de fichiers
contenant des données sensibles assurantielles (contrats, sinistres).

Actions simulées :
  1. Génération de logs de renommage massif de fichiers
  2. Détection d'extensions de chiffrement connues
  3. Tentative de connexion SMB latérale (mouvement latéral)
  4. Envoi des logs vers Wazuh via Syslog (UDP 514)
  5. Déclenchement du Playbook SOAR

Tactique MITRE : T1486 – Data Encrypted for Impact
================================================================
"""

import socket
import time
import random
import logging
import json
from datetime import datetime, timezone
from faker import Faker

# Configuration
WAZUH_HOST     = "localhost"
WAZUH_PORT     = 514          # Port Syslog Wazuh
LOG_BATCH_SIZE = 25           # Nombre de fichiers "chiffrés" simulés
DELAY_BETWEEN  = 0.2          # Délai entre chaque log (secondes)

fake = Faker("fr_FR")
logging.basicConfig(format="%(asctime)s [RANSOMWARE-SIM] %(levelname)s – %(message)s", level=logging.INFO)
logger = logging.getLogger()

# ─── Constantes métier assurantiel ────────────────────────────
SENSITIVE_FILE_PATHS = [
    "/data/contrats/particuliers/",
    "/data/contrats/entreprises/",
    "/data/sinistres/auto/",
    "/data/sinistres/habitation/",
    "/data/rh/",
    "/data/comptabilite/",
    "/data/actuariat/modeles/",
    "/partage/direction/",
]

SENSITIVE_EXTENSIONS = [".pdf", ".docx", ".xlsx", ".csv", ".json"]
RANSOMWARE_EXTENSIONS = [".locked", ".encrypted", ".CONTI", ".ryuk", ".crypt"]

VICTIM_HOST = f"SRVFILE-{random.randint(10, 99):02d}"
ATTACKER_IP = f"10.{random.randint(0,9)}.{random.randint(0,255)}.{random.randint(1,254)}"


def send_syslog(message: str, host: str = WAZUH_HOST, port: int = WAZUH_PORT) -> bool:
    """Envoie un message Syslog UDP vers Wazuh."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Format Syslog RFC 5424 simplifié
        syslog_msg = f"<14>1 {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} {VICTIM_HOST} ransomware-sim - - - {message}"
        sock.sendto(syslog_msg.encode("utf-8"), (host, port))
        sock.close()
        return True
    except Exception as e:
        logger.debug(f"Syslog non envoyé (Wazuh non démarré ?): {e}")
        return False


def log_event(event: dict, send_to_wazuh: bool = True):
    """Logge un événement et l'envoie optionnellement à Wazuh."""
    log_line = json.dumps(event, ensure_ascii=False)
    logger.info(log_line)
    if send_to_wazuh:
        send_syslog(log_line)


def simulate_initial_access():
    """Phase 1 : Simulation de l'accès initial (exécution de payload)."""
    logger.info("=" * 60)
    logger.info("🔴 SIMULATION RANSOMWARE – DÉBUT")
    logger.info(f"   Hôte victime : {VICTIM_HOST}")
    logger.info(f"   IP attaquant : {ATTACKER_IP}")
    logger.info("=" * 60)

    event = {
        "event_type": "process_creation",
        "description": "Exécution de processus suspect depuis un répertoire temporaire",
        "host": VICTIM_HOST,
        "source_ip": ATTACKER_IP,
        "process_name": "svchost32.exe",          # Faux nom (double extension)
        "process_path": "C:\\Users\\Public\\Downloads\\",
        "parent_process": "winword.exe",           # Lancé depuis Word → Macro
        "user": fake.user_name(),
        "mitre_technique": "T1566.001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    log_event(event)
    time.sleep(1)


def simulate_file_encryption():
    """Phase 2 : Simulation du chiffrement massif de fichiers sensibles."""
    logger.info("\n📁 Simulation du chiffrement des fichiers assurantiels...")

    total_encrypted = 0
    for i in range(LOG_BATCH_SIZE):
        folder        = random.choice(SENSITIVE_FILE_PATHS)
        original_ext  = random.choice(SENSITIVE_EXTENSIONS)
        encrypted_ext = random.choice(RANSOMWARE_EXTENSIONS)
        filename      = f"{fake.last_name()}_{fake.numerify('####')}{original_ext}"
        encrypted_name = filename + encrypted_ext

        event = {
            "event_type": "RANSOMWARE_FILE_RENAME",      # Matche la règle Wazuh 100001
            "host": VICTIM_HOST,
            "source_ip": ATTACKER_IP,
            "file.path": folder + filename,
            "file.name_after": folder + encrypted_name,
            "file.extension": encrypted_ext,
            "description": f"Fichier renommé avec extension de chiffrement: {encrypted_name}",
            "data_category": "PII" if "/rh/" in folder or "/contrats/" in folder else "Financial",
            "mitre_technique": "T1486",
            "encrypted_file_signal": "ENCRYPTED_EXTENSION_DETECTED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        log_event(event)
        total_encrypted += 1
        time.sleep(DELAY_BETWEEN)

    logger.info(f"\n✅ {total_encrypted} fichiers « chiffrés » simulés → Règle 100002 devrait se déclencher.")
    return total_encrypted


def simulate_ransom_note():
    """Phase 3 : Dépôt d'une note de rançon (README_HOW_TO_DECRYPT.txt)."""
    event = {
        "event_type": "file_creation",
        "host": VICTIM_HOST,
        "file.name": "README_HOW_TO_DECRYPT.txt",
        "file.path": "/data/",
        "description": "Note de rançon déposée sur le partage réseau",
        "mitre_technique": "T1486",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    log_event(event)


def simulate_lateral_movement():
    """Phase 4 : Tentative de mouvement latéral via SMB."""
    targets = [f"10.{random.randint(0,9)}.0.{i}" for i in random.sample(range(1, 50), 5)]
    for target in targets:
        event = {
            "event_type": "network_connection_attempt",
            "host": VICTIM_HOST,
            "source_ip": ATTACKER_IP,
            "destination_ip": target,
            "destination_port": 445,          # SMB
            "protocol": "TCP",
            "description": f"Tentative de connexion SMB vers {target} (mouvement latéral)",
            "mitre_technique": "T1021.002",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        log_event(event)
        time.sleep(0.1)


def run_simulation():
    """Exécute la simulation complète du scénario Ransomware."""
    simulate_initial_access()
    count = simulate_file_encryption()
    simulate_ransom_note()
    simulate_lateral_movement()

    logger.info("\n" + "=" * 60)
    logger.info("🔴 SIMULATION RANSOMWARE TERMINÉE")
    logger.info(f"   {count} fichiers assurantiels simulés comme chiffrés")
    logger.info("   → Vérifiez le dashboard Wazuh (règles 100001, 100002)")
    logger.info("   → Un Playbook SOAR devrait s'être déclenché dans Shuffle")
    logger.info("=" * 60)


if __name__ == "__main__":
    run_simulation()
