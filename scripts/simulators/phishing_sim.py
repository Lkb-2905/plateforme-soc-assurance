"""
================================================================
SIMULATEUR D'INCIDENT – PHISHING / SPEAR-PHISHING
Plateforme SOC Assurantielle
scripts/simulators/phishing_sim.py
================================================================
Simule une campagne de spear-phishing ciblant des employés
d'un groupe assurantiel (finance, RH, direction).

Phases simulées :
  1. Réception d'un email malveillant avec URL / pièce jointe
  2. Vérification CTI de l'URL (module threat_intelligence.py)
  3. Simulation du clic utilisateur → Alerte haute priorité
  4. Envoi des logs vers Wazuh via Syslog

Tactique MITRE : T1566.001 – Spearphishing Attachment
================================================================
"""

import sys
import os
import socket
import time
import random
import logging
import json
from datetime import datetime, timezone
from faker import Faker

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

# Configuration
WAZUH_HOST = "localhost"
WAZUH_PORT = 514
DELAY      = 0.5

fake = Faker("fr_FR")
logging.basicConfig(format="%(asctime)s [PHISHING-SIM] %(levelname)s – %(message)s", level=logging.INFO)
logger = logging.getLogger()

# ─── Données de simulation ─────────────────────────────────────
PHISHING_URLS = [
    "http://microsoft-secure-login.phishingdemo.net/auth",
    "http://portail-assurance-signin.evil.com/reset",
    "http://sharepoint-docview.ngrok.io/invoice_2024.pdf",
    "http://zoom-meeting-update.suspicious-domain.ru/install",
]

PHISHING_SENDERS = [
    "noreply@microsoft365-alerts.com",
    "support@assurance-portail-securite.fr",
    "direction@groupe-assurance-corp.net",
]

ATTACK_SUBJECTS = [
    "ACTION REQUISE : Mise à jour de vos identifiants SSO",
    "Document partagé – Rapport sinistres Q4 2024",
    "Invitation réunion Direction – Renouvellement contrats cadre",
    "Alerte sécurité : Connexion suspecte sur votre compte",
]

TARGETS = [
    {"name": "Marie Dupont",  "email": "m.dupont@assurance-demo.fr",   "dept": "Finance",   "role": "Responsable Comptabilité"},
    {"name": "Pierre Martin", "email": "p.martin@assurance-demo.fr",   "dept": "RH",        "role": "DRH"},
    {"name": "Sophie Bernard","email": "s.bernard@assurance-demo.fr",  "dept": "Direction", "role": "DSI"},
    {"name": "Lucas Moreau",  "email": "l.moreau@assurance-demo.fr",   "dept": "IT",        "role": "Administrateur Système"},
]

ATTACKER_DOMAIN = "185.220.101." + str(random.randint(1, 10))


def send_syslog(message: str):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        syslog_msg = f"<14>1 {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} MAIL-GW phishing-sim - - - {message}"
        sock.sendto(syslog_msg.encode("utf-8"), (WAZUH_HOST, WAZUH_PORT))
        sock.close()
    except Exception:
        pass


def log_event(event: dict):
    log_line = json.dumps(event, ensure_ascii=False)
    logger.info(log_line)
    send_syslog(log_line)


def simulate_email_reception(target: dict, phishing_url: str, sender: str, subject: str):
    """Simule la réception de l'email de phishing."""
    logger.info(f"\n📧 Email de phishing envoyé à {target['name']} ({target['role']})")

    event = {
        "event_type": "PHISHING_URL_DETECTED",
        "host": "MAIL-GW-01",
        "email.sender": sender,
        "email.recipient": target["email"],
        "user.name": target["name"],
        "user.department": target["dept"],
        "user.role": target["role"],
        "email.subject": subject,
        "email.url_detected": phishing_url,
        "email.has_attachment": True,
        "file.extension": random.choice([".docm", ".xlsm", ".pdf"]),
        "attachment_name": "SUSPICIOUS_ATTACHMENT",
        "source_ip": ATTACKER_DOMAIN,
        "source_geo_country": random.choice(["RU", "CN", "KP", "BY"]),
        "cti_verified": False,
        "description": f"Email de phishing détecté : URL malveillante dans message à {target['email']}",
        "mitre_technique": "T1566.001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    log_event(event)
    time.sleep(DELAY)
    return event


def simulate_cti_verification(phishing_url: str, target: dict) -> dict:
    """Simule la vérification CTI de l'URL (ou fait appel au vrai module si APIs configurées)."""
    logger.info(f"   🔍 Vérification CTI de l'URL : {phishing_url}")
    time.sleep(0.5)

    # Simulation du résultat CTI (score élevé = malveillant)
    cti_result = {
        "indicator_type": "url",
        "value": phishing_url,
        "threat_score": random.randint(75, 98),
        "is_malicious": True,
        "sources": ["AlienVault OTX", "AbuseIPDB"],
        "tags": ["phishing", "credential-harvesting"],
    }

    event = {
        "event_type": "CTI_LOOKUP_RESULT",
        "host": "CTI-MODULE",
        "indicator_type": cti_result["indicator_type"],
        "indicator_value": phishing_url,
        "threat_score": cti_result["threat_score"],
        "is_malicious": cti_result["is_malicious"],
        "cti_sources": cti_result["sources"],
        "target_user": target["email"],
        "description": f"IoC URL confirmé malveillant par CTI – Score: {cti_result['threat_score']}/100",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    log_event(event)
    logger.info(f"   🔴 URL confirmée malveillante – Score CTI: {cti_result['threat_score']}/100")
    return cti_result


def simulate_user_click(target: dict, phishing_url: str):
    """Simule le clic de l'utilisateur sur le lien de phishing."""
    logger.info(f"   ⚠️  L'utilisateur {target['name']} a CLIQUÉ sur le lien !")

    event = {
        "event_type": "USER_CLICKED_PHISHING_URL",
        "host": f"PC-{target['dept'].upper()}-{random.randint(100,199)}",
        "user.name": target["name"],
        "user.email": target["email"],
        "user.role": target["role"],
        "url_clicked": phishing_url,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "source_ip": f"192.168.{random.randint(1,10)}.{random.randint(1,254)}",
        "description": f"ALERTE – {target['name']} a cliqué sur une URL de phishing confirmée",
        "priority": "HIGH",
        "mitre_technique": "T1204.001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    log_event(event)
    time.sleep(DELAY)


def simulate_credential_submission(target: dict):
    """Simule la soumission de credentials sur la fausse page."""
    logger.info(f"   🔑 Credentials soumis sur la page de phishing !")

    event = {
        "event_type": "CREDENTIAL_SUBMISSION_SUSPECTED",
        "host": "PROXY-WEBFILTER",
        "user.name": target["name"],
        "user.email": target["email"],
        "description": "Soumission de formulaire détectée vers un domaine malveillant (probable vol de credentials)",
        "http_method": "POST",
        "mitre_technique": "T1056",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    log_event(event)


def run_simulation():
    """Exécute la simulation complète d'un scénario de spear-phishing."""
    logger.info("=" * 60)
    logger.info("🎣 SIMULATION PHISHING – DÉBUT")
    logger.info("=" * 60)

    # Choisir une cible aléatoire parmi les profils définis
    target   = random.choice(TARGETS)
    url      = random.choice(PHISHING_URLS)
    sender   = random.choice(PHISHING_SENDERS)
    subject  = random.choice(ATTACK_SUBJECTS)

    logger.info(f"   Cible     : {target['name']} – {target['role']}")
    logger.info(f"   Scénario  : {subject}")

    # Phases du scénario
    simulate_email_reception(target, url, sender, subject)
    simulate_cti_verification(url, target)
    time.sleep(1)

    # Simulation probabiliste du clic (80% de chance)
    if random.random() < 0.8:
        simulate_user_click(target, url)
        time.sleep(0.5)
        simulate_credential_submission(target)

    logger.info("\n" + "=" * 60)
    logger.info("🎣 SIMULATION PHISHING TERMINÉE")
    logger.info("   → Vérifiez Wazuh (règles 100010, 100011, 100012)")
    logger.info("   → Le Playbook Phishing SOAR devrait être déclenché")
    logger.info("=" * 60)


if __name__ == "__main__":
    run_simulation()
