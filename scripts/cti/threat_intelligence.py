"""
================================================================
MODULE CTI – Cyber Threat Intelligence
Plateforme SOC Assurantielle – scripts/cti/threat_intelligence.py
================================================================
Ce module interroge plusieurs APIs CTI gratuites pour évaluer
la réputation des indicateurs de compromission (IoC) :
  → IPs   : AbuseIPDB + AlienVault OTX
  → URLs  : AlienVault OTX + VirusTotal
  → Hash  : VirusTotal + AlienVault OTX
  → Domaines : AlienVault OTX

Résultats formatés en STIX2 ou en JSON pour injection dans le SOAR.
================================================================
"""

import os
import json
import logging
import hashlib
import requests
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional
from dotenv import load_dotenv
import colorlog

# ─── Configuration du logging ─────────────────────────────────
handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    "%(log_color)s%(asctime)s [CTI] %(levelname)s%(reset)s – %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    log_colors={"DEBUG": "cyan", "INFO": "green", "WARNING": "yellow", "ERROR": "red", "CRITICAL": "bold_red"},
))
logger = logging.getLogger("SOC-CTI")
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

load_dotenv()

# ─── Clés API (depuis .env) ────────────────────────────────────
OTX_API_KEY        = os.getenv("OTX_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# ─── Seuils de risque ──────────────────────────────────────────
ABUSEIPDB_SCORE_THRESHOLD = 50   # Score  > 50 → IP malveillante
OTX_PULSE_THRESHOLD       = 3    # Pulses > 3  → Indicateur connu dans plusieurs campaigns
VT_DETECTION_THRESHOLD    = 5    # Détections > 5 moteurs → Fichier malveillant


@dataclass
class ThreatIndicator:
    """Représente un indicateur de compromission (IoC) enrichi."""
    indicator_type: str          # "ip", "url", "hash", "domain"
    value: str                   # La valeur brute de l'IoC
    threat_score: int            # 0 (bénin) → 100 (très malveillant)
    is_malicious: bool
    sources: list[str]           # APIs qui ont confirmé la menace
    tags: list[str]              # Catégories (phishing, ransomware, botnet…)
    country: Optional[str]       # Pays d'origine (pour les IPs)
    last_seen: Optional[str]     # Dernière observation
    raw_context: dict            # Données brutes pour documentation
    timestamp: str = ""

    def __post_init__(self):
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return asdict(self)

    def to_stix2_indicator(self) -> dict:
        """Retourne une représentation STIX2 simplifiée de l'IoC."""
        pattern_map = {
            "ip":     f"[ipv4-addr:value = '{self.value}']",
            "domain": f"[domain-name:value = '{self.value}']",
            "url":    f"[url:value = '{self.value}']",
            "hash":   f"[file:hashes.'MD5' = '{self.value}']",
        }
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{hashlib.md5(self.value.encode()).hexdigest()}",
            "name": f"[{self.indicator_type.upper()}] {self.value}",
            "pattern": pattern_map.get(self.indicator_type, ""),
            "pattern_type": "stix",
            "valid_from": self.timestamp,
            "confidence": self.threat_score,
            "labels": self.tags,
            "description": f"Source(s): {', '.join(self.sources)}",
        }


class CTIEnricher:
    """
    Enrichit les indicateurs de compromission (IoC) via plusieurs
    APIs CTI gratuites et retourne un ThreatIndicator structuré.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.timeout = 10

    # ─────────────────────────────────────────────────────────────
    # API 1 : ABUSEIPDB – Réputation d'IP
    # ─────────────────────────────────────────────────────────────
    def check_ip_abuseipdb(self, ip: str) -> dict:
        """Interroge AbuseIPDB pour évaluer la réputation d'une IP."""
        if not ABUSEIPDB_API_KEY:
            logger.warning("Clé AbuseIPDB non configurée, vérification ignorée.")
            return {}
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
            resp = self.session.get(url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            logger.info(f"AbuseIPDB [{ip}] → Score: {data.get('abuseConfidenceScore', 0)}%")
            return data
        except Exception as e:
            logger.error(f"Erreur AbuseIPDB pour {ip}: {e}")
            return {}

    # ─────────────────────────────────────────────────────────────
    # API 2 : ALIENVAULT OTX – Réputation universelle (IP/URL/Hash/Domain)
    # ─────────────────────────────────────────────────────────────
    def check_otx(self, indicator_type: str, value: str) -> dict:
        """Interroge AlienVault OTX pour n'importe quel type d'IoC."""
        if not OTX_API_KEY:
            logger.warning("Clé OTX non configurée, vérification ignorée.")
            return {}
        type_map = {
            "ip":     f"IPv4/{value}/general",
            "domain": f"domain/{value}/general",
            "url":    f"url/{requests.utils.quote(value, safe='')}/general",
            "hash":   f"file/{value}/general",
        }
        endpoint = type_map.get(indicator_type, "")
        if not endpoint:
            return {}
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/{endpoint}"
            headers = {"X-OTX-API-KEY": OTX_API_KEY}
            resp = self.session.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            logger.info(f"OTX [{indicator_type}:{value}] → {pulse_count} pulses")
            return data
        except Exception as e:
            logger.error(f"Erreur OTX pour {value}: {e}")
            return {}

    # ─────────────────────────────────────────────────────────────
    # API 3 : VIRUSTOTAL – Hash de fichiers (mode gratuit)
    # ─────────────────────────────────────────────────────────────
    def check_hash_virustotal(self, file_hash: str) -> dict:
        """Interroge VirusTotal pour analyser un hash de fichier."""
        if not VIRUSTOTAL_API_KEY:
            logger.warning("Clé VirusTotal non configurée.")
            return {}
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            resp = self.session.get(url, headers=headers)
            if resp.status_code == 404:
                logger.info(f"VirusTotal [{file_hash}] → Hash inconnu (probablement bénin)")
                return {"not_found": True}
            resp.raise_for_status()
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            logger.info(f"VirusTotal [{file_hash}] → Détections: {stats.get('malicious', 0)}/{sum(stats.values())}")
            return data
        except Exception as e:
            logger.error(f"Erreur VirusTotal pour {file_hash}: {e}")
            return {}

    # ─────────────────────────────────────────────────────────────
    # ENRICHISSEMENT UNIFIÉ
    # ─────────────────────────────────────────────────────────────
    def enrich(self, indicator_type: str, value: str) -> ThreatIndicator:
        """
        Point d'entrée principal. Enrichit un IoC via toutes les APIs
        disponibles et retourne un ThreatIndicator consolidé.

        Args:
            indicator_type: "ip", "url", "hash", "domain"
            value: La valeur de l'indicateur

        Returns:
            ThreatIndicator avec score de menace consolidé
        """
        logger.info(f"🔍 Enrichissement CTI → [{indicator_type}] {value}")
        sources, tags = [], []
        threat_score  = 0
        country       = None
        last_seen     = None
        raw_context   = {}

        # ── Analyse IP ──────────────────────────────────────────
        if indicator_type == "ip":
            abuse_data = self.check_ip_abuseipdb(value)
            otx_data   = self.check_otx("ip", value)

            if abuse_data:
                raw_context["abuseipdb"] = abuse_data
                abuse_score = abuse_data.get("abuseConfidenceScore", 0)
                country     = abuse_data.get("countryCode")
                last_seen   = abuse_data.get("lastReportedAt")
                threat_score = max(threat_score, abuse_score)
                if abuse_score > ABUSEIPDB_SCORE_THRESHOLD:
                    sources.append("AbuseIPDB")
                    tags.extend(abuse_data.get("usageType", "").split(","))

            if otx_data:
                raw_context["otx"] = {"pulse_count": otx_data.get("pulse_info", {}).get("count", 0)}
                pulse_count = otx_data.get("pulse_info", {}).get("count", 0)
                if pulse_count >= OTX_PULSE_THRESHOLD:
                    sources.append("AlienVault OTX")
                    threat_score = min(100, threat_score + pulse_count * 5)
                    for pulse in otx_data.get("pulse_info", {}).get("pulses", [])[:3]:
                        tags.extend(pulse.get("tags", []))

        # ── Analyse Hash ─────────────────────────────────────────
        elif indicator_type == "hash":
            vt_data  = self.check_hash_virustotal(value)
            otx_data = self.check_otx("hash", value)

            if vt_data and not vt_data.get("not_found"):
                raw_context["virustotal"] = vt_data
                attrs      = vt_data.get("data", {}).get("attributes", {})
                stats      = attrs.get("last_analysis_stats", {})
                malicious  = stats.get("malicious", 0)
                last_seen  = attrs.get("last_submission_date")
                if malicious >= VT_DETECTION_THRESHOLD:
                    sources.append("VirusTotal")
                    threat_score = min(100, int(malicious / max(sum(stats.values()), 1) * 100))
                    tags.extend(attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "").split("."))

            if otx_data:
                pulse_count = otx_data.get("pulse_info", {}).get("count", 0)
                raw_context["otx"] = {"pulse_count": pulse_count}
                if pulse_count >= OTX_PULSE_THRESHOLD:
                    sources.append("AlienVault OTX")
                    threat_score = min(100, threat_score + pulse_count * 5)

        # ── Analyse URL / Domain ──────────────────────────────────
        else:
            otx_data = self.check_otx(indicator_type, value)
            if otx_data:
                pulse_count = otx_data.get("pulse_info", {}).get("count", 0)
                raw_context["otx"] = {"pulse_count": pulse_count}
                if pulse_count >= OTX_PULSE_THRESHOLD:
                    sources.append("AlienVault OTX")
                    threat_score = min(100, pulse_count * 10)

        # ── Conclusion ────────────────────────────────────────────
        is_malicious = threat_score >= ABUSEIPDB_SCORE_THRESHOLD or bool(sources)
        tags = list(set(t.strip() for t in tags if t.strip()))

        indicator = ThreatIndicator(
            indicator_type=indicator_type,
            value=value,
            threat_score=threat_score,
            is_malicious=is_malicious,
            sources=sources,
            tags=tags,
            country=country,
            last_seen=str(last_seen) if last_seen else None,
            raw_context=raw_context,
        )

        status = "🔴 MALVEILLANT" if is_malicious else "🟢 Bénin"
        logger.info(f"{status} [{indicator_type}] {value} – Score: {threat_score}/100 | Sources: {sources or ['Aucune']}")
        return indicator


def generate_cti_report(indicators: list[ThreatIndicator], output_path: str = None) -> dict:
    """
    Génère un rapport CTI structuré à partir d'une liste d'indicateurs.
    Utile pour la documentation et l'envoi au SOAR.
    """
    report = {
        "report_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_indicators": len(indicators),
        "malicious_count": sum(1 for i in indicators if i.is_malicious),
        "indicators": [i.to_dict() for i in indicators],
        "stix2_bundle": {
            "type": "bundle",
            "id": f"bundle--{hashlib.md5(str(datetime.now()).encode()).hexdigest()}",
            "objects": [i.to_stix2_indicator() for i in indicators if i.is_malicious],
        },
    }
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logger.info(f"📄 Rapport CTI sauvegardé → {output_path}")
    return report


# ─── Point d'entrée (démonstration) ───────────────────────────
if __name__ == "__main__":
    enricher = CTIEnricher()

    # Exemples d'IoCs à tester (remplacez par vos propres valeurs)
    test_iocs = [
        ("ip",     "185.220.101.1"),    # IP TOR malveillante connue
        ("hash",   "44d88612fea8a8f36de82e1278abb02f"),  # Hash EICAR test
        ("domain", "evil-phishing-demo.com"),
    ]

    results = []
    for ioc_type, ioc_value in test_iocs:
        indicator = enricher.enrich(ioc_type, ioc_value)
        results.append(indicator)

    # Génération du rapport
    report = generate_cti_report(results, output_path="./reports/generated/cti_report_demo.json")
    print(f"\n✅ Rapport CTI généré : {report['malicious_count']}/{report['total_indicators']} IoCs malveillants détectés")
