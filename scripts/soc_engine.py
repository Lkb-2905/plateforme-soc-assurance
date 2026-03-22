"""
================================================================
SOC CORE ENGINE – Moteur SIEM + SOAR Python natif
Plateforme SOC Assurantielle
scripts/soc_engine.py
================================================================
Ce module remplace Wazuh + Shuffle par un moteur Python pur :

  ┌──────────────────────────────────────────────────────────┐
  │  [Simulateurs]  →  [SIEM Engine]  →  [SOAR Engine]       │
  │  (générateurs)     (détection)       (playbooks Python)  │
  │                        │                    │            │
  │                   [CTI Module]         [Rapports]        │
  └──────────────────────────────────────────────────────────┘

Usage :
  python scripts/soc_engine.py --scenario ransomware
  python scripts/soc_engine.py --scenario phishing
  python scripts/soc_engine.py --scenario account_compromise
  python scripts/soc_engine.py --scenario all
================================================================
"""

import sys
import os
import json
import argparse
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Callable
from datetime import datetime, timezone

# Ajout du chemin racine pour les imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import colorlog
import logging

# ─── Logging coloré ───────────────────────────────────────────
handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    "%(log_color)s%(asctime)s [%(name)s]%(reset)s %(message)s",
    datefmt="%H:%M:%S",
    log_colors={
        "DEBUG":    "cyan",
        "INFO":     "green",
        "WARNING":  "yellow",
        "ERROR":    "red",
        "CRITICAL": "bold_red",
    }
))
logging.root.addHandler(handler)
logging.root.setLevel(logging.DEBUG)


# ══════════════════════════════════════════════════════════════
# DATACLASSES
# ══════════════════════════════════════════════════════════════

@dataclass
class Alert:
    """Alerte levée par le SIEM après correspondance d'une règle."""
    rule_id:     str
    rule_name:   str
    severity:    int               # 1 (info) → 5 (critique)
    event:       dict
    timestamp:   str = ""
    enrichments: dict = field(default_factory=dict)

    def __post_init__(self):
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "rule_id":     self.rule_id,
            "rule_name":   self.rule_name,
            "severity":    self.severity,
            "event":       self.event,
            "timestamp":   self.timestamp,
            "enrichments": self.enrichments,
        }


@dataclass
class PlaybookResult:
    """Résultat de l'exécution d'un playbook SOAR."""
    playbook_name: str
    alert:         Alert
    actions_taken: list[dict] = field(default_factory=list)
    report_path:   str = ""
    success:       bool = True


# ══════════════════════════════════════════════════════════════
# SIEM ENGINE – Moteur de détection
# ══════════════════════════════════════════════════════════════

class SIEMEngine:
    """
    Mini-SIEM : reçoit des événements JSON et applique des règles
    de détection pour générer des alertes. Imite le comportement
    de Wazuh sans nécessiter Docker.
    """

    def __init__(self):
        self.logger   = logging.getLogger("SIEM")
        self.rules    = self._load_rules()
        self._counters = {}          # Pour les règles de fréquence
        self._counter_lock = threading.Lock()

    def _load_rules(self) -> list[dict]:
        """
        Définit les règles de détection équivalentes aux règles XML Wazuh.
        Chaque règle a : id, name, match_fn (fonction Python), severity, mitre.
        """
        return [
            # ── Ransomware ────────────────────────────────────
            {
                "id": "100001",
                "name": "Ransomware – Renommage de fichier sensible",
                "severity": 3,
                "mitre": "T1486",
                "match": lambda e: e.get("event_type") == "RANSOMWARE_FILE_RENAME",
            },
            {
                "id": "100002",
                "name": "CRITIQUE – Ransomware actif (chiffrement massif)",
                "severity": 5,
                "mitre": "T1486",
                "match": lambda e: e.get("event_type") == "RANSOMWARE_FILE_RENAME",
                "frequency": {"count": 10, "window_s": 30},  # 10 events / 30s
            },
            {
                "id": "100003",
                "name": "Ransomware – Extension de chiffrement connue",
                "severity": 4,
                "mitre": "T1486",
                "match": lambda e: (
                    e.get("encrypted_file_signal") == "ENCRYPTED_EXTENSION_DETECTED"
                    or any(ext in str(e.get("file.extension", ""))
                           for ext in [".locked", ".encrypted", ".CONTI", ".ryuk", ".crypt"])
                ),
            },
            # ── Phishing ──────────────────────────────────────
            {
                "id": "100010",
                "name": "Phishing – URL malveillante dans un email",
                "severity": 3,
                "mitre": "T1566.001",
                "match": lambda e: e.get("event_type") == "PHISHING_URL_DETECTED",
            },
            {
                "id": "100011",
                "name": "Phishing – Pièce jointe Office avec macros",
                "severity": 3,
                "mitre": "T1566.001",
                "match": lambda e: e.get("attachment_name") == "SUSPICIOUS_ATTACHMENT",
            },
            {
                "id": "100012",
                "name": "ALERTE – Utilisateur a cliqué sur URL de phishing",
                "severity": 4,
                "mitre": "T1204.001",
                "match": lambda e: e.get("event_type") == "USER_CLICKED_PHISHING_URL",
            },
            # ── Compromission de compte ────────────────────────
            {
                "id": "100020",
                "name": "Connexion depuis pays à risque élevé",
                "severity": 3,
                "mitre": "T1078",
                "match": lambda e: e.get("event_type") == "LOGIN_FROM_HIGH_RISK_COUNTRY",
            },
            {
                "id": "100021",
                "name": "CRITIQUE – Impossible Travel détecté",
                "severity": 4,
                "mitre": "T1078.002",
                "match": lambda e: e.get("event_type") == "IMPOSSIBLE_TRAVEL_DETECTED",
            },
            {
                "id": "100022",
                "name": "INCIDENT MAJEUR – Compromission compte VIP",
                "severity": 5,
                "mitre": "T1078.002",
                "match": lambda e: (
                    e.get("event_type") == "IMPOSSIBLE_TRAVEL_DETECTED"
                    and e.get("user.role", "") in ["admin", "director", "dsi", "rssi", "cfo", "ceo"]
                ),
            },
        ]

    def process_event(self, event: dict) -> list[Alert]:
        """
        Analyse un événement et retourne la liste des alertes correspondantes.
        C'est le cœur du SIEM – équivalent à l'analyse Wazuh.
        """
        alerts = []
        for rule in self.rules:
            try:
                if not rule["match"](event):
                    continue

                # Vérification de la règle de fréquence (ex: 10 events / 30s)
                if "frequency" in rule:
                    if not self._check_frequency(rule["id"], rule["frequency"]):
                        continue   # Seuil pas encore atteint

                alert = Alert(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    event=event,
                )
                level_label = {1: "INFO", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}
                self.logger.warning(
                    f"🚨 Règle {rule['id']} – [{level_label.get(rule['severity'], '?')}] "
                    f"{rule['name']}  |  MITRE: {rule.get('mitre', '-')}"
                )
                alerts.append(alert)
            except Exception:
                pass
        return alerts

    def _check_frequency(self, rule_id: str, freq: dict) -> bool:
        """
        Vérifie si le seuil de fréquence est atteint pour une règle donnée.
        Retourne True uniquement quand le seuil est franchi.
        """
        now = time.time()
        with self._counter_lock:
            if rule_id not in self._counters:
                self._counters[rule_id] = []
            # Purge les events hors fenêtre
            self._counters[rule_id] = [t for t in self._counters[rule_id]
                                        if now - t < freq["window_s"]]
            self._counters[rule_id].append(now)
            count = len(self._counters[rule_id])
            if count == freq["count"]:
                self.logger.critical(
                    f"   ⚡ Seuil de fréquence atteint pour règle {rule_id} "
                    f"({count}/{freq['count']} events en {freq['window_s']}s)"
                )
                return True
        return False


# ══════════════════════════════════════════════════════════════
# SOAR ENGINE – Orchestrateur de playbooks
# ══════════════════════════════════════════════════════════════

class SOAREngine:
    """
    Mini-SOAR : reçoit les alertes du SIEM et exécute les playbooks
    Python correspondants. Imite Shuffle sans Docker.
    """

    def __init__(self, use_cti: bool = False):
        self.logger   = logging.getLogger("SOAR")
        self.use_cti  = use_cti
        self.playbooks: dict[str, Callable] = {}
        self._register_playbooks()

    def _register_playbooks(self):
        """Enregistre les playbooks par ID de règle déclencheur."""
        # Règles Ransomware (100001, 100002, 100003) → Playbook Ransomware
        for rule_id in ["100001", "100002", "100003"]:
            self.playbooks[rule_id] = self._playbook_ransomware

        # Règles Phishing (100010, 100011, 100012) → Playbook Phishing
        for rule_id in ["100010", "100011", "100012"]:
            self.playbooks[rule_id] = self._playbook_phishing

        # Règles Compromission (100020, 100021, 100022) → Playbook Account
        for rule_id in ["100020", "100021", "100022"]:
            self.playbooks[rule_id] = self._playbook_account_compromise

    def handle_alert(self, alert: Alert) -> PlaybookResult:
        """Point d'entrée : déclenche le bon playbook selon la règle."""
        playbook_fn = self.playbooks.get(alert.rule_id)
        if not playbook_fn:
            self.logger.debug(f"Aucun playbook pour règle {alert.rule_id}")
            return PlaybookResult(playbook_name="none", alert=alert, success=False)

        self.logger.info(
            f"\n{'─'*58}\n"
            f"  ⚡ SOAR – Déclenchement Playbook\n"
            f"  Règle  : {alert.rule_id} – {alert.rule_name}\n"
            f"  Sévérité : {'⭐' * alert.severity}\n"
            f"{'─'*58}"
        )
        return playbook_fn(alert)

    # ──────────────────────────────────────────────────────────
    # PLAYBOOK 1 : RANSOMWARE
    # ──────────────────────────────────────────────────────────
    def _playbook_ransomware(self, alert: Alert) -> PlaybookResult:
        result = PlaybookResult(playbook_name="playbook_ransomware_v1", alert=alert)
        event  = alert.event

        # Étape 1 – Extraction des artefacts
        result.actions_taken.append(self._step(
            "1. Extraction des artefacts",
            f"Hôte: {event.get('host', '?')} | "
            f"IP source: {event.get('source_ip', '?')} | "
            f"Fichier: {event.get('file.name_after', event.get('file.name', '?'))}"
        ))

        # Étape 2 – Enrichissement CTI (si configuré)
        cti_score = self._cti_check(event.get("source_ip"), "ip", result)

        # Étape 3 – Isolation de l'hôte
        host = event.get("host", "UNKNOWN")
        result.actions_taken.append(self._step(
            "3. Isolation réseau de l'hôte",
            f"✅ Commande d'isolation envoyée pour {host} "
            f"(simulation – en prod: API EDR/Firewall)"
        ))

        # Étape 4 – Suspension du compte utilisateur
        result.actions_taken.append(self._step(
            "4. Suspension du compte",
            "✅ Compte utilisateur suspendu en attente d'investigation"
        ))

        # Étape 5 – Notification cellule de crise
        result.actions_taken.append(self._step(
            "5. Notification P1 – Cellule de crise",
            "✅ Email envoyé à : rssi@assurance-demo.fr | soc-n2@assurance-demo.fr\n"
            f"     Objet : [P1-CRISE] Ransomware ACTIF sur {host}"
        ))

        # Étape 6 – Génération du rapport
        result.report_path = self._generate_report("ransomware", result)

        return result

    # ──────────────────────────────────────────────────────────
    # PLAYBOOK 2 : PHISHING
    # ──────────────────────────────────────────────────────────
    def _playbook_phishing(self, alert: Alert) -> PlaybookResult:
        result = PlaybookResult(playbook_name="playbook_phishing_v1", alert=alert)
        event  = alert.event

        # Étape 1 – Extraction
        url  = event.get("email.url_detected", event.get("url_clicked", "?"))
        user = event.get("user.name", event.get("user.email", "?"))
        result.actions_taken.append(self._step(
            "1. Extraction des artefacts",
            f"Utilisateur: {user} | URL: {url}"
        ))

        # Étape 2 – CTI sur l'URL
        self._cti_check(url, "url", result)

        # Étape 3 – Suppression de l'email
        result.actions_taken.append(self._step(
            "3. Suppression de l'email malveillant",
            f"✅ Email supprimé des boîtes de réception (simulation API messagerie)"
        ))

        # Étape 4 – Réinitialisation MDP (si clic détecté)
        if alert.rule_id == "100012":
            result.actions_taken.append(self._step(
                "4. Réinitialisation du mot de passe",
                f"✅ MDP de {user} réinitialisé & MFA forcé à la prochaine connexion"
            ))

        # Étape 5 – Notification
        result.actions_taken.append(self._step(
            "5. Notification SOC N1",
            f"✅ Alerte envoyée – Phishing confirmé ciblant {user}"
        ))

        result.report_path = self._generate_report("phishing", result)
        return result

    # ──────────────────────────────────────────────────────────
    # PLAYBOOK 3 : COMPROMISSION DE COMPTE
    # ──────────────────────────────────────────────────────────
    def _playbook_account_compromise(self, alert: Alert) -> PlaybookResult:
        result = PlaybookResult(playbook_name="playbook_account_compromise_v1", alert=alert)
        event  = alert.event

        user     = event.get("user.name", "?")
        username = event.get("user.username", "?")
        role     = event.get("user.role", "user")
        city2    = event.get("src_city_2", event.get("source_geo.country_name", "?"))

        result.actions_taken.append(self._step(
            "1. Extraction des artefacts",
            f"Compte: {username} ({role}) | "
            f"Localisation suspecte: {city2} | "
            f"IP: {event.get('second_login_ip', event.get('source_ip', '?'))}"
        ))

        # CTI sur l'IP suspecte
        self._cti_check(event.get("second_login_ip", event.get("source_ip")), "ip", result)

        # Blocage de la session
        result.actions_taken.append(self._step(
            "3. Blocage de la session suspecte",
            f"✅ Session depuis {city2} révoquée pour {username}"
        ))

        # Forcer MFA
        result.actions_taken.append(self._step(
            "4. Forçage du MFA",
            f"✅ MFA obligatoire activé pour {username} – Réinitialisation MDP"
        ))

        # Alerte VIP si compte sensible
        if role in ["admin", "director", "dsi", "rssi", "cfo", "ceo"]:
            result.actions_taken.append(self._step(
                "5. 🔴 INCIDENT P1 – Compte VIP compromis",
                f"✅ Alerte CRITIQUE envoyée – Incident P1 ouvert pour {user} ({role.upper()})\n"
                "     Destinataires : rssi@assurance-demo.fr | dg@assurance-demo.fr | soc-n2@"
            ))
        else:
            result.actions_taken.append(self._step(
                "5. Notification SOC N2",
                f"✅ Alerte P2 – Compromission potentielle : {user}"
            ))

        result.report_path = self._generate_report("ransomware", result)   # Utilise le template ransomware comme base
        return result

    # ──────────────────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────────────────
    def _step(self, name: str, detail: str) -> dict:
        """Exécute et logge une étape du playbook."""
        self.logger.info(f"  ├── {name}")
        self.logger.info(f"  │   {detail}")
        time.sleep(0.3)
        return {"name": name, "detail": detail, "status": "✅ Succès",
                "timestamp": datetime.now(timezone.utc).isoformat()}

    def _cti_check(self, ioc_value: str, ioc_type: str, result: PlaybookResult) -> int:
        """Enrichissement CTI (réel si clés dispo, simulé sinon)."""
        if not ioc_value or ioc_value == "?":
            return 0

        step_name = f"2. Enrichissement CTI – {ioc_type.upper()} : {ioc_value}"
        if self.use_cti:
            try:
                from scripts.cti.threat_intelligence import CTIEnricher
                enricher   = CTIEnricher()
                indicator  = enricher.enrich(ioc_type, ioc_value)
                detail     = (
                    f"Score: {indicator.threat_score}/100 | "
                    f"Malveillant: {indicator.is_malicious} | "
                    f"Sources: {indicator.sources or ['Aucune']}"
                )
                result.alert.enrichments[ioc_value] = indicator.to_dict()
            except Exception as e:
                detail = f"Erreur CTI: {e} – Enrichissement ignoré"
        else:
            # Mode démo : simulation d'un score CTI
            import random
            score  = random.randint(60, 95)
            detail = (
                f"[SIMULATION CTI] Score: {score}/100 | "
                f"Malveillant: True | Sources: ['AbuseIPDB (simulé)']"
            )
            result.alert.enrichments[ioc_value] = {"threat_score": score, "simulated": True}

        result.actions_taken.append(self._step(step_name, detail))
        return 0

    def _generate_report(self, incident_type: str, result: PlaybookResult) -> str:
        """Appelle le générateur de rapports Python."""
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from scripts.generate_report import generate_incident_report
            path = generate_incident_report(
                incident_type=incident_type,
                analyst_name="SOC Engine (Automatisé)"
            )
            self.logger.info(f"  └── 📄 Rapport d'incident généré → {path}")
            return path
        except Exception as e:
            self.logger.error(f"  └── ❌ Erreur génération rapport: {e}")
            return ""


# ══════════════════════════════════════════════════════════════
# PIPELINE PRINCIPAL
# ══════════════════════════════════════════════════════════════

class SOCPlatform:
    """
    Orchestrateur principal : connecte le simulateur → SIEM → SOAR.

      Simulateur  →  event_queue  →  SIEMEngine  →  alert_queue  →  SOAREngine
    """

    def __init__(self, use_cti: bool = False):
        self.siem        = SIEMEngine()
        self.soar        = SOAREngine(use_cti=use_cti)
        self.event_queue = queue.Queue()
        self.logger      = logging.getLogger("SOC-PLATFORM")

    def ingest(self, event: dict):
        """Injecte un événement dans le pipeline."""
        self.event_queue.put(event)

    def run(self, scenario: str):
        """Lance le scénario complet de bout en bout."""
        self.logger.info(f"\n{'═'*60}")
        self.logger.info(f"  🛡️  PLATEFORME SOC – DÉMARRAGE SCÉNARIO : {scenario.upper()}")
        self.logger.info(f"{'═'*60}")

        # Monkeypatch send_syslog vers notre queue au lieu de UDP
        self._patch_simulators()

        # Lance le simulateur dans un thread
        sim_thread = threading.Thread(
            target=self._run_simulator, args=(scenario,), daemon=True
        )
        sim_thread.start()

        # Traitement des événements
        alerts_processed = 0
        playbooks_run    = 0
        last_event_time  = time.time()

        while True:
            try:
                event = self.event_queue.get(timeout=3.0)
                last_event_time = time.time()

                # SIEM : Analyse de l'événement
                alerts = self.siem.process_event(event)

                # SOAR : Exécution des playbooks déclenchés
                for alert in alerts:
                    alerts_processed += 1
                    result = self.soar.handle_alert(alert)
                    if result.success and result.playbook_name != "none":
                        playbooks_run += 1

            except queue.Empty:
                # Plus d'événements depuis 3s → fin du scénario
                if not sim_thread.is_alive() and time.time() - last_event_time > 2:
                    break

        self._print_summary(scenario, alerts_processed, playbooks_run)

    def _run_simulator(self, scenario: str):
        """Exécute le simulateur dans un thread séparé."""
        import importlib
        sim_map = {
            "ransomware":        "scripts.simulators.ransomware_sim",
            "phishing":          "scripts.simulators.phishing_sim",
            "account_compromise":"scripts.simulators.account_compromise_sim",
        }

        scenarios_to_run = (
            list(sim_map.keys()) if scenario == "all" else [scenario]
        )

        for sc in scenarios_to_run:
            module_path = sim_map.get(sc)
            if not module_path:
                continue
            try:
                mod = importlib.import_module(module_path)
                self.logger.info(f"🚀 Lancement simulateur : {sc}")
                mod.run_simulation()
                if scenario == "all":
                    time.sleep(2)
            except Exception as e:
                self.logger.error(f"Erreur simulateur {sc}: {e}")

    def _patch_simulators(self):
        """
        Remplace la fonction send_syslog (UDP vers Wazuh) par une
        injection directe dans notre event_queue Python.
        → Plus besoin de Docker ou de port UDP 514 !
        """
        platform_ref = self

        def patched_send_syslog(message: str, host=None, port=None):
            try:
                # Le message syslog contient du JSON — on l'extrait
                # Format: "<14>1 2024-... HOSTNAME app - - - {JSON}"
                json_start = message.find("{")
                if json_start != -1:
                    event = json.loads(message[json_start:])
                    platform_ref.ingest(event)
            except Exception:
                pass
            return True

        # Injection du mock dans tous les modules simulateurs
        import importlib
        for mod_path in [
            "scripts.simulators.ransomware_sim",
            "scripts.simulators.phishing_sim",
            "scripts.simulators.account_compromise_sim",
        ]:
            try:
                mod = importlib.import_module(mod_path)
                mod.send_syslog = patched_send_syslog
            except ImportError:
                pass

    def _print_summary(self, scenario: str, alerts: int, playbooks: int):
        """Affiche le résumé de fin d'exécution."""
        self.logger.info(
            f"\n{'═'*60}\n"
            f"  ✅ SCÉNARIO '{scenario.upper()}' TERMINÉ\n"
            f"  📊 Alertes SIEM générées  : {alerts}\n"
            f"  ⚡ Playbooks SOAR exécutés : {playbooks}\n"
            f"  📄 Rapports → reports/generated/\n"
            f"{'═'*60}"
        )


# ══════════════════════════════════════════════════════════════
# POINT D'ENTRÉE
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC Platform – Moteur SIEM + SOAR Python")
    parser.add_argument(
        "--scenario",
        required=True,
        choices=["ransomware", "phishing", "account_compromise", "all"],
        help="Scénario d'incident à simuler"
    )
    parser.add_argument(
        "--cti",
        action="store_true",
        help="Activer l'enrichissement CTI réel (nécessite les clés API dans .env)"
    )
    args = parser.parse_args()

    platform = SOCPlatform(use_cti=args.cti)
    platform.run(scenario=args.scenario)
