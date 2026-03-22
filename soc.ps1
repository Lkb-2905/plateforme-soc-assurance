# ===================================================================
# SOC PLATFORM – Script de lancement centralisé (SANS Docker)
# Usage : .\soc.ps1 <commande>
# ===================================================================

# Définir le bon Python (pyenv)
$env:PATH = "C:\Users\pc\.pyenv\pyenv-win\versions\3.12.10\;" +
            "C:\Users\pc\.pyenv\pyenv-win\versions\3.12.10\Scripts\;" +
            $env:PATH

$command = $args[0]

switch ($command) {

    # ─── PIPELINE SOC COMPLET (SIEM + SOAR) ───────────────────
    "run" {
        $scenario = if ($args[1]) { $args[1] } else { "all" }
        $cti      = if ($args[2] -eq "--cti") { "--cti" } else { "" }
        Write-Host "`n🛡️  Démarrage Pipeline SOC complet – Scénario : $scenario" -ForegroundColor Cyan
        if ($cti) { Write-Host "   ✦ Enrichissement CTI RÉEL activé" -ForegroundColor Yellow }
        python scripts/soc_engine.py --scenario $scenario $cti
    }

    # ─── SIMULATEURS SEULS ────────────────────────────────────
    "sim-ransomware" {
        Write-Host "`n🔴 Simulation RANSOMWARE (logs seuls, sans pipeline SOC)" -ForegroundColor Red
        python scripts/simulators/ransomware_sim.py
    }
    "sim-phishing" {
        Write-Host "`n🎣 Simulation PHISHING (logs seuls, sans pipeline SOC)" -ForegroundColor Yellow
        python scripts/simulators/phishing_sim.py
    }
    "sim-account" {
        Write-Host "`n👤 Simulation COMPROMISSION DE COMPTE (logs seuls)" -ForegroundColor Magenta
        python scripts/simulators/account_compromise_sim.py
    }

    # ─── CTI MODULE ───────────────────────────────────────────
    "cti" {
        Write-Host "`n🔍 Test module CTI (démonstration, APIs simulées si pas de clés)" -ForegroundColor Blue
        python scripts/cti/threat_intelligence.py
    }

    # ─── RAPPORTS ─────────────────────────────────────────────
    "report" {
        $type    = if ($args[1]) { $args[1] } else { "ransomware" }
        $analyst = if ($args[2]) { $args[2] } else { "Analyste SOC" }
        Write-Host "`n📄 Génération rapport d'incident [$type]..." -ForegroundColor Cyan
        python scripts/generate_report.py --type $type --analyst "$analyst"
    }

    # ─── AIDE ─────────────────────────────────────────────────
    default {
        Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║           🛡️  PLATEFORME SOC – Commandes disponibles              ║
╠═══════════════════════════════════════════════════════════════════╣
║  PIPELINE COMPLET (SIEM + SOAR)                                   ║
║  .\soc.ps1 run all               → Simuler les 3 scénarios        ║
║  .\soc.ps1 run ransomware        → Pipeline Ransomware complet    ║
║  .\soc.ps1 run phishing          → Pipeline Phishing complet      ║
║  .\soc.ps1 run account_compromise → Pipeline Compromission        ║
║  .\soc.ps1 run all --cti         → Avec CTI réel (nécessite .env) ║
║                                                                   ║
║  SIMULATEURS SEULS (logs)                                         ║
║  .\soc.ps1 sim-ransomware        → Logs Ransomware seuls          ║
║  .\soc.ps1 sim-phishing          → Logs Phishing seuls            ║
║  .\soc.ps1 sim-account           → Logs Compromission seuls       ║
║                                                                   ║
║  MODULES                                                          ║
║  .\soc.ps1 cti                   → Test module Threat Intel.      ║
║  .\soc.ps1 report ransomware     → Générer rapport Markdown       ║
║  .\soc.ps1 report phishing       → Générer rapport Phishing       ║
╚═══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
    }
}
