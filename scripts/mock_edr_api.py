"""
================================================================
MOCK EDR & IT API – Simulateur d'équipements de sécurité
Plateforme SOC Assurantielle – scripts/mock_edr_api.py
================================================================
Expose une API REST simulée pour que le moteur SOAR puisse
effectuer de vraies requêtes HTTP d'endiguement.

Usage :
  pip install fastapi uvicorn
  python scripts/mock_edr_api.py
================================================================
"""

from fastapi import FastAPI
import uvicorn
import time

app = FastAPI(
    title="Mock Security API", 
    description="API de simulation d'équipements de sécurité (EDR, Firewall, AD) pour tests SOAR.",
    version="1.0"
)

@app.post("/api/v1/hosts/{hostname}/isolate")
def isolate_host(hostname: str):
    """Simule l'API d'un EDR (ex: CrowdStrike) pour isoler une machine du réseau."""
    # Simulation d'un délai d'action
    time.sleep(0.5)
    print(f"[EDR] 🛡️ Demande d'isolation reçue pour l'hôte : {hostname}")
    return {
        "status": "success", 
        "message": f"Host {hostname} isolated from network successfully.", 
        "action_id": "ISO-8849"
    }

@app.post("/api/v1/users/{username}/reset_password")
def reset_password(username: str):
    """Simule l'API d'un annuaire (Active Directory / Entra ID) pour forcer le reset MDP."""
    time.sleep(0.5)
    print(f"[AD] 🔑 Demande de réinitialisation de mot de passe reçue pour : {username}")
    return {
        "status": "success", 
        "message": f"Password reset forced and MFA enforced for user {username}.", 
        "action_id": "PWD-1120"
    }

@app.post("/api/v1/emails/delete")
def delete_email(recipient: str = "all_users", subject: str = "Malicious Email"):
    """Simule l'API de messagerie (Exchange/O365) pour supprimer un courriel."""
    time.sleep(0.3)
    print(f"[MAIL] 🗑️ Suppression de l'email '{subject}' dans les boîtes de {recipient}")
    return {
        "status": "success", 
        "message": f"Email removed from {recipient} mailbox.",
        "action_id": "MAIL-992"
    }

if __name__ == "__main__":
    print("\n🚀 Démarrage de l'API Mock EDR/IT sur http://127.0.0.1:8080")
    print("   Laissez ce terminal ouvert et lancez soc_engine.py dans un autre terminal.\n")
    uvicorn.run(app, host="127.0.0.1", port=8080, log_level="warning")
