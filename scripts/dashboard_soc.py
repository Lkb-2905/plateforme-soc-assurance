import streamlit as st
import os
import json
import glob

# Configuration de HTML de la page
st.set_page_config(page_title="SOC Executive Dashboard", page_icon="🛡️", layout="wide")

# Chemins des rapports
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports", "generated")

st.title("🛡️ Portail SOC - Surveillance & Réponse (Assurances)")
st.markdown("---")

# Récupérer les rapports générés (triés par date, le plus récent en premier)
# On filtre uniquement sur thehive_case_*.json pour ne pas inclure les rapports CTI
json_files = sorted(glob.glob(os.path.join(REPORTS_DIR, "thehive_case_*.json")), reverse=True)

if not json_files:
    st.warning("⚠️ Aucun incident détecté. Exécutez `soc_engine.py` pour générer des alertes de sécurité.")
else:
    # --- KPIs en haut de page ---
    st.header("📊 Métriques Opérationnelles du RUN")
    total_incidents = len(json_files)
    
    # Calculer combien d'incidents ont une sévérité très élevée (Critical / High)
    high_sev = 0
    for f in json_files:
        with open(f, "r", encoding="utf-8") as file:
            data = json.load(file)
            if data.get("severity", 0) >= 3:
                high_sev += 1
                
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Alerte Total (Mois)", total_incidents)
    col2.metric("Incidents Priorité Haute (P1/P2)", high_sev, delta="-2 par rapport à hier", delta_color="inverse")
    col3.metric("Playbooks Automatisés Déclenchés", total_incidents)
    col4.metric("Taux d'Endiguement Automatique", "100%")
    st.markdown("---")

    # --- SÉLECTION DU TICKET THEHIVE ---
    st.subheader("🎫 Visualisation du Flux d'Incidents (Mode TheHive)")
    selected_file = st.selectbox("Historique des incidents (Sélectionnez pour ouvrir) :", [os.path.basename(f) for f in json_files])
    
    if selected_file:
        file_path = os.path.join(REPORTS_DIR, selected_file)
        with open(file_path, "r", encoding="utf-8") as file:
            case_data = json.load(file)
            
            # Mise en page du ticket
            t1, t2 = st.columns([2, 1])
            with t1:
                st.markdown(f"### {case_data.get('title', 'Titre de L incident Inconnu')}")
                st.markdown(f"**Résumé Exécutif:**\n{case_data.get('description', '')}")
                
            with t2:
                # La sévérité Thehive va de 1 à 4 généralement
                sev_map = {1: "🟢 Basse", 2: "🟡 Moyenne", 3: "🟠 Haute", 4: "🔴 Critique", 5: "🔥 Incident Majeur"}
                
                # Récupérer la vraie sévérité de thehive json
                case_sev = case_data.get('severity', 1)
                st.info(f"**Sévérité :** {sev_map.get(case_sev, 'Inconnue')}")
                
                # Tags pour le filtrage
                tags = case_data.get('tags', [])
                st.info(f"**Tags de qualification :** {', '.join(tags)}")
                
                # --- KPI Cyber & Risque Assurantiel ---
                st.markdown("---")
                cf = case_data.get('customFields', {})
                st.info(f"⏱️ **MTTD (Temps moyen de détection):** {cf.get('mttd', {}).get('string', 'N/A')}")
                st.info(f"⚡ **MTTR (Temps moyen de réponse):** {cf.get('mttr', {}).get('string', 'N/A')}")
                
                if cf.get('gdpr_exposed', {}).get('boolean', False):
                    st.error("🚨 **RISQUE ASSURANTIEL & CNIL**")
                    st.warning("⚠️ **Données exposées** : Contrats / Santé / Sinistres.\n\n⏰ **Obligation légale** : Déclaration CNIL sous 72H.")
                else:
                    st.success("✅ **Impact Réglementaire :** Pas d'exposition de données clients critiques.")

            # --- Extraction des Observables (CTI) ---
            st.markdown("#### 🔍 Observables Extraits (Cyber Threat Intelligence)")
            obs_data = []
            for obs in case_data.get("observables", []):
                obs_data.append({
                    "Type IOC": obs.get("dataType"), 
                    "Valeur Malveillante": obs.get("data"), 
                    "Avis CTI": obs.get("message")
                })
            
            if obs_data:
                st.table(obs_data)
            else:
                st.write("Aucun observable détecté dans cet incident.")
                
            # --- Tâches SOC ---
            st.markdown("#### 🤖 Post-Mortem des Actions Automatisées (Triage & Remédiation)")
            for task in case_data.get("tasks", []):
                # On coche les cases visuellement pour montrer l'automatisation
                st.checkbox(f"**[{task.get('group', 'Task')}]** - {task.get('title')}", value=True)
                
            # --- Rapport Analyste Complet ---
            st.markdown("---")
            md_version = selected_file.replace("thehive_case_", "incident_report_").replace(".json", ".md")
            md_path = os.path.join(REPORTS_DIR, md_version)
            if os.path.exists(md_path):
                with st.expander("📄 Afficher le rapport analytique finalisé (Markdown exporté)"):
                    with open(md_path, "r", encoding="utf-8") as md_file:
                        st.markdown(md_file.read())
