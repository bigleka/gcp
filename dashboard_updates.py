import streamlit as st
import requests
import pandas as pd
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from google.oauth2.credentials import Credentials
from google.auth import default as google_default
from google.auth.transport.requests import Request

# Configuração da página
st.set_page_config(page_title="Cloud SQL Governance", layout="wide", page_icon="🛡️")

st.title("🛡️ Painel de Governança e Updates - Cloud SQL")
st.markdown("""
Visão centralizada de janelas de manutenção, agendamentos forçados e **versões de patch pendentes**.
""")

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

# ---------------------------------------------------------
# 1. Funções de Autenticação
# ---------------------------------------------------------
def load_creds_from_file(path):
    creds = Credentials.from_authorized_user_file(path, scopes=SCOPES)
    if not creds.valid and creds.refresh_token:
        creds.refresh(Request())
    return creds

def try_adc_local():
    creds, project = google_default(scopes=SCOPES)
    if not creds.valid and creds.refresh_token:
        creds.refresh(Request())
    return creds

# ---------------------------------------------------------
# 2. Funções de Listagem da API
# ---------------------------------------------------------
@st.cache_data(ttl=3600)
def list_active_projects(_creds):
    headers = {"Authorization": f"Bearer {_creds.token}"}
    projects = []
    url = "https://cloudresourcemanager.googleapis.com/v1/projects"
    
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            break
        data = resp.json()
        for p in data.get("projects", []):
            if p.get("lifecycleState") == "ACTIVE":
                projects.append(p["projectId"])
        pageToken = data.get("nextPageToken")
        url = f"https://cloudresourcemanager.googleapis.com/v1/projects?pageToken={pageToken}" if pageToken else None
        
    return sorted(projects)

def get_instance_maintenance_info(_creds, project_id):
    headers = {"Authorization": f"Bearer {_creds.token}"}
    url = f"https://sqladmin.googleapis.com/v1/projects/{project_id}/instances"
    
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code != 200:
            return []
            
        items = r.json().get("items", [])
        parsed_instances = []
        
        for i in items:
            settings = i.get("settings", {})
            m_window_cfg = settings.get("maintenanceWindow", {})
            scheduled = i.get("scheduledMaintenance", None)
            
            # --- NOVA LÓGICA: Captura das versões pendentes ---
            # A API retorna uma lista, ex: ["POSTGRES_14_9.R20230910.01"]
            available_vers_list = i.get("availableMaintenanceVersions", [])
            # Transformamos em string separada por vírgula se houver mais de uma
            pending_patch_str = ", ".join(available_vers_list) if available_vers_list else None
            
            status_update = "OK"
            next_maintenance_time = None
            
            if scheduled:
                status_update = "SCHEDULED"
                ms_str = scheduled.get("startTime", "")
                try:
                    next_maintenance_time = datetime.strptime(ms_str.split(".")[0], "%Y-%m-%dT%H:%M:%S")
                except:
                    next_maintenance_time = ms_str
            elif available_vers_list:
                status_update = "AVAILABLE"
            
            # Formatação da janela
            day_map = {1: "Seg", 2: "Ter", 3: "Qua", 4: "Qui", 5: "Sex", 6: "Sab", 7: "Dom"}
            pref_day = m_window_cfg.get("day", 0)
            pref_hour = m_window_cfg.get("hour", 0)
            window_str = f"{day_map.get(pref_day, 'N/A')} {pref_hour}h" if pref_day else "Qualquer"

            parsed_instances.append({
                "Projeto": project_id,
                "Instância": i.get("name"),
                "Versão DB": i.get("databaseVersion"),
                "Estado": i.get("state"),
                "Status Update": status_update,
                "Patch Pendente": pending_patch_str, # Nova Coluna
                "Data Agendada": next_maintenance_time,
                "Janela Pref.": window_str,
                "Labels": settings.get("userLabels", {})
            })
            
        return parsed_instances
    except Exception:
        return []

# ---------------------------------------------------------
# 3. Interface Principal
# ---------------------------------------------------------
with st.sidebar:
    st.header("🔑 Acesso")
    auth_mode = st.radio("Método", ["ADC Local", "Upload JSON"])
    creds = None
    
    if auth_mode == "Upload JSON":
        uploaded = st.file_uploader("Service Account JSON", type=["json"])
        if uploaded:
            with open("temp_auth_gov.json", "wb") as f:
                f.write(uploaded.getvalue())
            creds = load_creds_from_file("temp_auth_gov.json")
    else:
        if st.button("Carregar Credenciais Locais"):
            creds = try_adc_local()
            
    st.info("Requer permissão `cloudsql.instances.list`.")

if creds:
    if "data_snapshot" not in st.session_state:
        st.session_state.data_snapshot = None

    col_btn, col_check = st.columns([1, 4])
    with col_btn:
        refresh = st.button("🔄 Escanear Ambiente", type="primary")
    with col_check:
        only_pending = st.checkbox("Mostrar apenas com updates pendentes/agendados")

    if refresh:
        with st.status("Escaneando projetos...", expanded=True) as status:
            projects = list_active_projects(creds)
            st.write(f"Projetos ativos: {len(projects)}")
            
            all_instances = []
            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_proj = {executor.submit(get_instance_maintenance_info, creds, p): p for p in projects}
                
                completed = 0
                for future in as_completed(future_to_proj):
                    data = future.result()
                    if data:
                        all_instances.extend(data)
                    completed += 1
                    if completed % 10 == 0:
                        st.write(f"Processado {completed}/{len(projects)}...")
            
            st.session_state.data_snapshot = pd.DataFrame(all_instances)
            status.update(label="Varredura completa!", state="complete", expanded=False)

    if st.session_state.data_snapshot is not None and not st.session_state.data_snapshot.empty:
        df = st.session_state.data_snapshot.copy()

        # Métricas
        total = len(df)
        scheduled = len(df[df["Status Update"] == "SCHEDULED"])
        avail = len(df[df["Status Update"] == "AVAILABLE"])
        
        m1, m2, m3 = st.columns(3)
        m1.metric("Total Instâncias", total)
        m2.metric("Agendados (Crítico)", scheduled, delta_color="inverse")
        m3.metric("Disponíveis (Preventivo)", avail)

        if only_pending:
            df = df[df["Status Update"] != "OK"]

        # Ordenação: Agendados > Disponíveis > OK
        status_map = {"SCHEDULED": 0, "AVAILABLE": 1, "OK": 2}
        df["_sort"] = df["Status Update"].map(status_map)
        df = df.sort_values(by=["_sort", "Data Agendada"]).drop(columns=["_sort"])

        st.divider()
        st.subheader("📋 Detalhe de Atualizações")

        st.dataframe(
            df,
            column_config={
                "Status Update": st.column_config.TextColumn(
                    "Status",
                    width="medium",
                    help="SCHEDULED: Data marcada pelo Google. AVAILABLE: Pendente, mas sem data."
                ),
                "Patch Pendente": st.column_config.TextColumn(
                    "Patch Disponível",
                    width="medium",
                    help="Nome técnico da atualização pendente (ex: POSTGRES_14_9...)"
                ),
                "Data Agendada": st.column_config.DatetimeColumn(
                    "Agendado Para",
                    format="D MMM YYYY, HH:mm",
                ),
                "Labels": st.column_config.Column("Labels", width="small")
            },
            use_container_width=True,
            hide_index=True,
            height=600
        )
        
        # Download
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Baixar CSV", csv, "cloudsql_updates.csv", "text/csv")

    elif st.session_state.data_snapshot is not None:
        st.warning("Nenhuma instância encontrada.")

else:
    st.info("👈 Autentique-se para começar.")