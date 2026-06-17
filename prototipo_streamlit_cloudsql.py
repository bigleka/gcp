"""
Protótipo completo: Streamlit app para listar instâncias Cloud SQL (Postgres) e executar SQL em múltiplas instâncias.

Funcionalidades incluídas:
- Suporta upload de JSON (Service Account ou ADC gerado por `gcloud auth application-default login`).
- Suporta usar ADC local sem upload (checkbox).
- Lista instâncias Cloud SQL (sqladmin API) e tenta listar AlloyDB (discovery).
- Filtra por label (ex: `environment`) e permite seleção por checkboxes.
- Informa usuário/senha do banco e executa SQL em paralelo nas instâncias selecionadas.
- Exibe resultados por instância (dataframe ou erro).

Observações importantes (segurança e produção):
- Este protótipo usa conexões diretas por IP público quando disponível.
- Não armazene senhas em texto claro em produção; use Secret Manager.

Como rodar:
1. Crie um virtualenv e ative.
2. pip install streamlit google-api-python-client google-auth google-auth-httplib2 psycopg2-binary
3. streamlit run prototipo_streamlit_cloudsql.py

"""

"""
Cloud SQL / AlloyDB Multi-Project — Projetos + Histórico + Status
-----------------------------------------------------------------
Melhorias:
1️⃣ Ícones de status (🟢 online / 🔴 offline)
2️⃣ Agrupamento por projeto (colapsáveis)
4️⃣ Histórico local de queries executadas (sidebar)
"""

import streamlit as st
import requests
import psycopg2
import psycopg2.extras
from datetime import datetime
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google.auth import default as google_default
from concurrent.futures import ThreadPoolExecutor, as_completed

st.set_page_config(page_title="Cloud SQL Multi-Project", layout="wide")
st.title("🧭 Cloud SQL / AlloyDB Multi-Project — Status via Databases API")

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

# -----------------------------
# Helpers
# -----------------------------
def load_creds_from_file(path):
    creds = Credentials.from_authorized_user_file(path, scopes=SCOPES)
    if not creds.valid and creds.refresh_token:
        creds.refresh(Request())
    return creds

def try_adc_local():
    creds, project = google_default(scopes=SCOPES)
    if not creds.valid and creds.refresh_token:
        creds.refresh(Request())
    return creds, project

# -----------------------------
# API listagem
# -----------------------------
@st.cache_data(show_spinner=False)
def list_all_projects(_creds):
    headers = {"Authorization": f"Bearer {_creds.token}"}
    url = "https://cloudresourcemanager.googleapis.com/v1/projects"
    projects = []
    while url:
        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            break
        data = r.json()
        for p in data.get("projects", []):
            if p.get("lifecycleState") == "ACTIVE":
                projects.append(p["projectId"])
        url = f"https://cloudresourcemanager.googleapis.com/v1/projects?pageToken={data.get('nextPageToken')}" if data.get("nextPageToken") else None
    return sorted(projects)

@st.cache_data(show_spinner=False)
def list_cloudsql_instances_for_project(_creds, project_id):
    headers = {"Authorization": f"Bearer {_creds.token}"}
    url = f"https://sqladmin.googleapis.com/v1/projects/{project_id}/instances"
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return []
    items = r.json().get("items", [])
    return [
        {
            "project": project_id,
            "name": it.get("name"),
            "type": "cloudsql",
            "state": it.get("state"),
            "ipAddresses": it.get("ipAddresses", []),
            "labels": it.get("settings", {}).get("userLabels", {}),
            "databaseVersion": it.get("databaseVersion"),
            "real_status": "UNKNOWN",
        }
        for it in items
    ]

@st.cache_data(show_spinner=False)
def list_alloydb_clusters_for_project(_creds, project_id):
    headers = {"Authorization": f"Bearer {_creds.token}"}
    url = f"https://alloydb.googleapis.com/v1/projects/{project_id}/locations/-/clusters"
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return []
    clusters = r.json().get("clusters", [])
    return [
        {
            "project": project_id,
            "name": c.get("name"),
            "type": "alloydb",
            "state": c.get("state"),
            "ipAddresses": [],
            "labels": c.get("labels", {}),
            "databaseVersion": c.get("databaseVersion"),
            "real_status": "UNKNOWN",
        }
        for c in clusters
    ]

@st.cache_data(show_spinner=False)
def list_all_instances_for_all_projects(_creds):
    all_instances = []
    for p in list_all_projects(_creds):
        try:
            all_instances += list_cloudsql_instances_for_project(_creds, p)
        except Exception as e:
            st.warning(f"Erro Cloud SQL em {p}: {e}")
        try:
            all_instances += list_alloydb_clusters_for_project(_creds, p)
        except Exception as e:
            st.warning(f"Erro AlloyDB em {p}: {e}")
    return all_instances

# -----------------------------
# Listar databases e status real
# -----------------------------
def list_databases_via_api(inst, creds):
    """Retorna databases e define status real"""
    if inst["type"] != "cloudsql":
        return [], "UNKNOWN"
    headers = {"Authorization": f"Bearer {creds.token}"}
    url = f"https://sqladmin.googleapis.com/v1/projects/{inst['project']}/instances/{inst['name']}/databases"
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code != 200:
            return [], "OFFLINE"
        data = r.json().get("items", [])
        ignore = {"template0", "template1", "cloudsqladmin"}
        dbs = sorted([d["name"] for d in data if d["name"] not in ignore])
        if dbs:
            return dbs, "ONLINE"
        else:
            return [], "OFFLINE"
    except Exception:
        return [], "OFFLINE"

def list_databases_parallel(insts, creds, max_workers=10):
    """Lista databases e atualiza status em paralelo"""
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(list_databases_via_api, i, creds): i for i in insts}
        for fut in as_completed(futs):
            inst = futs[fut]
            key = f"{inst['project']}|{inst['name']}"
            try:
                dbs, status = fut.result()
                results[key] = {"dbs": dbs, "status": status}
            except Exception:
                results[key] = {"dbs": [], "status": "OFFLINE"}
    return results

# -----------------------------
# SQL execution helpers
# -----------------------------
def choose_ip_for_instance(inst):
    ips = inst.get("ipAddresses", [])
    if not ips:
        return None
    first = ips[0]
    if isinstance(first, dict):
        return first.get("ipAddress")
    return first

def run_sql_on_instance(inst, user, password, db, sql, timeout=10):
    host = choose_ip_for_instance(inst)
    out = {"instance": inst["name"], "project": inst["project"], "host": host, "success": False}
    if not host:
        out["error"] = "Sem IP público."
        return out
    try:
        conn = psycopg2.connect(host=host, user=user, password=password, dbname=db, connect_timeout=timeout)
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql)
        try:
            out["rows"] = cur.fetchall()
        except psycopg2.ProgrammingError:
            out["rows"] = None
            out["rows_affected"] = cur.rowcount
        conn.commit()
        conn.close()
        out["success"] = True
    except Exception as e:
        out["error"] = str(e)
    return out

# -----------------------------
# Session state
# -----------------------------
if "instances_cache" not in st.session_state:
    st.session_state.instances_cache = None
if "creds_cache" not in st.session_state:
    st.session_state.creds_cache = None
if "databases_cache" not in st.session_state:
    st.session_state.databases_cache = {}
if "query_history" not in st.session_state:
    st.session_state.query_history = []
if "expanders_state" not in st.session_state:
    st.session_state.expanders_state = {}

# -----------------------------
# Sidebar - Histórico
# -----------------------------
with st.sidebar.expander("📜 Histórico de queries", expanded=False):
    if st.session_state.query_history:
        for q in reversed(st.session_state.query_history[-15:]):
            st.markdown(
                f"🕒 `{q['time']}` — **{q['successes']}/{q['instances']} ok**\n\n```sql\n{q['sql'][:200]}\n```"
            )
    else:
        st.caption("Nenhuma query executada ainda.")

# -----------------------------
# UI principal
# -----------------------------
st.markdown("### 🔐 Autenticação e carregamento de instâncias")
col_a, col_b, col_c = st.columns([2, 2, 3])
with col_a:
    cred_file = st.file_uploader("JSON de credenciais", type=["json"])
with col_b:
    use_adc = st.checkbox("Usar ADC local se nenhum arquivo enviado", True)

cols_btn = st.columns([2, 2, 6])
with cols_btn[0]:
    list_btn = st.button("🔄 Listar todas instâncias")
with cols_btn[1]:
    list_db_btn = st.button("📚 Listar databases via API")

# -----------------------------
# Carregar instâncias
# -----------------------------
if list_btn:
    try:
        if cred_file:
            with open("._temp_cred.json", "wb") as f:
                f.write(cred_file.getvalue())
            creds = load_creds_from_file("._temp_cred.json")
        elif use_adc:
            creds, _ = try_adc_local()
        else:
            creds = None
        if creds:
            with st.spinner("Carregando instâncias via API..."):
                all_instances = list_all_instances_for_all_projects(creds)
            st.session_state.instances_cache = all_instances
            st.session_state.creds_cache = creds
            st.success(f"{len(all_instances)} instâncias carregadas.")
    except Exception as e:
        st.error(f"Erro: {e}")

# -----------------------------
# Exibição agrupada
# -----------------------------
if st.session_state.instances_cache:
    creds = st.session_state.creds_cache
    insts = st.session_state.instances_cache

    grouped = {}
    for inst in insts:
        grouped.setdefault(inst["project"], []).append(inst)

    if list_db_btn and creds:
        with st.spinner("Listando bases via Cloud SQL Admin API..."):
            all_flat = [i for plist in grouped.values() for i in plist]
            dbmap = list_databases_parallel(all_flat, creds)
        for k, v in dbmap.items():
            st.session_state.databases_cache[k] = v
        st.success("Bases e status atualizados com sucesso.")

    selected = []
    st.markdown("### ☁️ Instâncias por projeto")

    for proj, inst_list in grouped.items():
        exp_key = f"exp_{proj}"
        expanded_state = st.session_state.expanders_state.get(exp_key, False)
        with st.expander(f"📦 Projeto `{proj}` ({len(inst_list)} instâncias)", expanded=expanded_state):
            st.session_state.expanders_state[exp_key] = True
            for inst in inst_list:
                cols = st.columns([4, 1, 3, 3, 3])
                key = f"{inst['project']}|{inst['name']}"
                cache_data = st.session_state.databases_cache.get(key, {"dbs": [], "status": "UNKNOWN"})
                online_flag = cache_data["status"] == "ONLINE"
                status_icon = "🟢" if online_flag else "🔴"

                with cols[0]:
                    st.write(f"{status_icon} **{inst['name']}**")
                    st.caption(f"{inst['type']} • {inst.get('databaseVersion','')}")
                with cols[1]:
                    chk = st.checkbox("", key=f"{inst['project']}|{inst['name']}")
                with cols[2]:
                    st.write(choose_ip_for_instance(inst) or "---")
                dbs = cache_data["dbs"]
                with cols[3]:
                    if dbs:
                        st.selectbox("DB", dbs, key=f"dbsel|{key}", label_visibility="collapsed")
                    else:
                        st.selectbox("DB", ["(nenhuma)"], key=f"dbsel|{key}", disabled=True, label_visibility="collapsed")
                with cols[4]:
                    st.write(f"{inst['state']}")
                if chk:
                    selected.append(inst)

    st.divider()
    st.write(f"Instâncias selecionadas: **{len(selected)}**")

    db_user = st.text_input("DB user", "postgres")
    db_pass = st.text_input("DB password", type="password")
    sql = st.text_area("SQL a executar", "SELECT version();")
    max_workers = st.slider("Paralelismo", 1, 20, 8)

    if st.button("▶️ Executar SQL"):
        if not selected:
            st.warning("Nenhuma instância selecionada.")
        elif not db_pass:
            st.warning("Informe a senha.")
        else:
            with st.spinner("Executando SQL..."):
                results = []
                with ThreadPoolExecutor(max_workers=max_workers) as ex:
                    futmap = {
                        ex.submit(
                            run_sql_on_instance,
                            inst,
                            db_user,
                            db_pass,
                            st.session_state.get(f"dbsel|{inst['project']}|{inst['name']}", "postgres"),
                            sql,
                        ): inst for inst in selected
                    }
                    for fut in as_completed(futmap):
                        inst = futmap[fut]
                        try:
                            res = fut.result()
                        except Exception as e:
                            res = {"instance": inst["name"], "project": inst["project"], "success": False, "error": str(e)}
                        results.append((inst, res))

            # Exibir resultados
            success_count = 0
            for inst, r in results:
                st.subheader(f"{inst['project']} / {inst['name']}")
                if r["success"]:
                    success_count += 1
                    st.success("OK")
                    if r.get("rows"):
                        st.dataframe(r["rows"])
                    else:
                        st.caption("Query executada com sucesso.")
                else:
                    st.error(r.get("error"))

            # Adicionar histórico
            st.session_state.query_history.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "sql": sql.strip(),
                "instances": len(selected),
                "successes": success_count,
            })
else:
    st.info("Envie credenciais e clique em 'Listar todas instâncias'.")
