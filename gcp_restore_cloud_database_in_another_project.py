# dependencias usadas no linux
# sudo apt-get install python3-tk
# sudo apt-get install python3-pil python3-pil.imagetk

# instalar dependencias pelo pip
# pip install google-auth google-auth-oauthlib
# pip install --upgrade google-api-python-client
# pip install ttkbootstrap --break-system-packages

# Variável global para armazenar as credenciais
# Para gerar as credencias executar o comando
# gcloud auth application-default login
# executar a autenticação do browser e voltar ao prompt
# copiar o arquivo ou o caminho do arquivo que será criado em
# C:\Users\????\AppData\Roaming\gcloud\application_default_credentials.json
# Onde ???? é o seu usuário



import tkinter as tk
from tkinter import filedialog, messagebox
import requests
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from PIL import Image, ImageTk

# Classe com barra de rolagem e filtro
class ProjectSelector(ttk.Frame):
    def __init__(self, master, on_select_callback, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.on_select_callback = on_select_callback
        self.projects = []

        self.entry = ttk.Entry(self)
        self.entry.pack(fill=tk.X, pady=2)
        self.entry.bind('<KeyRelease>', self.filter_projects)

        listbox_frame = ttk.Frame(self)
        listbox_frame.pack(fill=tk.BOTH, expand=True)

        self.scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.listbox = tk.Listbox(listbox_frame, height=6, yscrollcommand=self.scrollbar.set, font=("Segoe UI", 10))
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.config(command=self.listbox.yview)

        self.listbox.bind("<<ListboxSelect>>", self.select_project)

    def set_projects(self, projects):
        self.projects = sorted(projects)
        self.update_listbox(self.projects)

    def filter_projects(self, event=None):
        search = self.entry.get().lower()
        filtered = [p for p in self.projects if search in p.lower()]
        self.update_listbox(filtered)

    def update_listbox(self, values):
        self.listbox.delete(0, tk.END)
        for v in values:
            self.listbox.insert(tk.END, v)

    def select_project(self, event=None):
        if self.listbox.curselection():
            selected = self.listbox.get(self.listbox.curselection())
            self.entry.delete(0, tk.END)
            self.entry.insert(0, selected)
            self.on_select_callback(selected)

    def get_selected_project(self):
        return self.entry.get().strip()

# Autenticação
creds = None

def authenticate_with_gcp(cred_file):
    creds = Credentials.from_authorized_user_file(cred_file)
    if not creds.valid:
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
    return creds

def get_projects():
    headers = {"Authorization": f"Bearer {creds.token}"}
    url = "https://cloudresourcemanager.googleapis.com/v1/projects"
    response = requests.get(url, headers=headers)
    return [project['projectId'] for project in response.json().get('projects', [])]

def get_instances(project_id):
    headers = {"Authorization": f"Bearer {creds.token}"}
    url = f"https://sqladmin.googleapis.com/v1/projects/{project_id}/instances"
    response = requests.get(url, headers=headers)
    return [instance['name'] for instance in response.json().get('items', [])]

def load_credentials():
    global creds
    filepath = filedialog.askopenfilename(title="Carregar arquivo de credenciais",filetypes=[("Arquivos Json","*.json")])
    if filepath:
        creds = authenticate_with_gcp(filepath)
        projects = get_projects()
        left_project_selector.set_projects(projects)
        right_project_selector.set_projects(projects)

def update_instances_dropdown(project_selector, instance_dropdown):
    instances = get_instances(project_selector.get_selected_project())
    instance_dropdown["values"] = sorted(instances)
    instance_dropdown["state"] = "readonly"

def on_left_project_selected(project_id):
    update_instances_dropdown(left_project_selector, left_instance_dropdown)

def on_right_project_selected(project_id):
    update_instances_dropdown(right_project_selector, right_instance_dropdown)

def load_backups():
    if not creds:
        messagebox.showwarning("Aviso", "Credenciais não carregadas.")
        return
    else:
        backup_listbox.delete(0, tk.END)
        project_id = left_project_selector.get_selected_project()
        instance_id = left_instance_dropdown.get()
        headers = {"Authorization": f"Bearer {creds.token}"}
        url = f"https://sqladmin.googleapis.com/v1/projects/{project_id}/instances/{instance_id}/backupRuns"
        response = requests.get(url, headers=headers)
        for backup in response.json().get('items', []):
            backup_listbox.insert(tk.END, f"ID: {backup['id']} | StartTime: {backup['startTime']}")

def restore_backup():
    if not backup_listbox.curselection():
        messagebox.showwarning("Aviso", "Selecione um backup para restaurar.")
        return
    if not right_instance_dropdown.get():
        messagebox.showwarning("Aviso", "Seleciona uma instância de destino.")
        return
    confirm = messagebox.askyesno("Confirmação", "Deseja realmente prosseguir? Isso sobrescreverá a instância de destino.")
    if not confirm:
        return

    selected_backup = backup_listbox.get(backup_listbox.curselection())
    backup_id = selected_backup.split("|")[0].split(":")[1].strip()
    source_project = left_project_selector.get_selected_project()
    source_instance = left_instance_dropdown.get()
    target_project = right_project_selector.get_selected_project()
    target_instance = right_instance_dropdown.get()

    data = {
        "restoreBackupContext": {
            "backupRunId": backup_id,
            "project": source_project,
            "instanceId": source_instance
        }
    }

    headers = {"Authorization": f"Bearer {creds.token}", "Content-Type": "application/json"}
    url = f"https://sqladmin.googleapis.com/v1/projects/{target_project}/instances/{target_instance}/restoreBackup"
    response = requests.post(url, headers=headers, json=data)

    if response.status_code == 200:
        messagebox.showinfo("Sucesso", "Solicitação de clonagem enviada com sucesso!")
    else:
        messagebox.showerror("Erro", f"Ocorreu um erro: {response.json()}")

# App Principal
app = ttk.Window(themename="darkly")  # pode trocar por: 'cosmo', 'litera', 'journal', 'superhero', etc
app.title("GCP Backup Restore Utility")
#app.geometry("900x600")
app.geometry("650x600")
app.resizable(False, False)

# Frame principal
main_frame = ttk.Frame(app, padding=20)
main_frame.pack(fill=BOTH, expand=True)

# Painéis lado esquerdo (Origem) e direito (Destino)
left_panel = ttk.Labelframe(main_frame, text="Origem", padding=10)
left_panel.grid(row=0, column=0, padx=10, pady=10, sticky=N)

right_panel = ttk.Labelframe(main_frame, text="Destino", padding=10)
right_panel.grid(row=0, column=1, padx=10, pady=10, sticky=N)

# Seletor de projetos GCP com filtro
left_project_selector = ProjectSelector(left_panel, on_left_project_selected)
left_project_selector.pack(fill=BOTH, pady=5)

left_instance_dropdown = ttk.Combobox(left_panel, state='disabled')
left_instance_dropdown.pack(fill=X, pady=5)

ttk.Button(left_panel, text="Carregar Backups", bootstyle=PRIMARY, command=load_backups).pack(fill=X, pady=10)

right_project_selector = ProjectSelector(right_panel, on_right_project_selected)
right_project_selector.pack(fill=BOTH, pady=5)

right_instance_dropdown = ttk.Combobox(right_panel, state='disabled')
right_instance_dropdown.pack(fill=X, pady=5)

ttk.Button(right_panel, text="Restaurar", bootstyle=SUCCESS, command=restore_backup).pack(fill=X, pady=10)

# Botão principal para carregar credenciais
ttk.Button(main_frame, text="Carregar Credenciais GCP", bootstyle=INFO, command=load_credentials).grid(row=1, column=0, columnspan=2, pady=15)

# Lista de backups
backup_frame = ttk.Labelframe(main_frame, text="Backups disponíveis", padding=10)
backup_frame.grid(row=2, column=0, columnspan=2, sticky=W+E, padx=10)

backup_listbox = tk.Listbox(backup_frame, width=70, height=5, font=("Segoe UI", 10))
backup_listbox.pack(side=tk.LEFT, fill=BOTH, expand=True)

backup_scroll = ttk.Scrollbar(backup_frame, orient=VERTICAL, command=backup_listbox.yview)
backup_scroll.pack(side=tk.RIGHT, fill=Y)

backup_listbox.config(yscrollcommand=backup_scroll.set)

# Inicia a interface
app.mainloop()
