# dependencias usadas no linux
# sudo apt-get install python3-tk
# sudo apt-get install python3-pil python3-pil.imagetk

# instalar dependencias pelo pip
# pip install google-auth google-auth-oauthlib
# pip install --upgrade google-api-python-client
# pip install ttkbootstrap --break-system-packages

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import requests
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

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
db_logs = []
creds = None
flag_vars = []

# Log visual
def log_message(msg):
    db_logs.append(msg)
    log_listbox.insert(tk.END, msg)
    log_listbox.yview_moveto(1)

# Funções GCP
def authenticate_with_gcp(cred_file):
    creds = Credentials.from_authorized_user_file(cred_file)
    if not creds.valid:
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
    log_message("Credenciais carregadas com sucesso.")
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

def get_instance_flags(project_id, instance_id):
    headers = {"Authorization": f"Bearer {creds.token}"}
    url = f"https://sqladmin.googleapis.com/v1/projects/{project_id}/instances/{instance_id}"
    response = requests.get(url, headers=headers)
    data = response.json()
    return data.get('settings', {}).get('databaseFlags', [])

# Interface de Flags com Checkbuttons e destaque
select_all_var = None

def display_flags(flags):
    for widget in flags_canvas_frame.winfo_children():
        widget.destroy()

    global select_all_var
    select_all_var = tk.BooleanVar()
    select_all_check = tk.Checkbutton(flags_canvas_frame, text="Selecionar Tudo", variable=select_all_var, command=toggle_select_all)
    select_all_check.pack(anchor='w')

    global flag_vars
    flag_vars = []

    for flag in flags:
        var = tk.BooleanVar(value=True)
        flag_vars.append((var, flag))

        cb = tk.Checkbutton(flags_canvas_frame, text=f"{flag.get('name')} = {flag.get('value')}", variable=var, anchor='w', justify='left')
        cb.pack(anchor='w', fill='x')

        cb.bind('<Double-1>', lambda e, f=flag, cb_ref=cb: edit_flag_value(f, cb_ref))

def toggle_select_all():
    for var, _ in flag_vars:
        var.set(select_all_var.get())

def edit_flag_value(flag, checkbox):
    current_value = flag.get('value', '')
    new_value = simpledialog.askstring("Editar Flag", f"Novo valor para {flag.get('name')}:", initialvalue=current_value)
    if new_value is not None:
        flag['value'] = new_value.strip()
        checkbox.config(text=f"{flag.get('name')} = {flag['value']}", fg='yellow')
        log_message(f"Flag {flag.get('name')} alterada para {flag['value']}.")
        app.after(3000, lambda: checkbox.config(fg='white'))

# Funções principais
def load_flags():
    if not creds:
        messagebox.showwarning("Aviso", "Credenciais não carregadas.")
        return
    project_id = left_project_selector.get_selected_project()
    instance_id = left_instance_dropdown.get()
    flags = get_instance_flags(project_id, instance_id)
    display_flags(flags)
    log_message(f"Carregadas {len(flags)} flags da instância {instance_id}.")

def apply_flags_to_instance():
    source_project = left_project_selector.get_selected_project()
    source_instance = left_instance_dropdown.get()
    target_project = right_project_selector.get_selected_project()
    target_instance = right_instance_dropdown.get()

    if not source_project or not source_instance or not target_project or not target_instance:
        messagebox.showwarning("Aviso", "Preencha todos os campos para aplicar as flags.")
        return

    selected_flags = [flag for var, flag in flag_vars if var.get()]

    if not selected_flags:
        messagebox.showinfo("Aviso", "Nenhuma flag selecionada.")
        return

    confirm = messagebox.askyesno("Confirmação", f"Aplicar {len(selected_flags)} flags na instância de destino?")
    if not confirm:
        return

    headers = {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json"
    }
    url = f"https://sqladmin.googleapis.com/v1/projects/{target_project}/instances/{target_instance}?updateMask=settings.databaseFlags"
    data = {"settings": {"databaseFlags": selected_flags}}
    response = requests.patch(url, headers=headers, json=data)

    if response.status_code == 200:
        messagebox.showinfo("Sucesso", "Flags aplicadas com sucesso na instância de destino!")
        log_message(f"Flags aplicadas na instância {target_instance}.")
    else:
        messagebox.showerror("Erro", f"Erro ao aplicar flags: {response.text}")
        log_message(f"Erro ao aplicar flags: {response.text}")

def load_credentials():
    global creds
    filepath = filedialog.askopenfilename(title="Carregar arquivo de credenciais", filetypes=[("Arquivos Json", "*.json")])
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

# App Principal
app = ttk.Window(themename="darkly")
app.title("GCP Flag Copier Utility")
app.geometry("650x1000")
app.resizable(False, True)

main_frame = ttk.Frame(app, padding=20)
main_frame.pack(fill=BOTH, expand=True)

left_panel = ttk.Labelframe(main_frame, text="Origem", padding=10)
left_panel.grid(row=0, column=0, padx=10, pady=10, sticky=N)

right_panel = ttk.Labelframe(main_frame, text="Destino", padding=10)
right_panel.grid(row=0, column=1, padx=10, pady=10, sticky=N)

left_project_selector = ProjectSelector(left_panel, on_left_project_selected)
left_project_selector.pack(fill=BOTH, pady=5)

left_instance_dropdown = ttk.Combobox(left_panel, state='disabled')
left_instance_dropdown.pack(fill=X, pady=5)

ttk.Button(left_panel, text="Carregar Flags", bootstyle=PRIMARY, command=load_flags).pack(fill=X, pady=10)

right_project_selector = ProjectSelector(right_panel, on_right_project_selected)
right_project_selector.pack(fill=BOTH, pady=5)

right_instance_dropdown = ttk.Combobox(right_panel, state='disabled')
right_instance_dropdown.pack(fill=X, pady=5)

ttk.Button(right_panel, text="Aplicar Flags", bootstyle=SUCCESS, command=apply_flags_to_instance).pack(fill=X, pady=10)

ttk.Button(main_frame, text="Carregar Credenciais GCP", bootstyle=INFO, command=load_credentials).grid(row=1, column=0, columnspan=2, pady=15)

# Frame com Canvas e Scroll para flags
flags_frame = ttk.Labelframe(main_frame, text="Flags da Instância de Origem", padding=10)
flags_frame.grid(row=2, column=0, columnspan=2, sticky=W+E+N+S, padx=10)

flags_canvas = tk.Canvas(flags_frame)
flags_scrollbar = ttk.Scrollbar(flags_frame, orient=VERTICAL, command=flags_canvas.yview)
flags_canvas.configure(yscrollcommand=flags_scrollbar.set)
flags_canvas.pack(side=LEFT, fill=BOTH, expand=True)
flags_scrollbar.pack(side=RIGHT, fill=Y)

flags_canvas_frame = ttk.Frame(flags_canvas)
flags_canvas_frame.bind("<Configure>", lambda e: flags_canvas.configure(scrollregion=flags_canvas.bbox("all")))
flags_canvas.create_window((0, 0), window=flags_canvas_frame, anchor="nw")

# Logs
log_frame = ttk.Labelframe(main_frame, text="Logs", padding=10)
log_frame.grid(row=3, column=0, columnspan=2, sticky=W+E, padx=10, pady=10)

log_listbox = tk.Listbox(log_frame, width=70, height=10, font=("Segoe UI", 10))
log_listbox.pack(side=tk.LEFT, fill=BOTH, expand=True)

log_scroll = ttk.Scrollbar(log_frame, orient=VERTICAL, command=log_listbox.yview)
log_scroll.pack(side=tk.RIGHT, fill=Y)
log_listbox.config(yscrollcommand=log_scroll.set)

app.mainloop()
