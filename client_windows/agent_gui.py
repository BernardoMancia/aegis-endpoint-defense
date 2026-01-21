import customtkinter as ctk
import threading
import time
import requests
import psutil
import socket
import os
import sys
import winreg
import subprocess
import io
import base64
import platform
from PIL import ImageGrab

# ========================================================
SERVER_IP = ""
SERVER_PORT = 5000
API_TOKEN = ""     
# ========================================================

BASE_URL = f"http://{SERVER_IP}:{SERVER_PORT}"

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class AegisAgent(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.hostname = socket.gethostname()
        self.os_version = f"{platform.system()} {platform.release()} ({platform.version()})"
        self.pid = os.getpid()
        
        self.setup_persistence()
        
        self.title(f"Aegis EDR - {self.hostname}")
        self.geometry("800x600")
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Barra Lateral
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        ctk.CTkLabel(self.sidebar, text="🛡️ AEGIS", font=("Arial", 20, "bold")).pack(pady=20)
        self.status_lbl = ctk.CTkLabel(self.sidebar, text="PROTECTED", text_color="#00ff00")
        self.status_lbl.pack(pady=10)

        # Área Principal
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        
        # Console
        self.console = ctk.CTkTextbox(self.main_frame, height=250)
        self.console.pack(fill="x", padx=10, pady=5)
        
        # Chat
        self.chat_frame = ctk.CTkFrame(self.main_frame)
        self.chat_frame.pack(fill="both", expand=True, padx=10, pady=10)
        ctk.CTkLabel(self.chat_frame, text="Chat Suporte").pack(anchor="w", padx=5)
        
        self.chat_history = ctk.CTkTextbox(self.chat_frame, state="disabled", height=150)
        self.chat_history.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.chat_input = ctk.CTkEntry(self.chat_frame, placeholder_text="Mensagem...")
        self.chat_input.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        ctk.CTkButton(self.chat_frame, text="Enviar", width=80, command=self.send_chat).pack(side="right", padx=5)

        self.log(f"Agente Iniciado (PID: {self.pid})")
        self.log(f"Conectando a {BASE_URL}...")
        
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()

    def setup_persistence(self):
        try:
            path = os.path.abspath(sys.argv[0])
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "AegisEDR", 0, winreg.REG_SZ, path)
            winreg.CloseKey(key)
        except: pass

    def log(self, msg):
        try:
            self.console.insert("end", f"> {msg}\n")
            self.console.see("end")
        except: pass

    def add_chat_msg(self, sender, msg):
        self.chat_history.configure(state="normal")
        self.chat_history.insert("end", f"[{sender}]: {msg}\n")
        self.chat_history.configure(state="disabled")
        self.chat_history.see("end")

    def send_chat(self):
        msg = self.chat_input.get()
        if not msg: return
        self.add_chat_msg("Eu", msg)
        try:
            requests.post(f"{BASE_URL}/api/send_chat", json={'hostname': self.hostname, 'message': msg})
            self.chat_input.delete(0, 'end')
        except: self.log("Erro de conexão chat")

    def execute_system_command(self, cmd):
        self.log(f"Comando recebido: {cmd}")
        if cmd == 'restart':
            os.system("shutdown /r /t 5")
        elif cmd == 'shutdown':
            os.system("shutdown /s /t 5")
        elif cmd.startswith('rename:'):
            new_name = cmd.split(':')[1]
            subprocess.run(["powershell", "-Command", f'Rename-Computer -NewName "{new_name}" -Force'], capture_output=True)
            self.log(f"Renomeando para {new_name}")
        elif cmd == 'screenshot':
            self.capture_screen()

    def capture_screen(self):
        try:
            screenshot = ImageGrab.grab()
            buffer = io.BytesIO()
            screenshot.save(buffer, format="PNG", optimize=True, quality=50)
            img_str = base64.b64encode(buffer.getvalue()).decode()
            requests.post(f"{BASE_URL}/api/upload_screenshot", json={'hostname': self.hostname, 'image_data': img_str})
            self.log("Screenshot enviada")
        except: self.log("Falha no screenshot")

    def get_software(self):
        try:
            cmd = 'powershell "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName"'
            out = subprocess.check_output(cmd, shell=True).decode(errors='ignore')
            return ", ".join([l.strip() for l in out.split('\r\n') if l.strip() and "DisplayName" not in l and "---" not in l][:20])
        except: return ""

    def check_threats(self):
        suspicious = []
        targets = ['mimikatz.exe', 'ncat.exe', 'keylogger.exe']
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['pid'] == self.pid: continue 
                if proc.info['name'] in targets: suspicious.append(proc.info['name'])
            except: pass
        return suspicious if suspicious else None

    def heartbeat_loop(self):
        software = self.get_software()
        while True:
            try:
                payload = {
                    'token': API_TOKEN,
                    'hostname': self.hostname,
                    'os_version': self.os_version,
                    'ip': socket.gethostbyname(self.hostname),
                    'cpu': psutil.cpu_percent(),
                    'ram': psutil.virtual_memory().percent,
                    'software': software,
                    'threats': self.check_threats()
                }
                res = requests.post(f"{BASE_URL}/api/heartbeat", json=payload, timeout=5)
                if res.status_code == 200:
                    self.status_lbl.configure(text="CONECTADO", text_color="#00ff00")
                    data = res.json()
                    if data.get('command'): self.execute_system_command(data['command'])
                    if data.get('chat'):
                        for m in data['chat']: 
                            self.add_chat_msg("Admin", m)
                            self.deiconify()
                            self.lift()
                else: self.status_lbl.configure(text="ERRO TOKEN", text_color="orange")
            except Exception as e:
                self.status_lbl.configure(text="DESCONECTADO", text_color="red")
            
            time.sleep(5)

if __name__ == "__main__":
    app = AegisAgent()
    app.mainloop()