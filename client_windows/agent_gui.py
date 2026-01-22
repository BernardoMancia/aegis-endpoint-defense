import customtkinter as ctk
import threading
import time
import requests
import platform
import socket
import os
import sys
import subprocess
import winsound
from PIL import ImageGrab
import io
import base64

SERVER_IP = "0.0.0.0"
SERVER_PORT = 0000
API_TOKEN = ""
HOSTNAME = socket.gethostname()

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

class AgentGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("AEGIS CLIENT")
        self.geometry("500x600")
        self.resizable(False, False)
        
        self.msg_queue = [] # Fila de mensagens para enviar

        # TABVIEW
        self.tabview = ctk.CTkTabview(self, width=480, height=580)
        self.tabview.pack(pady=10)
        
        self.tab_status = self.tabview.add("Status")
        self.tab_chat = self.tabview.add("Chat")
        self.tab_log = self.tabview.add("Log")

        # TAB STATUS
        self.lbl_host = ctk.CTkLabel(self.tab_status, text=f"HOST: {HOSTNAME}", font=("Arial", 20, "bold"))
        self.lbl_host.pack(pady=50)
        self.lbl_conn = ctk.CTkLabel(self.tab_status, text="Conectando...", text_color="orange")
        self.lbl_conn.pack()

        # TAB CHAT
        self.txt_chat = ctk.CTkTextbox(self.tab_chat, width=450, height=350, state="disabled")
        self.txt_chat.pack(pady=5)
        
        self.entry_chat = ctk.CTkEntry(self.tab_chat, width=350, placeholder_text="Digite aqui...")
        self.entry_chat.pack(side="left", padx=10)
        self.entry_chat.bind("<Return>", self.send_chat_event) # Enter envia
        
        self.btn_send = ctk.CTkButton(self.tab_chat, text="Enviar", width=80, command=self.send_chat)
        self.btn_send.pack(side="right", padx=10)

        # TAB LOG
        self.txt_log = ctk.CTkTextbox(self.tab_log, width=450, height=450)
        self.txt_log.pack(pady=5)

        # START THREAD
        threading.Thread(target=self.loop_agent, daemon=True).start()

    def log(self, text):
        self.txt_log.insert("end", f"> {text}\n")
        self.txt_log.see("end")

    def add_chat_msg(self, sender, msg):
        self.txt_chat.configure(state="normal")
        self.txt_chat.insert("end", f"[{sender}]: {msg}\n")
        self.txt_chat.see("end")
        self.txt_chat.configure(state="disabled")
        if sender == "ADMIN": winsound.MessageBeep()

    def send_chat_event(self, event): self.send_chat()

    def send_chat(self):
        msg = self.entry_chat.get()
        if msg:
            self.msg_queue.append(msg) # Adiciona na fila p/ enviar no heartbeat
            self.add_chat_msg("VOCÊ", msg)
            self.entry_chat.delete(0, "end")

    def get_software(self):
        try:
            cmd = 'powershell "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName | ft -hide"'
            res = subprocess.check_output(cmd, shell=True, creationflags=subprocess.CREATE_NO_WINDOW).decode('utf-8', errors='ignore')
            return [l.strip() for l in res.split('\r\n') if len(l)>3][:50]
        except: return []

    def loop_agent(self):
        sw_list = self.get_software()
        
        while True:
            try:
                payload = {
                    "token": API_TOKEN, "hostname": socket.gethostname(),
                    "device_type": "desktop", "os_version": platform.platform(),
                    "software": sw_list, "ip": socket.gethostbyname(socket.gethostname())
                }

                # Se tiver msg na fila, envia
                if self.msg_queue:
                    payload['client_message'] = self.msg_queue.pop(0)

                r = requests.post(f"http://{SERVER_IP}:{SERVER_PORT}/api/heartbeat", json=payload, timeout=10)

                if r.status_code == 200:
                    self.lbl_conn.configure(text="CONECTADO", text_color="#22C55E")
                    data = r.json()
                    
                    # Comandos
                    cmd = data.get("command")
                    if cmd:
                        self.log(f"CMD: {cmd}")
                        if cmd == "screenshot":
                            try:
                                s = ImageGrab.grab(); b = io.BytesIO(); s.save(b, format='JPEG', quality=40)
                                b64 = base64.b64encode(b.getvalue()).decode()
                                requests.post(f"http://{SERVER_IP}:{SERVER_PORT}/api/upload_screenshot", 
                                              json={"hostname": socket.gethostname(), "image_data": "data:image/jpeg;base64,"+b64})
                                self.log("Print enviado.")
                            except: self.log("Erro print.")
                        
                        elif cmd == "beep": winsound.Beep(1000, 2000)
                        elif cmd == "shutdown": os.system("shutdown /s /t 0")
                        
                        elif cmd.startswith("set_hostname:"):
                            new_h = cmd.split(":")[1]
                            subprocess.run(f'powershell Rename-Computer -NewName "{new_h}" -Force', shell=True)
                            subprocess.run("shutdown /r /t 5", shell=True)

                        elif cmd.startswith("shell:"):
                            real = cmd.split("shell:")[1]
                            # Captura output e envia
                            try:
                                out = subprocess.check_output(real, shell=True, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW).decode('cp850', errors='ignore')
                            except subprocess.CalledProcessError as e:
                                out = e.output.decode('cp850', errors='ignore')
                            
                            # Envia resposta imediata
                            payload['cmd_output'] = out
                            requests.post(f"http://{SERVER_IP}:{SERVER_PORT}/api/heartbeat", json=payload)
                            self.log("Output shell enviado.")

                    # Chat Recebido
                    for m in data.get("chat_messages", []):
                        self.add_chat_msg("ADMIN", m)
                else:
                    self.lbl_conn.configure(text=f"ERRO {r.status_code}", text_color="red")

            except Exception as e:
                self.lbl_conn.configure(text="DESCONECTADO", text_color="red")
            
            time.sleep(3)

if __name__ == "__main__":
    app = AgentGUI()
    app.mainloop()