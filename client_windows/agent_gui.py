import customtkinter as ctk
import psutil
import requests
import socket
import platform
import threading
import time
import sys
from datetime import datetime

SERVER_IP = "0.0.0.0"
SERVER_PORT = 0000

API_URL = f"http://{SERVER_IP}:{SERVER_PORT}/api/telemetry"
AGENT_VERSION = "1.0.0"

try:
    import wmi
    wmi_available = True
except ImportError:
    wmi_available = False

class AegisAgent(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(f"Aegis EDR Sensor - v{AGENT_VERSION}")
        self.geometry("500x450")
        self.resizable(False, False)
        
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("green")

        self.running = True
        self.hostname = socket.gethostname()
        self.ip_local = socket.gethostbyname(self.hostname)
        self.os_info = f"{platform.system()} {platform.release()}"

        self.create_widgets()

        self.thread = threading.Thread(target=self.telemetry_loop, daemon=True)
        self.thread.start()

    def create_widgets(self):
        self.header_frame = ctk.CTkFrame(self)
        self.header_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(
            self.header_frame, 
            text="AEGIS ENDPOINT DEFENSE", 
            font=("Roboto", 20, "bold"),
            text_color="#00FF00"
        ).pack(pady=5)

        ctk.CTkLabel(
            self.header_frame, 
            text=f"Host: {self.hostname} | Target: {SERVER_IP}",
            font=("Consolas", 12)
        ).pack(pady=5)

        self.lbl_status = ctk.CTkLabel(
            self, 
            text="STATUS: INITIALIZING", 
            font=("Roboto", 14, "bold"),
            text_color="orange"
        )
        self.lbl_status.pack(pady=10)

        self.metrics_frame = ctk.CTkFrame(self)
        self.metrics_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.lbl_cpu = ctk.CTkLabel(self.metrics_frame, text="CPU Usage: 0%")
        self.lbl_cpu.pack(pady=2)
        self.prog_cpu = ctk.CTkProgressBar(self.metrics_frame, width=300)
        self.prog_cpu.set(0)
        self.prog_cpu.pack(pady=2)

        self.lbl_ram = ctk.CTkLabel(self.metrics_frame, text="RAM Usage: 0%")
        self.lbl_ram.pack(pady=2)
        self.prog_ram = ctk.CTkProgressBar(self.metrics_frame, width=300)
        self.prog_ram.set(0)
        self.prog_ram.pack(pady=2)

        self.log_box = ctk.CTkTextbox(self, height=100, font=("Consolas", 11))
        self.log_box.pack(fill="x", padx=10, pady=10)

        ctk.CTkButton(self, text="Encerrar Agente", command=self.on_close, fg_color="red", hover_color="darkred").pack(pady=10)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_box.insert("end", f"[{timestamp}] {message}\n")
        self.log_box.see("end")

    def get_antivirus_status(self):
        av_list = []
        if wmi_available and platform.system() == "Windows":
            try:
                c = wmi.WMI(namespace=r"root\SecurityCenter2")
                for item in c.AntiVirusProduct():
                    av_list.append(item.displayName)
            except:
                return "WMI Access Error"
        return ", ".join(av_list) if av_list else "Not Detected"

    def telemetry_loop(self):
        self.log_message(f"Connecting to {API_URL}...")
        while self.running:
            try:
                cpu = psutil.cpu_percent(interval=1)
                ram = psutil.virtual_memory().percent
                disk = psutil.disk_usage('/').percent
                
                self.prog_cpu.set(cpu / 100)
                self.lbl_cpu.configure(text=f"CPU Usage: {cpu}%")
                self.prog_ram.set(ram / 100)
                self.lbl_ram.configure(text=f"RAM Usage: {ram}%")

                payload = {
                    "hostname": self.hostname,
                    "os": self.os_info,
                    "cpu": cpu,
                    "ram": ram,
                    "disk": disk,
                    "antivirus": self.get_antivirus_status()
                }

                response = requests.post(API_URL, json=payload, timeout=5)

                if response.status_code == 200:
                    self.lbl_status.configure(text="STATUS: CONNECTED", text_color="#00FF00")
                else:
                    self.lbl_status.configure(text=f"SERVER ERROR: {response.status_code}", text_color="orange")
                    self.log_message(f"HTTP Error: {response.status_code}")

            except requests.exceptions.ConnectionError:
                self.lbl_status.configure(text="STATUS: UNREACHABLE", text_color="red")
            except Exception as e:
                self.log_message(f"Error: {str(e)}")

            time.sleep(5)

    def on_close(self):
        self.running = False
        self.destroy()
        sys.exit()

if __name__ == "__main__":
    app = AegisAgent()
    app.mainloop()