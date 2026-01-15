import customtkinter as ctk
import threading
import time
import requests
import psutil
import socket
import platform
import wmi
import os

SERVER_IP = "000.000.000.000"
SERVER_PORT = 0000

BASE_URL = f"http://{SERVER_IP}:{SERVER_PORT}"
REPORT_ENDPOINT = f"{BASE_URL}/api/report"
ANALYZE_ENDPOINT = f"{BASE_URL}/api/analyze"

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class SecurityScanner(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Aegis EDR - Endpoint Security")
        self.geometry("700x500")
        self.resizable(False, False)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar, text="🛡️ AEGIS EDR", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.status_label = ctk.CTkLabel(self.sidebar, text="SYSTEM SECURE", text_color="#2cc985", font=ctk.CTkFont(size=14, weight="bold"))
        self.status_label.grid(row=1, column=0, padx=20, pady=10)

        self.scan_button = ctk.CTkButton(self.sidebar, text="Start Deep Scan", command=self.start_scan_thread, fg_color="#3B8ED0")
        self.scan_button.grid(row=2, column=0, padx=20, pady=10)

        self.main_area = ctk.CTkFrame(self, corner_radius=10)
        self.main_area.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

        self.info_label = ctk.CTkLabel(self.main_area, text="System Status Monitor", font=ctk.CTkFont(size=24))
        self.info_label.pack(pady=20)

        self.progress_bar = ctk.CTkProgressBar(self.main_area, width=400)
        self.progress_bar.pack(pady=20)
        self.progress_bar.set(0)

        self.log_box = ctk.CTkTextbox(self.main_area, width=450, height=250)
        self.log_box.pack(pady=10)
        self.log_box.insert("0.0", "System initialized. Waiting for user command...\n")

    def log(self, message):
        self.log_box.insert("end", f"> {message}\n")
        self.log_box.see("end")

    def check_firewall(self):
        try:
            w = wmi.WMI(namespace=r"root\SecurityCenter2")
            fw = w.Query("Select * from FirewallProduct")
            if len(fw) > 0:
                return "Active", "Low"
            return "Disabled", "High"
        except:
            return "Unknown", "Medium"

    def check_suspicious_processes(self):
        suspicious = []
        targets = ['mimikatz.exe', 'ncat.exe', 'powershell.exe', 'cmd.exe'] 
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'] in targets:
                    suspicious.append(proc.info['name'])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        if suspicious:
            return suspicious, "Critical"
        return [], "Low"

    def run_scan(self):
        self.progress_bar.set(0.1)
        self.log("Scanning System Integrity...")
        self.status_label.configure(text="SCANNING...", text_color="orange")
        time.sleep(1)

        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        self.progress_bar.set(0.3)
        self.log(f"Resources: CPU {cpu}% | RAM {ram}%")

        fw_status, fw_risk = self.check_firewall()
        self.progress_bar.set(0.6)
        self.log(f"Firewall Status: {fw_status} (Risk: {fw_risk})")

        threats, proc_risk = self.check_suspicious_processes()
        self.progress_bar.set(0.9)
        
        risk_level = "Low"
        if fw_risk == "High" or proc_risk == "Critical":
            risk_level = "High"
            self.status_label.configure(text="THREAT DETECTED", text_color="#ff4d4d")
        else:
            self.status_label.configure(text="SYSTEM SECURE", text_color="#2cc985")

        report_data = {
            'hostname': socket.gethostname(),
            'ip': socket.gethostbyname(socket.gethostname()),
            'cpu': cpu,
            'ram': ram,
            'firewall': fw_status,
            'threats_found': threats,
            'risk_level': risk_level
        }
        
        try:
            self.log("Uploading telemetry to HQ...")
            requests.post(REPORT_ENDPOINT, json=report_data, timeout=5)
            
            if risk_level == "High":
                self.log("Requesting AI Forensics Analysis...")
                requests.post(ANALYZE_ENDPOINT, json=report_data, timeout=10)
                
            self.log("Sync Complete.")
        except Exception as e:
            self.log(f"Error contacting server: {e}")

        self.progress_bar.set(1.0)
        time.sleep(1)
        self.progress_bar.set(0)

    def start_scan_thread(self):
        threading.Thread(target=self.run_scan).start()

if __name__ == "__main__":
    app = SecurityScanner()
    app.mainloop()