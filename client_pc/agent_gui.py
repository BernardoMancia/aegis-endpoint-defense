"""
Aegis EDR — Windows Agent GUI
================================
Agente de endpoint com interface CustomTkinter multi-aba.
Funcionalidades: Heartbeat, Event Log, FIM, Scanner, Comandos Remotos, Persistência.
"""

import os
import sys
import json
import socket
import hashlib
import logging
import platform
import subprocess
import threading
import uuid
import base64
import time
import winreg
from datetime import datetime
from pathlib import Path

import psutil
import requests
import customtkinter as ctk
from PIL import ImageGrab

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

DEFAULT_SERVER = os.getenv("AEGIS_SERVER", "http://localhost:5000")
DEFAULT_TOKEN  = "mude-este-token-secreto-agora"
HEARTBEAT_INTERVAL = 10 
LOG_INTERVAL       = 30 
FIM_INTERVAL       = 60 

AUTOSTART_KEY  = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_NAME = "AegisAgent"

log = logging.getLogger("aegis-agent")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")




def get_original_hostname() -> str:
    """Identificador imutável baseado no hostname + UUID da máquina."""
    hostname = socket.gethostname()
    try:
        machine_id = str(uuid.UUID(int=uuid.getnode()))
    except Exception:
        machine_id = hostname
    return f"{hostname}_{machine_id[:8]}"


def get_network_info() -> dict:
    """Coleta IP, MAC e gateway padrão."""
    info = {"ip": "N/A", "mac": "N/A", "gateway": "N/A"}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["ip"] = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    try:
        mac_int = uuid.getnode()
        info["mac"] = ":".join(f"{mac_int:012x}"[i:i+2].upper() for i in range(0, 12, 2))
    except Exception:
        pass
    try:
        out = subprocess.check_output("ipconfig", encoding="cp850", errors="ignore")
        for line in out.splitlines():
            if "Gateway" in line and line.strip().split(":")[-1].strip():
                info["gateway"] = line.strip().split(":")[-1].strip()
                break
    except Exception:
        pass
    return info


def get_os_info() -> str:
    return f"{platform.system()} {platform.version()} ({platform.machine()})"


def take_screenshot() -> str | None:
    """Captura a tela e retorna em base64."""
    try:
        img = ImageGrab.grab()
        from io import BytesIO
        buf = BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        log.warning(f"Screenshot falhou: {e}")
        return None


def compute_hash(path: str) -> str | None:
    try:
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except Exception:
        return None




def install_autostart():
    """Adiciona o agente ao registro de inicialização automática."""
    try:
        exe = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, AUTOSTART_NAME, 0, winreg.REG_SZ, f'"{exe}"')
        winreg.CloseKey(key)
        return True
    except Exception as e:
        log.error(f"Falha ao instalar autostart: {e}")
        return False


def remove_autostart():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, AUTOSTART_NAME)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def is_autostart_installed() -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY, 0, winreg.KEY_READ)
        winreg.QueryValueEx(key, AUTOSTART_NAME)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False




def isolate_host(enable: bool):
    """Bloqueia/desbloqueia TODO o tráfego de saída via netsh (isolamento)."""
    try:
        action = "add" if enable else "delete"
        cmd = (
            f'netsh advfirewall firewall {action} rule name="AEGIS_ISOLATION" '
            f'dir=out action=block protocol=any'
        )
        subprocess.run(cmd, shell=True, capture_output=True)
        log.warning(f"[FIREWALL] Isolamento {'ATIVADO' if enable else 'REMOVIDO'}")
    except Exception as e:
        log.error(f"Erro ao configurar firewall: {e}")




def check_vulnerabilities() -> list:
    """Verifica configurações Windows e retorna lista de Dicionários de vulns."""
    vulns = []

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
        val, _ = winreg.QueryValueEx(key, "EnableLUA")
        if val == 0:
            vulns.append({
                "title": "UAC Desativado",
                "description": "User Account Control está desativado, permitindo que malwares escalem privilégios sem confirmação.",
                "severity": "HIGH",
                "remediation_cmd": 'reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f'
            })
        winreg.CloseKey(key)
    except Exception:
        pass

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")
        val, _ = winreg.QueryValueEx(key, "SMB1")
        if val == 1:
            vulns.append({
                "title": "SMBv1 Ativado",
                "description": "Protocolo legado severamente vulnerável (ex: exploit EternalBlue).",
                "severity": "CRITICAL",
                "remediation_cmd": 'powershell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"'
            })
        winreg.CloseKey(key)
    except Exception:
        pass

    if not vulns:
        vulns.append({
            "title": "Auditoria de Criação de Processos Ausente",
            "description": "Rastreamento avançado de execução de processos (ID 4688) desativado.",
            "severity": "MEDIUM",
            "remediation_cmd": 'auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable'
        })

    return vulns




def read_windows_events(max_events: int = 50) -> list:
    """Lê eventos dos logs Security e System usando pywin32."""
    events = []
    try:
        import win32evtlog
        import win32evtlogutil
        import pywintypes

        INTERESTING_IDS = {4625, 4672, 4648, 4688, 4697, 4698, 4720, 4732, 7045, 1102, 4103, 4104}
        logs_to_read = [("Security", "Security"), ("System", "System")]

        for log_name, source in logs_to_read:
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                records = win32evtlog.ReadEventLog(hand, flags, 0)
                win32evtlog.CloseEventLog(hand)

                for rec in records[:max_events]:
                    eid = rec.EventID & 0xFFFF
                    if eid not in INTERESTING_IDS:
                        continue
                    try:
                        msg = win32evtlogutil.SafeFormatMessage(rec, source)
                    except Exception:
                        msg = str(rec.StringInserts or "")
                    events.append({
                        "event_id": str(eid),
                        "source": source.lower(),
                        "event_type": f"EventID_{eid}",
                        "raw_data": msg[:1024],
                        "timestamp": rec.TimeGenerated.Format(),
                    })
            except Exception as e:
                log.warning(f"Erro lendo log {log_name}: {e}")
    except ImportError:

        events.append({
            "event_id": "4625",
            "source": "security",
            "event_type": "EventID_4625",
            "raw_data": "[SIMULADO] Failed logon attempt",
        })
    return events




class AegisAgentCore:
    """
    Lógica headless do agente: heartbeat, envio de logs, FIM e execução de comandos.
    Projetado para ser usado tanto com a GUI quanto de forma autônoma.
    """

    def __init__(self, server_url: str, api_token: str):
        self.server_url      = server_url.rstrip("/")
        self.api_token       = api_token
        self.original_hostname = get_original_hostname()
        self.net_info        = get_network_info()
        self.os_info         = get_os_info()
        self.agent_id        = None
        self.running         = False
        self.event_buffer    = []
        self.event_lock      = threading.Lock()
        self.fim_hashes      = {} 
        self.fim_dirs        = [] 
        self.status_callback = None
        self.log_callback    = None
        
        self.chat_queue      = []  
        self.chat_callback   = None

    @property
    def headers(self):
        return {"Authorization": f"Bearer {self.api_token}", "Content-Type": "application/json"}

    def notify(self, msg: str, level="info"):
        log.info(msg)
        if self.log_callback:
            try:
                self.log_callback(msg, level)
            except Exception:
                pass

    def heartbeat(self):
        """Envia heartbeat ao C2 e processa comando pendente."""
        payload = {
            "original_hostname": self.original_hostname,
            "hostname": socket.gethostname(),
            "ip_address": self.net_info["ip"],
            "mac_address": self.net_info["mac"],
            "os_info": self.os_info,
            "agent_version": "1.0.0",
            "platform": "windows",
        }
        try:
            res = requests.post(f"{self.server_url}/api/heartbeat", json=payload,
                                headers=self.headers, timeout=10)
            if res.status_code == 200:
                data = res.json()
                self.agent_id = data.get("agent_id")
                if self.status_callback:
                    self.status_callback("online")
                cmd = data.get("pending_command")
                if cmd:
                    self.execute_command(cmd)
            else:
                if self.status_callback:
                    self.status_callback("erro")
                self.notify(f"Heartbeat server status: {res.status_code} - {res.text}", "error")
        except requests.exceptions.ConnectionError:
            if self.status_callback:
                self.status_callback("offline")
            self.notify(f"Heartbeat server unreachable: conexao recusada.", "error")
        except Exception as e:
            self.notify(f"Heartbeat erro: {e}", "error")
            import traceback
            traceback.print_exc()

    def flush_events(self):
        """Envia eventos acumulados em lote ao C2."""
        with self.event_lock:
            if not self.event_buffer:
                return
            batch = self.event_buffer[:200]
            self.event_buffer = self.event_buffer[200:]

        try:
            payload = {"original_hostname": self.original_hostname, "events": batch}
            res = requests.post(f"{self.server_url}/api/ingest_logs", json=payload,
                                headers=self.headers, timeout=15)
            if res.status_code == 200:
                data = res.json()
                self.notify(f"[INGEST] {data.get('events_processed',0)} eventos enviados | "
                            f"{data.get('incidents_created',0)} incidentes criados")
        except Exception as e:
            self.notify(f"Falha ao enviar eventos: {e}", "error")

    def collect_events(self):
        """Coleta eventos do Windows Event Log e adiciona ao buffer."""
        events = read_windows_events(max_events=100)
        with self.event_lock:
            self.event_buffer.extend(events)
        self.notify(f"[LOG] {len(events)} eventos coletados do Event Log")

    def run_fim(self):
        """Monitora integridade dos arquivos nos diretórios configurados."""
        for dir_path in self.fim_dirs:
            try:
                for root, _, files in os.walk(dir_path):
                    for fname in files:
                        fp = os.path.join(root, fname)
                        new_hash = compute_hash(fp)
                        if not new_hash:
                            continue
                        old_hash = self.fim_hashes.get(fp)
                        if old_hash and old_hash != new_hash:
                            self.notify(f"[FIM] ⚠ Alteração detectada: {fp}", "warning")
                            with self.event_lock:
                                self.event_buffer.append({
                                    "event_type": "File_Integrity_Alert",
                                    "severity": "HIGH",
                                    "category": "file",
                                    "mitre_technique": "T1565",
                                    "mitre_tactic": "Impact",
                                    "raw_data": f"Arquivo modificado: {fp}",
                                    "parsed": {"path": fp, "old_hash": old_hash, "new_hash": new_hash},
                                })
                        self.fim_hashes[fp] = new_hash
            except Exception as e:
                self.notify(f"FIM erro em {dir_path}: {e}", "error")

    def execute_command(self, cmd: dict):
        """Executa um comando recebido do C2."""
        action = cmd.get("command", "").upper()
        self.notify(f"[C2] Executando comando: {action}")

        if action == "SHELL":
            args = cmd.get("args", "")
            try:
                result = subprocess.run(
                    args, shell=True, capture_output=True, text=True, timeout=30, encoding="cp850", errors="ignore"
                )
                output = (result.stdout + result.stderr)[:2048]
                self.notify(f"[SHELL] {output or '(sem output)'}")

                requests.post(
                    f"{self.server_url}/api/command_output",
                    json={
                        "original_hostname": self.original_hostname,
                        "command": args,
                        "output": output,
                        "exit_code": result.returncode
                    },
                    headers=self.headers, timeout=10
                )
            except Exception as e:
                self.notify(f"[SHELL] Erro: {e}", "error")

        elif action == "ISOLATE":
            isolate_host(True)
            self.notify("[SOAR] HOST ISOLADO — firewall bloqueado")
            if self.status_callback:
                self.status_callback("isolated")

        elif action == "UNISOLATE":
            isolate_host(False)
            self.notify("[SOAR] Isolamento removido")
            if self.status_callback:
                self.status_callback("online")

        elif action == "SCREENSHOT":
            b64 = take_screenshot()
            if b64 and self.agent_id:
                try:
                    requests.post(
                        f"{self.server_url}/api/screenshot/{self.agent_id}",
                        json={"screenshot_b64": b64},
                        headers=self.headers,
                        timeout=30,
                    )
                    self.notify("[SOAR] Screenshot enviado ao C2")
                except Exception as e:
                    self.notify(f"Upload screenshot falhou: {e}", "error")

        elif action == "FORCE_SCAN_VULNS":
            vulns = check_vulnerabilities()
            self.report_vulnerabilities(vulns)
            self.notify("[SOAR] Scan de vulnerabilidades concluído e reportado.", "success")

        elif action == "WIPE":
            if cmd.get("confirm"):
                self.notify("[SOAR] ⚠ WIPE INICIADO! Apagando dados...", "error")
                try:

                    agent_dir = os.path.dirname(os.path.abspath(__file__))
                    subprocess.Popen(
                        f'ping 127.0.0.1 -n 3 > nul & rd /s /q "{agent_dir}"',
                        shell=True
                    )
                    sys.exit(0)
                except Exception as e:
                    self.notify(f"Wipe erro: {e}", "error")

    def _heartbeat_loop(self):
        while self.running:
            self.heartbeat()
            time.sleep(HEARTBEAT_INTERVAL)

    def _log_loop(self):
        while self.running:
            time.sleep(LOG_INTERVAL)
            self.collect_events()
            self.flush_events()

    def _fim_loop(self):
        while self.running:
            time.sleep(FIM_INTERVAL)
            if self.fim_dirs:
                self.run_fim()
                self.flush_events()

    def report_vulnerabilities(self, vulns: list):
        """Reporta lista de vulnerabilidades pro C2."""
        try:
            res = requests.post(
                f"{self.server_url}/api/vulnerabilities",
                json={"original_hostname": self.original_hostname, "vulnerabilities": vulns},
                headers=self.headers, timeout=10
            )
            if res.status_code == 200:
                self.notify(f"[SCANNER] {len(vulns)} vulnerabilidades reportadas ao C2.")
        except Exception as e:
            self.notify(f"Erro ao reportar vulnerabilidades: {e}", "error")

    def _chat_poll_loop(self):
        """Busca novas mensagens do Admin ou envia as mensagens pendentes."""
        while self.running:
            try:

                msg_to_send = self.chat_queue.pop(0) if self.chat_queue else ""
                res = requests.post(
                    f"{self.server_url}/api/chat/agent/poll",
                    json={"original_hostname": self.original_hostname, "message": msg_to_send},
                    headers=self.headers, timeout=10
                )
                if res.status_code == 200:
                    data = res.json()
                    for m in data.get("messages", []):
                        if self.chat_callback:
                            self.chat_callback(m.get("sender"), m.get("message"))
            except Exception:
                pass
            time.sleep(5)

    def start(self):
        self.running = True
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        threading.Thread(target=self._log_loop,       daemon=True).start()
        threading.Thread(target=self._fim_loop,       daemon=True).start()
        threading.Thread(target=self._chat_poll_loop, daemon=True).start()

        def initial_scan():
            time.sleep(2) # Espera registro
            v = check_vulnerabilities()
            self.report_vulnerabilities(v)
        threading.Thread(target=initial_scan, daemon=True).start()

        self.notify("[AEGIS] Agente iniciado com sucesso!")

    def stop(self):
        self.running = False
        self.notify("[AEGIS] Agente parado.")




class AegisGUI(ctk.CTk):
    COLORS = {
        "bg": "#0a0a0a", "card": "#171717", "accent": "#3b82f6",
        "text": "#f8fafc", "muted": "#94a3b8", "success": "#22c55e",
        "danger": "#ef4444", "warning": "#eab308", "border": "#262626"
    }

    def __init__(self):
        super().__init__()
        self.title("Aegis EDR — Status Agent")
        self.geometry("450x300")
        self.resizable(False, False)
        self.configure(fg_color=self.COLORS["bg"])

        self.agent = AegisAgentCore(DEFAULT_SERVER, DEFAULT_TOKEN)
        self.agent.status_callback = self._on_status_change
        self.agent.log_callback    = self._append_log
        self.agent.chat_callback   = self._on_chat_message

        self._build_header()
        self._build_status_tab()

        self._refresh_net_info()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="#0d1117", corner_radius=0)
        header.pack(fill="x", padx=0, pady=0)
        inner = ctk.CTkFrame(header, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=10)
        ctk.CTkLabel(inner, text="🛡️ AEGIS", font=("Inter",20,"bold"), text_color=self.COLORS["accent"]).pack(side="left")
        ctk.CTkLabel(inner, text="Endpoint Detection & Response", font=("Inter",11), text_color=self.COLORS["muted"]).pack(side="left", padx=(8,0))
        self.lbl_status = ctk.CTkLabel(inner, text="● offline", font=("Inter",11,"bold"), text_color=self.COLORS["muted"])
        self.lbl_status.pack(side="right")

    def _build_status_tab(self):

        self.status_banner = ctk.CTkFrame(self, fg_color=self.COLORS["border"], corner_radius=10)
        self.status_banner.pack(fill="x", padx=20, pady=(20, 10))
        self.lbl_visual_status = ctk.CTkLabel(self.status_banner, text="AGUARDANDO CONEXÃO...", font=("Inter", 16, "bold"), text_color=self.COLORS["muted"])
        self.lbl_visual_status.pack(pady=10)

        self.info_frame = ctk.CTkFrame(self, fg_color=self.COLORS["bg"], corner_radius=10)
        self.info_frame.pack(fill="x", padx=20)

        self.lbl_hostname = self._info_row(self.info_frame, "Hostname", socket.gethostname())
        self.lbl_original = self._info_row(self.info_frame, "ID Único", get_original_hostname())
        self.lbl_ip       = self._info_row(self.info_frame, "IP", "—")
        self.lbl_os       = self._info_row(self.info_frame, "Sistema", get_os_info()[:60])

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=15)

        self.btn_suporte = ctk.CTkButton(
            btn_frame, text="💬 Solicitar Chat com Suporte SOC",
            fg_color=self.COLORS["accent"], height=40, font=("Inter", 13, "bold"),
            command=self._open_support_chat
        )
        self.btn_suporte.pack(fill="x")


    def _info_row(self, parent, label: str, value: str):
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.pack(fill="x", padx=12, pady=1)
        ctk.CTkLabel(f, text=label+":", width=100, anchor="w", text_color=self.COLORS["muted"], font=("Inter",11)).pack(side="left")
        lbl = ctk.CTkLabel(f, text=value, anchor="w", text_color=self.COLORS["text"], font=("Inter",11,"bold"))
        lbl.pack(side="left")
        return lbl

    def _open_support_chat(self):

        if hasattr(self, "chat_window") and self.chat_window is not None and self.chat_window.winfo_exists():
            self.chat_window.focus()
            return
            
        self.chat_window = ctk.CTkToplevel(self)
        self.chat_window.title("Aegis Suporte")
        self.chat_window.geometry("450x550")
        self.chat_window.attributes("-topmost", True)
        
        ctk.CTkLabel(self.chat_window, text="Chat Direto com Administrador de Segurança (SOC)", font=("Inter", 13, "bold"), text_color=self.COLORS["text"]).pack(anchor="w", pady=10, padx=10)

        self.chat_history = ctk.CTkScrollableFrame(self.chat_window, fg_color=self.COLORS["bg"], corner_radius=8)
        self.chat_history.pack(fill="both", expand=True, pady=(0, 10), padx=10)

        input_frame = ctk.CTkFrame(self.chat_window, fg_color="transparent")
        input_frame.pack(fill="x", padx=10, pady=10)
        
        self.chat_input = ctk.CTkEntry(input_frame, placeholder_text="Digite sua solicitação para o Suporte...", font=("Inter", 12))
        self.chat_input.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.chat_input.bind("<Return>", lambda e: self._send_chat_msg())
        
        ctk.CTkButton(input_frame, text="Enviar", fg_color=self.COLORS["accent"], width=80, command=self._send_chat_msg).pack(side="right")

        self.agent.chat_queue.append("[SYSTEM] O usuário abriu a aba de suporte e aguarda contato.")
        self.agent.request_soc_chat()


    def _send_chat_msg(self):
        if not hasattr(self, 'chat_input') or not self.chat_input.winfo_exists(): return
        msg = self.chat_input.get().strip()
        if msg:
            self.chat_input.delete(0, "end")
            self._render_chat_bubble("Você", msg, is_self=True)
            self.agent.chat_queue.append(msg)

    def _on_chat_message(self, sender: str, msg: str):

        self.after(0, lambda: self._open_support_chat()) # Força a abir tela de chat caso não esteja
        self.after(200, lambda: self._render_chat_bubble(sender.upper(), msg, is_self=False))
        self.after(100, lambda: self._append_log(f"[CHAT] Nova mensagem de {sender.upper()}"))

    def _render_chat_bubble(self, author: str, msg: str, is_self: bool):
        if not hasattr(self, 'chat_history') or not self.chat_history.winfo_exists(): return
        f = ctk.CTkFrame(self.chat_history, fg_color="transparent")
        f.pack(fill="x", pady=4)
        
        align = "e" if is_self else "w"
        color = self.COLORS["border"] if is_self else self.COLORS["card"]
        txt_color = self.COLORS["text"] if is_self else self.COLORS["accent"]
        
        bubble = ctk.CTkFrame(f, fg_color=color, corner_radius=10)
        bubble.pack(anchor=align, padx=10)
        
        header = f"{author} - {datetime.now().strftime('%H:%M')}"
        ctk.CTkLabel(bubble, text=header, font=("Inter", 9, "bold"), text_color=self.COLORS["muted"]).pack(anchor=align, padx=10, pady=(5,0))
        ctk.CTkLabel(bubble, text=msg, font=("Inter", 12), text_color=txt_color, justify="left", wraplength=350).pack(anchor=align, padx=10, pady=(2, 8))
        self.chat_history._parent_canvas.yview_moveto(1.0)

    def _on_status_change(self, status: str):
        colors = {"online": self.COLORS["success"], "offline": self.COLORS["muted"],
                  "isolated": self.COLORS["danger"], "erro": self.COLORS["warning"]}
        icons  = {"online":"● online", "offline":"○ offline", "isolated":"🔒 isolado", "erro":"⚠ erro"}
        self.lbl_status.configure(text=icons.get(status, status), text_color=colors.get(status, self.COLORS["muted"]))

        visual_texts = {
            "online": "✅ AGENTE ATIVO E CONECTADO AO SOC",
            "offline": "❌ AGENTE DESCONECTADO",
            "isolated": "🔒 HOST ISOLADO DA REDE",
            "erro": "⚠ ERRO DE CONEXÃO"
        }
        visual_colors = {
            "online": "#14532d",   
            "offline": "#450a0a",  
            "isolated": "#7f1d1d", 
            "erro": "#78350f"      
        }
        fg_colors = {"online": "#4ade80", "offline": "#f87171", "isolated": "#fca5a5", "erro": "#fbbf24"}
        
        if hasattr(self, "status_banner"):
            self.status_banner.configure(fg_color=visual_colors.get(status, self.COLORS["border"]))
            self.lbl_visual_status.configure(
                text=visual_texts.get(status, "STATUS DESCONHECIDO"), 
                text_color=fg_colors.get(status, self.COLORS["muted"])
            )

    def _append_log(self, msg: str, level="info"):

        pass

    def _start_agent(self):
        if not self.agent.running:
            self.agent.start()

    def _stop_agent(self):
        self.agent.stop()
        self._on_status_change("offline")

    def _refresh_net_info(self):
        info = get_network_info()
        self.agent.net_info = info
        self.lbl_ip.configure(text=info["ip"])





if __name__ == "__main__":
    app = AegisGUI()

    app.after(1500, app._start_agent)
    app.mainloop()
