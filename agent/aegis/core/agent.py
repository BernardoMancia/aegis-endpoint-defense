import os
import time
import requests
import json
import logging
from ..collectors.events import read_windows_events
from ..collectors.vulnerabilities import check_vulnerabilities
from ..utils.system import get_os_info, get_original_hostname, get_network_info
from ..utils.crypto import take_screenshot, compute_hash

log = logging.getLogger("aegis-agent")


class AegisAgentCore:
    def __init__(self, server_url: str, token: str):
        self.server_url = server_url.rstrip("/")
        self.token = token
        self.original_hostname = get_original_hostname()
        self.running = False
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        })
        self.last_events = []
        self.chat_history = []
        self.on_log_callback = None
        self.on_chat_callback = None
        self.monitored_dirs = [os.path.expanduser("~\\Downloads")]
        self.fim_baseline = {}

    def log_gui(self, msg: str):
        log.info(msg)
        if self.on_log_callback:
            self.on_log_callback(msg)

    def heartbeat(self) -> dict | None:
        url = f"{self.server_url}/api/heartbeat"
        net = get_network_info()
        payload = {
            "original_hostname": self.original_hostname,
            "hostname": os.getenv("COMPUTERNAME", self.original_hostname),
            "ip_address": net["ip"],
            "mac_address": net["mac"],
            "os_info": get_os_info(),
            "agent_version": "1.1",
            "platform": "windows",
            "extra_data": {"gateway": net["gateway"]}
        }
        try:
            resp = self.session.post(url, json=payload, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                self.agent_id = data.get("agent_id")
                self.log_gui(f"Heartbeat enviado (AgentID: {self.agent_id})")
                return data
            else:
                self.log_gui(f"Falha heartbeat HTTP {resp.status_code}")
                return None
        except Exception as e:
            self.log_gui(f"Erro heartbeat: {e}")
            return None

    def flush_events(self):
        url = f"{self.server_url}/api/ingest_logs"
        events = read_windows_events("System", 10) + read_windows_events("Security", 10)
        self.last_events = events
        filtered = []
        for e in events:
            evt_id = str(e.get("event_id"))
            if evt_id in ("4624", "4625", "4688", "4697", "7045", "1102", "4672", "4720", "4104"):
                severity = "HIGH" if evt_id in ("4625", "4697", "1102", "4672", "4104") else "MEDIUM"
                category = "process" if evt_id in ("4688", "4697", "7045", "4104") else "auth"
            else:
                severity = "LOW"
                category = "generic"

            filtered.append({
                "event_id": evt_id,
                "event_type": e.get("message", f"Event {evt_id}")[:80].strip(),
                "severity": severity,
                "source": e.get("source", "windows"),
                "category": category,
                "raw": json.dumps(e)
            })
        if not filtered:
            self.log_gui("Nenhum log lido do Event Viewer (verifique privilégios).")
            return

        payload = {"original_hostname": self.original_hostname, "events": filtered}
        try:
            r = self.session.post(url, json=payload, timeout=5)
            if r.status_code == 200:
                self.log_gui(f"Enviados {len(filtered)} logs.")
        except Exception as e:
            self.log_gui(f"Erro ao enviar logs: {e}")

    def run_fim(self):
        new_baseline = {}
        changes = []
        for d in self.monitored_dirs:
            if not os.path.exists(d):
                continue
            for root, _, files in os.walk(d):
                for f in files:
                    if f.startswith("~") or f.endswith(".tmp"): continue
                    path = os.path.join(root, f)
                    try:
                        sz = os.path.getsize(path)
                        if sz > 10 * 1024 * 1024: continue
                        h = compute_hash(path)
                        if not h: continue
                        new_baseline[path] = h
                        if path in self.fim_baseline:
                            if self.fim_baseline[path] != h:
                                changes.append(f"MODIFIED: {path}")
                        else:
                            if self.fim_baseline:
                                changes.append(f"NEW: {path}")
                    except Exception:
                        pass
        if self.fim_baseline and changes:
            self.log_gui(f"FIM: {len(changes)} alterações detectadas!")
            evts = [{"event_id": "FIM_ALERT", "event_type": "File Integrity Altered", "severity": "HIGH", "category": "file", "parsed": {"changes": changes}}]
            try:
                self.session.post(f"{self.server_url}/api/ingest_logs", json={"original_hostname": self.original_hostname, "events": evts})
            except Exception: pass
        self.fim_baseline = new_baseline
        self.log_gui(f"Baseline FIM atualizada: {len(new_baseline)} arquivos.")

    def run_vuln_scan(self):
        self.log_gui("Iniciando Vulnerability Scan...")
        vulns = check_vulnerabilities()
        if vulns:
            self.log_gui(f"Scan concluído: {len(vulns)} vulnerabilidades.")
            payload = {"original_hostname": self.original_hostname, "vulnerabilities": vulns}
            try:
                r = self.session.post(f"{self.server_url}/api/vulnerabilities", json=payload, timeout=5)
                if r.status_code == 200:
                    self.log_gui("Vulnerabilidades reportadas ao SOC.")
            except Exception as e:
                self.log_gui(f"Falha ao reportar vulns: {e}")
        else:
            self.log_gui("Scan concluído: Nenhuma vulnerabilidade pendente.")

    def request_chat_support(self):
        url = f"{self.server_url}/api/agent/request_chat"
        try:
            r = self.session.post(url, json={"original_hostname": self.original_hostname}, timeout=5)
            if r.status_code == 200:
                self.log_gui("Solicitação de suporte enviada ao SOC!")
        except Exception as e:
            self.log_gui(f"Erro ao pedir suporte: {e}")

    def poll_chat(self, pending_msg: str = ""):
        url = f"{self.server_url}/api/chat/agent/poll"
        try:
            r = self.session.post(url, json={"original_hostname": self.original_hostname, "message": pending_msg}, timeout=5)
            if r.status_code == 200:
                data = r.json()
                for m in data.get("messages", []):
                    self.chat_history.append({"sender": "admin", "message": m["message"], "time": m["timestamp"]})
                    if self.on_chat_callback:
                        self.on_chat_callback()
        except Exception as e:
            log.warning(f"Erro poll chat: {e}")

    def send_command_result(self, cmd: str, output: str, code: int):
        url = f"{self.server_url}/api/command_output"
        payload = {"original_hostname": self.original_hostname, "command": cmd, "output": output, "exit_code": code}
        try:
            self.session.post(url, json=payload, timeout=5)
        except Exception as e:
            self.log_gui(f"Erro reply command: {e}")

    def send_screenshot(self):
        b64 = take_screenshot()
        if not b64:
            self.log_gui("⚠️ Falha ao capturar screenshot (Pillow não instalado ou erro de sistema).")
            return

        agent_id = getattr(self, 'agent_id', None)
        if not agent_id:
            self.log_gui("❌ Erro ao enviar screenshot: agent_id não disponível (heartbeat pendente).")
            return

        url = f"{self.server_url}/api/screenshot/{agent_id}"
        try:
            r = self.session.post(url, json={"screenshot_b64": b64}, timeout=15)
            if r.status_code == 200:
                self.log_gui("✅ Screenshot enviado e processado pelo C2.")
            else:
                self.log_gui(f"❌ Erro ao enviar screenshot: C2 retornou HTTP {r.status_code}")
        except Exception as e:
            self.log_gui(f"💥 Erro de conexão ao enviar print: {e}")
