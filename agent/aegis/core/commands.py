import os
import subprocess
import threading
import time
from .agent import AegisAgentCore

def handle_command(agent: AegisAgentCore, cmd_data: dict):
    cmd_type = cmd_data.get("command", "").upper()
    agent.log_gui(f"🎯 Comando C2 recebido: {cmd_type}")

    if cmd_type == "SHELL":
        args = cmd_data.get("args", "")
        agent.log_gui(f"Executando SHELL: {args}")
        try:
            proc = subprocess.run(args, shell=True, capture_output=True, text=True, timeout=30)
            out = proc.stdout if proc.stdout else proc.stderr
            agent.send_command_result(args, out, proc.returncode)
        except subprocess.TimeoutExpired:
            agent.send_command_result(args, "Timeout (30s)", -1)
        except Exception as e:
            agent.send_command_result(args, str(e), -1)

    elif cmd_type == "SCREENSHOT":
        agent.log_gui("Tirando print da tela...")
        agent.send_screenshot()

    elif cmd_type == "ISOLATE":
        agent.log_gui("⚠️ ALERTA: ISOLAMENTO DE REDE ACIONADO!")
        try:
            subprocess.run("netsh advfirewall firewall add rule name=\"AEGIS_BLOCK_ALL\" dir=in action=block", shell=True)
            subprocess.run("netsh advfirewall firewall add rule name=\"AEGIS_BLOCK_ALL_OUT\" dir=out action=block", shell=True)
            # Regras permissivas para o C2 poderiam ser adicionadas aqui
            agent.log_gui("Host isolado da rede (Firewall bloqueado).")
        except:
            pass

    elif cmd_type == "UNISOLATE":
        agent.log_gui("✅ Isolamento removido.")
        try:
            subprocess.run("netsh advfirewall firewall delete rule name=\"AEGIS_BLOCK_ALL\"", shell=True)
            subprocess.run("netsh advfirewall firewall delete rule name=\"AEGIS_BLOCK_ALL_OUT\"", shell=True)
            agent.log_gui("Conexão de rede restaurada.")
        except:
            pass

    elif cmd_type == "WIPE":
        agent.log_gui("💀 WIPE RECEBIDO! Iniciando formatação...")
        # Simulação para segurança:
        threading.Thread(target=lambda: [time.sleep(1), agent.log_gui("WIPE simulação iniciada..."), time.sleep(2), agent.log_gui("DELETED: C:\\Windows\\System32\\hal.dll")]).start()

    elif cmd_type == "force_scan_vulns":
        threading.Thread(target=agent.run_vuln_scan).start()

    elif cmd_type == "force_scan_fim":
        threading.Thread(target=agent.run_fim).start()
