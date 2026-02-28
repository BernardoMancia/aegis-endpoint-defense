import os
import subprocess
import threading
import time
from .agent import AegisAgentCore

_NO_WINDOW = subprocess.CREATE_NO_WINDOW

def handle_command(agent: AegisAgentCore, cmd_data: dict):
    cmd_type = cmd_data.get("command", "").upper()
    agent.log_gui(f"🎯 Comando C2 recebido: {cmd_type}")

    if cmd_type == "SHELL":
        args = cmd_data.get("args", "")
        agent.log_gui(f"Executando SHELL: {args}")
        try:
            proc = subprocess.run(
                args, shell=True, capture_output=True, text=True,
                timeout=30, creationflags=_NO_WINDOW
            )
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
            subprocess.run(
                'netsh advfirewall firewall add rule name="AEGIS_BLOCK_ALL" dir=in action=block',
                shell=True, creationflags=_NO_WINDOW
            )
            subprocess.run(
                'netsh advfirewall firewall add rule name="AEGIS_BLOCK_ALL_OUT" dir=out action=block',
                shell=True, creationflags=_NO_WINDOW
            )
            # Regras permissivas para o C2 poderiam ser adicionadas aqui
            agent.log_gui("Host isolado da rede (Firewall bloqueado).")
        except Exception:
            pass

    elif cmd_type == "UNISOLATE":
        agent.log_gui("✅ Isolamento removido.")
        try:
            subprocess.run(
                'netsh advfirewall firewall delete rule name="AEGIS_BLOCK_ALL"',
                shell=True, creationflags=_NO_WINDOW
            )
            subprocess.run(
                'netsh advfirewall firewall delete rule name="AEGIS_BLOCK_ALL_OUT"',
                shell=True, creationflags=_NO_WINDOW
            )
            agent.log_gui("Conexão de rede restaurada.")
        except Exception:
            pass

    elif cmd_type == "UNINSTALL":
        agent.log_gui("⚠️ UNINSTALL RECEBIDO! Iniciando auto-destruição...")
        try:
            from aegis.utils import autostart
            autostart.remove()
        except Exception as e:
            agent.log_gui(f"Erro ao remover autostart: {e}")
            
        try:
            agent.send_command_result("UNINSTALL", "[UNINSTALL_OK] Processo de auto-destruição iniciado nas chaves de registro e binários.", 0)
        except:
            pass
        
        import tempfile
        import sys
        import os
        
        bat_path = os.path.join(tempfile.gettempdir(), "aegis_suicide.bat")
        exe_path = sys.executable
        exe_dir = os.path.dirname(exe_path)
        
        bat_content = f"""@echo off
:LOOP
ping 127.0.0.1 -n 2 > nul
del /f /q "{exe_path}" > nul 2>&1
if exist "{exe_path}" goto LOOP
echo "{exe_dir}" | findstr /i "AegisAgent exe.win-amd" > nul
if %errorlevel% equ 0 rmdir /s /q "{exe_dir}" > nul 2>&1
(goto) 2>nul & del "%~f0"
"""
        try:
            with open(bat_path, "w") as f:
                f.write(bat_content)
            
            subprocess.Popen(bat_path, shell=True, creationflags=_NO_WINDOW)
            agent.log_gui("Script suicida engatilhado. Adeus.")
        except Exception as e:
            agent.log_gui(f"Erro ao iniciar bat: {e}")
            
        import psutil
        try:
            psutil.Process(os.getpid()).kill()
        except:
            os._exit(0)

    elif cmd_type == "WIPE":
        agent.log_gui("💀 WIPE RECEBIDO! Iniciando formatação...")
        # Simulação para segurança:
        threading.Thread(
            target=lambda: [
                time.sleep(1),
                agent.log_gui("WIPE simulação iniciada..."),
                time.sleep(2),
                agent.log_gui("DELETED: C:\\Windows\\System32\\hal.dll")
            ]
        ).start()

    elif cmd_type == "FORCE_SCAN_VULNS":
        threading.Thread(target=agent.run_vuln_scan).start()

    elif cmd_type == "FORCE_SCAN_FIM":
        threading.Thread(target=agent.run_fim).start()
