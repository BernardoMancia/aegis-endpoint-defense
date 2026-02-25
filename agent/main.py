import os
import sys
import argparse
from dotenv import load_dotenv
from pathlib import Path

# Adiciona o diretório atual ao sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

load_dotenv()

from aegis.core.agent import AegisAgentCore
from aegis.utils import autostart
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("aegis-agent")


def main():
    parser = argparse.ArgumentParser(description="AEGIS C2 Endpoint Agent")
    parser.add_argument("--url", help="URL do C2 Server (ex: http://localhost:5000)")
    parser.add_argument("--token", help="Bearer Token da API do Aegis")
    parser.add_argument("--install", action="store_true", help="Instala no autostart do Windows")
    parser.add_argument("--remove", action="store_true", help="Remove do autostart do Windows")
    parser.add_argument("--headless", action="store_true", help="Executa sem interface gráfica")
    args = parser.parse_args()

    if args.install:
        autostart.install()
        sys.exit(0)

    if args.remove:
        autostart.remove()
        sys.exit(0)

    # Carrega do env por padrão se não for passado em args
    server_url = args.url or os.getenv("AEGIS_C2_URL", "http://127.0.0.1:5000")
    token = args.token or os.getenv("AEGIS_API_TOKEN", "AEGIS-C913AD56BF3BCC24DB9D34A8510A847B")

    # Inicia agente (o core roda threads independetes com a GUI em cima)
    agent = AegisAgentCore(server_url=server_url, token=token)

    if args.headless:
        log.info("Iniciando em modo HEADLESS...")
        import time
        from aegis.core.commands import handle_command
        import threading
        # Threads
        def agent_loop():
            time.sleep(2)
            while True:
                resp = agent.heartbeat()
                if resp and resp.get("pending_command"):
                    handle_command(agent, resp["pending_command"])
                agent.flush_events()
                agent.poll_chat()
                time.sleep(15)
        threading.Thread(target=agent_loop, daemon=True).start()
        threading.Thread(target=lambda: [time.sleep(10), agent.run_vuln_scan()], daemon=True).start()
        threading.Thread(target=lambda: [time.sleep(5), agent.run_fim()], daemon=True).start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Encerrando Aegis Agent...")
            sys.exit(0)
    else:
        log.info("Iniciando GUI do Agente...")
        from aegis.gui.app import AegisAgentGUI
        app = AegisAgentGUI(agent)
        app.mainloop()

if __name__ == "__main__":
    main()
