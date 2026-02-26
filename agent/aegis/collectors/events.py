import os
import json
import logging
import subprocess

log = logging.getLogger("aegis-agent")


def read_windows_events(log_type="Security", last_n=20) -> list:
    """Lê os últimos N eventos de segurança do Windows via PowerShell."""
    if os.name != "nt":
        return []
    try:
        script = f"""
        $events = Get-WinEvent -LogName {log_type} -MaxEvents {last_n} -ErrorAction SilentlyContinue
        $result = @()
        foreach ($e in $events) {{
            $result += @{{
                event_id = $e.Id
                time = $e.TimeCreated.ToString('o')
                message = $e.Message
                source = $e.ProviderName
            }}
        }}
        $result | ConvertTo-Json -Compress
        """
        proc = subprocess.run(["powershell", "-NoProfile", "-Command", script],
                              capture_output=True, text=True, timeout=15,
                              creationflags=subprocess.CREATE_NO_WINDOW)
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout.strip())
        return []
    except Exception as e:
        log.error(f"[EVT] Falha ao coletar eventos: {e}")
        return []
