import os
import sys
import platform
import socket
import subprocess
import uuid
from pathlib import Path


def get_original_hostname() -> str:
    hostname = socket.gethostname()
    try:
        machine_id = str(uuid.UUID(int=uuid.getnode()))
    except Exception:
        machine_id = hostname
    return f"{hostname}_{machine_id[:8]}"


def get_os_info() -> str:
    return f"{platform.system()} {platform.version()} ({platform.machine()})"


def get_network_info() -> dict:
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
