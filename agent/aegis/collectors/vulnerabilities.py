import os
import subprocess
import logging

log = logging.getLogger("aegis-agent")


def check_vulnerabilities() -> list:
    """Verifica vulnerabilidades básicas no sistema local."""
    vulns = []
    if os.name != "nt":
        return vulns

    # 1. Antivírus desativado (simples)
    try:
        cmd = 'powershell -NoProfile -Command "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"'
        out = subprocess.check_output(cmd, encoding='utf-8', errors='ignore').strip()
        if out == "False":
            vulns.append({
                "title": "Windows Defender Desativado",
                "description": "A Proteção em Tempo Real do Windows Defender está desligada.",
                "severity": "CRITICAL",
                "remediation_cmd": "Set-MpPreference -DisableRealtimeMonitoring $false"
            })
    except Exception:
        pass

    # 2. Firewall desativado
    try:
        cmd = 'netsh advfirewall show currentprofile state'
        out = subprocess.check_output(cmd, encoding='utf-8', errors='ignore')
        if "OFF" in out.upper() or "DESLIGADO" in out.upper():
            vulns.append({
                "title": "Firewall do Windows Desativado",
                "description": "O perfil atual de firewall está desativado.",
                "severity": "HIGH",
                "remediation_cmd": "netsh advfirewall set currentprofile state on"
            })
    except Exception:
        pass

    # 3. UAC Desativado
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
        val, _ = winreg.QueryValueEx(key, "EnableLUA")
        winreg.CloseKey(key)
        if val == 0:
            vulns.append({
                "title": "UAC Desativado",
                "description": "O User Account Control (UAC) está desabilitado no Registro.",
                "severity": "HIGH",
                "remediation_cmd": "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f"
            })
    except Exception:
        pass

    # 4. RDP Habilitado
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server")
        val, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
        winreg.CloseKey(key)
        if val == 0:
            vulns.append({
                "title": "Área de Trabalho Remota (RDP) Ativa",
                "description": "O serviço RDP está habilitado (fDenyTSConnections=0).",
                "severity": "MEDIUM",
                "remediation_cmd": "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f"
            })
    except Exception:
        pass

    # 5. SMBv1 Habilitado
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")
        val, _ = winreg.QueryValueEx(key, "SMB1")
        winreg.CloseKey(key)
        if val == 1:
            vulns.append({
                "title": "Protocolo Legado SMBv1 Ativo",
                "description": "O protocolo vulnerável SMBv1 está habilitado.",
                "severity": "CRITICAL",
                "remediation_cmd": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
            })
    except FileNotFoundError:
        pass
    except Exception:
        pass

    return vulns
