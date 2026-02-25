import sys
import logging
import winreg

log = logging.getLogger("aegis-agent")

AUTOSTART_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_NAME = "AegisAgent"


def is_installed() -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY)
        winreg.QueryValueEx(key, AUTOSTART_NAME)
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return False


def install() -> bool:
    try:
        exe_path = sys.executable
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, AUTOSTART_NAME, 0, winreg.REG_SZ, f'"{exe_path}" "{sys.argv[0]}"')
        winreg.CloseKey(key)
        log.info("[PERSIST] Autostart instalado no registro.")
        return True
    except Exception as e:
        log.error(f"[PERSIST] Falha ao instalar autostart: {e}")
        return False


def remove() -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, AUTOSTART_NAME)
        winreg.CloseKey(key)
        log.info("[PERSIST] Autostart removido do registro.")
        return True
    except Exception as e:
        log.error(f"[PERSIST] Falha ao remover autostart: {e}")
        return False
