import sys
import os
from cx_Freeze import setup, Executable

base_dir = os.path.dirname(os.path.abspath(__file__))
agent_dir = os.path.join(base_dir, "agent")

# Tcl/Tk paths
python_base = os.path.dirname(sys.executable)
tcl_dir = os.path.join(python_base, "tcl", "tcl8.6")
tk_dir = os.path.join(python_base, "tcl", "tk8.6")

include_files = [
    (tcl_dir, "tcl8.6"),
    (tk_dir, "tk8.6"),
]

build_exe_options = {
    "packages": [
        "customtkinter",
        "tkinter",
        "requests",
        "psutil",
        "win32api",
        "win32con",
        "PIL",
        "aegis",
    ],
    "excludes": ["unittest", "email.policy", "xml"],
    "include_files": include_files,
    "path": [agent_dir] + sys.path,
    "include_msvcr": True,
    "zip_include_packages": "*",
    "zip_exclude_packages": ["tkinter", "customtkinter", "aegis"],
}

# Windows startup registry entry via MSI
msi_data = {
    "Registry": [
        (
            "AutostartReg",
            -2147483646,  # HKCU
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "AegisAgent",
            "[TARGETDIR]AegisAgent.exe",
            "COMPONENT_MAIN",
        )
    ],
    "Component": [
        ("COMPONENT_MAIN", "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}", "TARGETDIR", 0, None, "AegisAgent.exe"),
    ],
    "Condition": [
        ("COMPONENT_MAIN", 0, "AUTOSTART = 1"),
    ],
}

bdist_msi_options = {
    "upgrade_code": "{B2C3D4E5-F678-90AB-CDEF-1234567890A1}",
    "add_to_path": False,
    "initial_target_dir": r"[LocalAppDataFolder]\Aegis Security\Agent",
    "install_icon": os.path.join(agent_dir, "aegis_icon.ico"),
    "summary_data": {
        "author": "Aegis Security",
        "comments": "Aegis EDR Endpoint Agent - Protecao de endpoints em tempo real",
        "keywords": "security endpoint defense EDR SIEM",
    },
}

exe = Executable(
    script=os.path.join(agent_dir, "main.py"),
    base="gui",
    target_name="AegisAgent.exe",
    icon=os.path.join(agent_dir, "aegis_icon.ico"),
)

setup(
    name="Aegis Endpoint Agent",
    version="1.1.0",
    description="Aegis EDR - Endpoint Detection & Response Agent",
    options={
        "build_exe": build_exe_options,
        "bdist_msi": bdist_msi_options,
    },
    executables=[exe],
)
