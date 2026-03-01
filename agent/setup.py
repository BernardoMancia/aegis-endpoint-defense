import sys
from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need
# fine tuning.
build_options = {
    "packages": ["os", "sys", "ctypes", "logging", "threading", "psutil", "requests", "json", "uuid", "socket", "platform", "subprocess", "PIL"],
    "excludes": ["unittest"],
    "include_files": ["aegis_icon.ico"]
}

# base="gui" should be used only for Windows GUI app
# As we want stealth (headless), "gui" prevents the console from even flashing
base = "gui" if sys.platform == "win32" else None

executables = [
    Executable(
        "main.py",
        base=base,
        target_name="AegisAgent.exe",
        icon="aegis_icon.ico",
        shortcut_name="Aegis EDR Agent",
        shortcut_dir="ProgramMenuFolder"
    )
]

setup(
    name="AegisAgent",
    version="1.0.0",
    description="Aegis SOC Endpoint Agent - Stealth Mode",
    options={"build_exe": build_options},
    executables=executables
)
