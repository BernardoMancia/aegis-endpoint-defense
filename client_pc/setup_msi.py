import sys
from cx_Freeze import setup, Executable

build_exe_options = {
    "packages": ["os", "sys", "requests", "customtkinter", "PIL", "psutil", "dotenv"],
    "include_files": [


    ],
}

bdist_msi_options = {
    "upgrade_code": "{98765432-1234-5678-9012-ABCDEF123456}",
    "add_to_path": False,
    "initial_target_dir": r"[ProgramFilesFolder]\AegisAgent",
}

base = None
if sys.platform == "win32":
    base = "gui"

setup(
    name="AegisAgent",
    version="1.0",
    description="Aegis Endpoint Defense Agent",
    options={
        "build_exe": build_exe_options,
        "bdist_msi": bdist_msi_options,
    },
    executables=[
        Executable(
            "agent_gui.py",
            base=base,
            target_name="AegisAgent.exe",
            shortcut_name="Aegis Agent",
            shortcut_dir="ProgramMenuFolder",
        )
    ],
)
