import os
import sys
import time
import tempfile
import subprocess

exe_path = "test_kill.exe"
with open(exe_path, "w") as f:
    f.write("fake_exe")

bat_path = os.path.join(tempfile.gettempdir(), "aegis_suicide.bat")
bat_content = f"""@echo off
ping 127.0.0.1 -n 4 > nul
del /f /q "{exe_path}"
del /f /q "%~f0"
"""

with open(bat_path, "w") as f:
    f.write(bat_content)

print(f"Executando BAT: {bat_path}")
print(f"Alvo: {exe_path}")
subprocess.Popen(bat_path, shell=True)

print("Aguardando 5s para o BAT finalizar...")
time.sleep(5)

if not os.path.exists(exe_path):
    print("SUCESSO: O executavel alvo foi deletado nas sombras!")
else:
    print("FALHA: O arquivo alvo continua intacto.")

if not os.path.exists(bat_path):
    print("SUCESSO: E o BAT se auto-destruiu!")
else:
    print("FALHA: O BAT ainda esta na pasta temp.")
