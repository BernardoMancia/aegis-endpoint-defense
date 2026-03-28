# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('C:\\Users\\lukeo\\AppData\\Local\\Python\\pythoncore-3.14-64\\tcl\\tcl8.6', 'tcl8.6'), ('C:\\Users\\lukeo\\AppData\\Local\\Python\\pythoncore-3.14-64\\tcl\\tk8.6', 'tk8.6'), ('C:\\Users\\lukeo\\AppData\\Local\\Python\\pythoncore-3.14-64\\DLLs\\tcl86t.dll', '.'), ('C:\\Users\\lukeo\\AppData\\Local\\Python\\pythoncore-3.14-64\\DLLs\\tk86t.dll', '.')]
binaries = []
hiddenimports = []
tmp_ret = collect_all('customtkinter')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['agent\\main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['agent\\hook_tcl.py'],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='AegisAgent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['agent\\aegis_icon.ico'],
)
