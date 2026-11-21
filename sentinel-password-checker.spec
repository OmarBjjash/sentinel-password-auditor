# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_all

datas = [('wordlist.txt', '.')]
binaries = []
hiddenimports = [
    'cryptography.hazmat.bindings._rust',
    'cryptography.hazmat.primitives.ciphers.algorithms',
    'cryptography.hazmat.primitives.ciphers.modes',
    'cryptography.hazmat.decrepit.ciphers.algorithms',
    'Registry',
    'Registry.Registry',
    'pyescrypt',
    'bcrypt',
]

# Locate python3t.dll (required by cryptography._rust on Python 3.14/3.15 free-threaded ABI)
python_base = Path(sys.base_prefix)
candidates = list(python_base.rglob('python3t.dll'))
for c in candidates:
    binaries.append((str(c), '.'))

packages = ['customtkinter', 'cryptography', 'Registry', 'passlib', 'bcrypt', 'reportlab']
for pkg in packages:
    try:
        tmp_ret = collect_all(pkg)
        datas += tmp_ret[0]
        binaries += tmp_ret[1]
        hiddenimports += tmp_ret[2]
    except Exception:
        pass

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
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
    name='sentinel-password-checker',
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
)
