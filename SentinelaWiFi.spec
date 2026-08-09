# -*- mode: python ; coding: utf-8 -*-
# Build reproduzível do Sentinela Wi-Fi.
#   pyinstaller SentinelaWiFi.spec
# Gera dist/SentinelaWiFi.exe (onefile, sem console, com ícone e a base de
# fabricantes embutidos — main.py/scanner.py leem esses recursos via
# sys._MEIPASS quando rodando a partir do executável empacotado).

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[
        ("oui_vendors.json", "."),
        ("icon.ico", "."),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="SentinelaWiFi",
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
    icon="icon.ico",
)
