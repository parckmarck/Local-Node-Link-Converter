# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

root = Path(SPECPATH)
a = Analysis(
    [str(root / "main.py")],
    pathex=[str(root)],
    # 测试内核 mihomo.exe 不参与收集：由 scripts/build_windows.py 在 PyInstaller
    # 收尾后单独写入并校验 SHA256。这样即使安全软件瞬时拦截写入该文件，打包脚本
    # 也能自动重试，而不会让整个打包失败（2026-10-29 修复）。
    binaries=[],
    datas=[
        (str(root / "assets" / "icons"), "assets/icons"),
        (str(root / "licenses"), "licenses"),
        (str(root / "vendor" / "manifest.json"), "vendor"),
    ],
    hiddenimports=["PySide6.QtSvg"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
        "PySide6.QtWebEngineQuick", "PySide6.QtQml", "PySide6.QtQuick",
        "PySide6.QtMultimedia", "PySide6.QtPdf", "PySide6.QtSql",
        "numpy", "pandas", "matplotlib", "torch", "scipy", "pytest",
        "IPython", "notebook",
    ],
    noarchive=False,
    optimize=1,
)

# Qt 6.11 在 Windows 上使用系统自带的 ICU(System32\icuuc.dll)。若打包机的 PATH 上
# 混有第三方缓存里的同名 icuuc/icudt 文件(例如 poppler),它们会被误收集进包并覆盖
# 系统 ICU,导致 “DLL load failed while importing QtCore: 找不到指定的程序”。
# 从收集结果中过滤掉这些文件(2026-10-29 修复)。
_ICU_NAMES = {"icuuc.dll", "icuin.dll", "icu.dll"}


def _keep_binary(entry):
    base = entry[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base not in _ICU_NAMES and not base.startswith("icudt")


a.binaries = [entry for entry in a.binaries if _keep_binary(entry)]

pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="NodeDesk",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=True,
    icon=str(root / "assets" / "app.ico"),
)
coll = COLLECT(
    exe, a.binaries, a.datas,
    strip=False,
    upx=False,
    name="NodeDesk",
)
