# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：把 kakao_export.py 打成单文件 KakaoChatExport.exe。

用法（在 Windows 上、项目根目录执行）：
    python -m PyInstaller --noconfirm KakaoChatExport.spec
或直接双击 build.bat。

设计要点：
  - onefile：产物是单个 exe，拷到没有 Python 环境的电脑双击即可（运行时自带 Python）。
  - 随包 bin/：若项目根存在 bin/ 目录，其中所有文件（sqlcipher.exe 及依赖 DLL）
    会被打进 exe，运行时解压到 sys._MEIPASS/bin/，find_sqlcipher() 能自动定位。
  - console=True：交互式引导需要终端。
  - uac_admin=False：默认不弹 UAC（同用户 KakaoTalk 取钥通常无需管理员）；
    若取钥失败，右键「以管理员身份运行」即可。
"""
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

HERE = Path(SPECPATH).resolve()

# ---- 随包数据：bin/ 下的 sqlcipher.exe 及其依赖 DLL（存在才收集） ----
datas = []
_bin = HERE / "bin"
if _bin.exists():
    for _f in sorted(_bin.iterdir()):
        if _f.is_file():
            datas.append((str(_f), "bin"))

# ---- 隐藏导入：kakao_edb 的 win/mac 子包是延迟 import，需显式收集 ----
hiddenimports = ["cryptography", "cryptography.hazmat.primitives.ciphers"]
try:
    hiddenimports += collect_submodules("kakao_edb")
except Exception:
    hiddenimports += [
        "kakao_edb", "kakao_edb.orchestrator", "kakao_edb.cli", "kakao_edb.cache",
        "kakao_edb.db.key_derivation", "kakao_edb.db.plist_parser",
        "kakao_edb.db.kakao_db", "kakao_edb.db.sqlcipher", "kakao_edb.db.sqlcipher_page",
        "kakao_edb.mac.discover",
        "kakao_edb.win.discover", "kakao_edb.win.probe", "kakao_edb.win.snapshot",
        "kakao_edb.win.memscan", "kakao_edb.win.decrypt", "kakao_edb.win.status",
    ]

a = Analysis(
    [str(HERE / "kakao_export.py")],
    pathex=[str(HERE)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "PyQt5", "PySide6", "numpy", "pandas"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="KakaoChatExport",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=False,
)
