"""SQLCipher 解密桥：调用外部 sqlcipher3 可执行文件把加密 EDB 转为明文 SQLite。

对齐 JS 版 vendor/sqlcipher.mjs 的职责，但走「外部二进制 + ATTACH/EXPORT」路线，
避免在 Python 里内嵌 4MB wasm。

依赖：
    macOS:   brew install sqlcipher
    Windows: choco install sqlcipher / scoop install sqlcipher
    Linux:   apt install sqlcipher

WAL 重放：把 -wal/-shm/-journal 伴随文件复制到主库同目录同名，
sqlcipher3 打开主库时会自动 checkpoint 合入（与 JS 版 readEdbWithWal 等价）。
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# SQLCipher 4（KakaoTalk 新版）默认参数
CIPHER_COMPATIBILITY = 4
KDF_ITER = 256_000
PAGE_SIZE = 4096
HMAC_USE = "HMAC_SHA512"
KDF_USE = "PBKDF2_HMAC_SHA512"


class SqlCipherNotFound(RuntimeError):
    pass


def _bundled_dirs() -> list[Path]:
    """随包/同目录候选根目录（用于绿色部署 / PyInstaller 打包后定位 sqlcipher）。

    覆盖：
      - PyInstaller onefile 运行时解压目录 sys._MEIPASS（datas 打进来的 bin/ 在此）
      - frozen（onedir/exe）时 sys.executable 所在目录
      - 源码脚本模式：当前工作目录 + 项目根（kakao_edb/db/ 的上上级）
    """
    dirs: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        dirs.append(Path(meipass))
    try:
        if getattr(sys, "frozen", False):
            dirs.append(Path(sys.executable).resolve().parent)
        else:
            dirs.append(Path.cwd())
            # __file__ = .../<project>/kakao_edb/db/sqlcipher.py → parents[2] = <project>
            dirs.append(Path(__file__).resolve().parents[2])
    except Exception:
        pass
    # 去重且保序
    seen: set[Path] = set()
    out: list[Path] = []
    for d in dirs:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def find_sqlcipher() -> str:
    """定位 sqlcipher 可执行文件。

    优先级：
      1. 环境变量 KKV_SQLCIPHER（显式指定完整路径）
      2. 随包目录 bin/sqlcipher(.exe) 与同级目录（PyInstaller / 绿色部署）
      3. 系统 PATH（shutil.which）
      4. 常见 brew/choco 安装路径兜底
    """
    # 1. 环境变量显式指定
    env = os.environ.get("KKV_SQLCIPHER")
    if env and Path(env).exists():
        return env

    exe_names = ("sqlcipher.exe", "sqlcipher3.exe", "sqlcipher", "sqlcipher3")
    # 2. 随包/同目录（bin/ 子目录与根目录都找）
    for base in _bundled_dirs():
        for sub in ("bin", ""):
            d = base / sub if sub else base
            for name in exe_names:
                cand = d / name
                if cand.exists():
                    return str(cand)

    # 3. 系统 PATH
    for name in ("sqlcipher3", "sqlcipher"):
        p = shutil.which(name)
        if p:
            return p

    # 4. 常见 brew/choco 安装路径兜底
    for cand in (
        "/opt/homebrew/bin/sqlcipher", "/usr/local/bin/sqlcipher",
        "C:/ProgramData/chocolatey/bin/sqlcipher.exe",
    ):
        if Path(cand).exists():
            return cand
    raise SqlCipherNotFound(
        "未找到 sqlcipher 可执行文件。请安装：macOS `brew install sqlcipher` / "
        "Windows `choco install sqlcipher` / Linux `apt install sqlcipher`；"
        "或设环境变量 KKV_SQLCIPHER 指向 sqlcipher.exe，或把它放到程序同级 bin/ 目录"
    )


@dataclass
class DecryptResult:
    ok: bool
    plain_path: Path | None
    reason: str = ""


def _copy_with_sides(src_main: Path, dst_dir: Path) -> Path:
    """把主库连同 -wal/-shm/-journal 伴随文件复制到 dst_dir（保持同名，供 sqlcipher 自动 checkpoint）。"""
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst_main = dst_dir / src_main.name
    shutil.copy2(src_main, dst_main)
    for suffix in ("-wal", "-shm", "-journal"):
        side = src_main.with_name(src_main.name + suffix)
        if side.exists():
            try:
                shutil.copy2(side, dst_main.with_name(dst_main.name + suffix))
            except OSError as ex:
                log.warning("复制伴随文件失败 %s: %s", side, ex)
    return dst_main


def decrypt_to_plain(encrypted: Path, key_hex: str, out_path: Path,
                     kdf_iter: int = KDF_ITER, page_size: int = PAGE_SIZE,
                     compatibility: int = CIPHER_COMPATIBILITY,
                     hmac_alg: str = HMAC_USE, kdf_alg: str = KDF_USE,
                     timeout: int = 120) -> DecryptResult:
    """用 raw hex key 解密 SQLCipher 数据库到明文 SQLite 文件。

    走 sqlcipher CLI 的 ATTACH ... AS plaintext KEY '' + sqlcipher_export('plaintext')。
    """
    sqlcipher = find_sqlcipher()
    encrypted = Path(encrypted).expanduser().resolve()
    out_path = Path(out_path).expanduser().resolve()
    if not encrypted.exists():
        return DecryptResult(False, None, f"文件不存在: {encrypted}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()

    # 复制到临时目录，连同伴随文件（WAL 重放）
    with tempfile.TemporaryDirectory(prefix="kkv-decrypt-") as tmp:
        work_main = _copy_with_sides(encrypted, Path(tmp))
        script = f"""PRAGMA key = "x'{key_hex}'";
PRAGMA cipher_compatibility = {compatibility};
PRAGMA kdf_iter = {kdf_iter};
PRAGMA cipher_page_size = {page_size};
PRAGMA cipher_hmac_algorithm = {hmac_alg};
PRAGMA cipher_kdf_algorithm = {kdf_alg};
ATTACH DATABASE '{out_path.as_posix()}' AS plaintext KEY '';
SELECT sqlcipher_export('plaintext');
DETACH DATABASE plaintext;
"""
        try:
            proc = subprocess.run(
                [sqlcipher, "-batch", str(work_main)],
                input=script, capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return DecryptResult(False, None, f"sqlcipher 超时 {timeout}s")

        # sqlcipher 在密钥错误时不一定非零退出，需校验产物
        if not out_path.exists() or out_path.stat().st_size < 100:
            err = (proc.stderr or proc.stdout or "").strip()[:300]
            return DecryptResult(False, None, f"解密失败（密钥或参数不匹配）: {err}")

        # 用 stdlib sqlite3 快速校验明文可读（SQLCipher 头 16 字节应为 "SQLite format 3\0"）
        with out_path.open("rb") as f:
            head = f.read(16)
        if head != b"SQLite format 3\x00":
            out_path.unlink(missing_ok=True)
            return DecryptResult(False, None, "产物非明文 SQLite（头部校验失败）")

    return DecryptResult(True, out_path)


def verify_key(encrypted: Path, key_hex: str,
               kdf_iter: int = KDF_ITER, compatibility: int = CIPHER_COMPATIBILITY) -> bool:
    """快速验证密钥是否能打开数据库（不导出，只跑一次 SELECT count(*) FROM sqlite_master）。"""
    sqlcipher = find_sqlcipher()
    script = f"""PRAGMA key = "x'{key_hex}'";
PRAGMA cipher_compatibility = {compatibility};
PRAGMA kdf_iter = {kdf_iter};
SELECT count(*) FROM sqlite_master;
"""
    try:
        proc = subprocess.run(
            [sqlcipher, "-batch", str(encrypted)],
            input=script, capture_output=True, text=True, timeout=30, check=False,
        )
    except subprocess.TimeoutExpired:
        return False
    out = (proc.stdout or "").strip()
    # 成功时输出一个数字；失败时 stderr 含 "file is not a database" 或空输出
    if proc.returncode != 0:
        return False
    first = out.splitlines()[0] if out else ""
    return first.strip().isdigit()
