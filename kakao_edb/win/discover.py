"""Windows KakaoTalk 目录发现 + 注册表设备材料 + 进程检测。

对齐 JS 版 winKakao.discoverWindows / listEdbFiles。

数据根目录：%LocalAppData%\\Kakao\\KakaoTalk（可用 KKV_WIN_BASE_DIR 覆盖）。
目录结构：
    <base>/users/<userId>/chat/KakaoChat.db            旧版单库
    <base>/users/<userId>/db/TalkUserDB.edb            好友表
    <base>/users/<userId>/db/chatListInfo.edb          聊天室列表
    <base>/users/<userId>/db/chatLogs_<N>.edb          每聊天室一库（新版）
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_DEFAULT_BASE = Path(os.environ.get("LOCALAPPDATA", "")) / "Kakao" / "KakaoTalk"
_EDB_GLOB = ("*.edb", "*.db")
_SIDE_SUFFIX_RE = re.compile(r"-(wal|shm|journal)$", re.I)


@dataclass
class EdbEntry:
    name: str
    path: Path
    size: int
    user_id: str | None = None
    kind: str = "chat"  # chat / user / chatlist / other


@dataclass
class DeviceMaterial:
    """注册表 DeviceInfo 下的一组设备材料（旧版 SQLCipher 派生用；新版无需）。"""
    dev_id: str = ""
    extra: dict[str, str] = field(default_factory=dict)


@dataclass
class KakaoDiscovery:
    base_dir: Path
    users_dir: Path | None
    dev_ok: bool
    dev_ids: list[DeviceMaterial]
    edbs: list[EdbEntry]
    user_id_candidates: list[dict]


def _base_dir() -> Path:
    env = os.environ.get("KKV_WIN_BASE_DIR")
    if env:
        return Path(env).expanduser().resolve()
    return _DEFAULT_BASE


def is_kakao_running() -> bool:
    return len(find_kakao_pids()) > 0


def find_kakao_pids() -> list[int]:
    """tasklist 查 KakaoTalk.exe 进程 PID 列表。"""
    if os.name != "nt":
        return []
    try:
        proc = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq KakaoTalk.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=8, check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    pids: list[int] = []
    for line in (proc.stdout or "").splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[0].lower() == "kakaotalk.exe":
            try:
                pids.append(int(parts[1]))
            except ValueError:
                continue
    return pids


def _read_registry_device_info() -> tuple[bool, list[DeviceMaterial]]:
    """reg query 读取 HKCU\\Software\\Kakao\\DeviceInfo（旧版材料；新版可能不存在）。"""
    if os.name != "nt":
        return False, []
    key = r"HKCU\Software\Kakao\DeviceInfo"
    try:
        proc = subprocess.run(["reg", "query", key, "/s"],
                              capture_output=True, text=True, timeout=8, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, []
    if proc.returncode != 0:
        return False, []
    materials: list[DeviceMaterial] = []
    cur: DeviceMaterial | None = None
    for line in (proc.stdout or "").splitlines():
        line = line.rstrip()
        if line.startswith(key):
            if cur:
                materials.append(cur)
            cur = DeviceMaterial()
        elif cur is not None and line.strip():
            m = re.match(r"\s+(\S+)\s+REG_\S+\s+(.*)", line)
            if m:
                name, val = m.group(1), m.group(2).strip()
                if name.lower() in ("dev_id", "devid"):
                    cur.dev_id = val
                else:
                    cur.extra[name] = val
    if cur:
        materials.append(cur)
    return bool(materials), materials


def _classify(name: str) -> str:
    n = name.lower()
    if n.startswith("talkuserdb"):
        return "user"
    if n.startswith("chatlistinfo"):
        return "chatlist"
    if n.startswith("chatlogs") or n.endswith(".edb") or n.endswith(".db"):
        return "chat"
    return "other"


def list_edb_files(base: Path | None = None) -> list[EdbEntry]:
    """扫描 <base>/users/*/db/ 与 <base>/users/*/chat/ 下的 .edb/.db（排除伴随文件）。"""
    base = base or _base_dir()
    users_dir = base / "users"
    out: list[EdbEntry] = []
    if not users_dir.exists():
        return out
    for user_dir in users_dir.iterdir():
        if not user_dir.is_dir():
            continue
        uid = user_dir.name
        for sub in ("db", "chat", ""):
            d = user_dir / sub if sub else user_dir
            if not d.exists():
                continue
            for pattern in _EDB_GLOB:
                for f in d.glob(pattern):
                    if not f.is_file():
                        continue
                    if _SIDE_SUFFIX_RE.search(f.name):
                        continue
                    try:
                        size = f.stat().st_size
                    except OSError:
                        continue
                    out.append(EdbEntry(name=f.name, path=f, size=size,
                                        user_id=uid, kind=_classify(f.name)))
    # 去重（同一文件可能从多个 glob 命中）
    seen: set[Path] = set()
    uniq: list[EdbEntry] = []
    for e in out:
        rp = e.path.resolve()
        if rp in seen:
            continue
        seen.add(rp)
        uniq.append(e)
    uniq.sort(key=lambda e: -e.size)
    return uniq


def discover_windows(base: Path | None = None) -> KakaoDiscovery:
    base = base or _base_dir()
    users_dir = base / "users"
    dev_ok, dev_ids = _read_registry_device_info()
    edbs = list_edb_files(base)
    candidates = [{"num": int(d.name), "source": "users-dir"}
                  for d in users_dir.iterdir() if d.is_dir() and d.name.isdigit()] if users_dir.exists() else []
    return KakaoDiscovery(
        base_dir=base,
        users_dir=users_dir if users_dir.exists() else None,
        dev_ok=dev_ok, dev_ids=dev_ids, edbs=edbs,
        user_id_candidates=candidates,
    )
