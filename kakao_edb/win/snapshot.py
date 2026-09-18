"""退出态 EDB 快照（对齐 JS 版 snapshotCoreEdbs / loadSnapshotEdbs）。

把核心 EDB 连同 -wal/-shm/-journal 伴随文件复制到缓存目录 snapshot/，
供运行态取钥后离线解密（避开 KakaoTalk 重新落盘覆盖的窗口）。
"""
from __future__ import annotations

import logging
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from ..cache import Cache
from .discover import EdbEntry
from .probe import EdbState, probe_edb_state

log = logging.getLogger(__name__)

_SIDE_SUFFIX_RE = re.compile(r"-(wal|shm|journal)$", re.I)
# 核心库：TalkUserDB / chatListInfo / chatLogs_*（其他如 TalkMemoDB 可选）
_CORE_PATTERNS = (
    re.compile(r"^talkuserdb", re.I),
    re.compile(r"^chatlistinfo", re.I),
    re.compile(r"^chatlogs_", re.I),
    re.compile(r"\.edb$", re.I),
)


def _is_core(name: str) -> bool:
    return any(p.search(name) for p in _CORE_PATTERNS)


@dataclass
class SnapshotResult:
    ok: bool
    count: int = 0
    dir: Path | None = None
    skipped: list[str] = field(default_factory=list)
    reason: str = ""


def snapshot_core_edbs(edbs: list[EdbEntry], cache: Cache) -> SnapshotResult:
    """退出态快照：仅复制 NORMAL 态的核心库 + 伴随文件。"""
    snap_dir = cache.snapshot_dir
    snap_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    skipped: list[str] = []
    for edb in edbs:
        if not _is_core(edb.name):
            continue
        st = probe_edb_state(edb.path)
        if st.state != EdbState.NORMAL:
            skipped.append(f"{edb.name}({st.state.value})")
            continue
        try:
            shutil.copy2(edb.path, snap_dir / edb.name)
            count += 1
        except OSError as ex:
            log.warning("快照 %s 失败: %s", edb.name, ex)
            skipped.append(f"{edb.name}(copy-error)")
            continue
        # 伴随文件
        for suffix in ("-wal", "-shm", "-journal"):
            side = edb.path.with_name(edb.path.name + suffix)
            if side.exists():
                try:
                    shutil.copy2(side, snap_dir / side.name)
                except OSError as ex:
                    log.warning("快照伴随文件 %s 失败: %s", side.name, ex)
    if count == 0:
        return SnapshotResult(False, 0, snap_dir, skipped,
                              reason="核心库均不可读（KakaoTalk 可能正在运行并保护文件）")
    return SnapshotResult(True, count, snap_dir, skipped)


def load_snapshot_edbs(cache: Cache) -> tuple[bool, list[EdbEntry], str]:
    """读取已有快照清单，返回 (ok, edbs, reason)。"""
    snap_dir = cache.snapshot_dir
    if not snap_dir.exists():
        return False, [], "快照目录不存在"
    out: list[EdbEntry] = []
    for p in sorted(snap_dir.iterdir()):
        if not p.is_file():
            continue
        if _SIDE_SUFFIX_RE.search(p.name):
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        out.append(EdbEntry(name=p.name, path=p, size=size, kind="chat"))
    if not out:
        return False, [], "快照为空"
    return True, out, ""
