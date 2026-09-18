"""EDB 运行时保护三态探针（对齐 JS 版 probeEdbState / buildProbeHeads）。

新版 KakaoTalk 运行时对核心 EDB 做反取证保护：
    - 文件内容全零（磁盘上抹掉）
    - 独占锁（共享读打开失败）
    - 正常（退出态，可读且非全零）

探针头：page1 前 4096 字节的 hex，用于运行态内存扫描时定位密钥
（内存里 SQLCipher 上下文携带该页头，可作为密钥候选的验证材料）。
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

log = logging.getLogger(__name__)

PROBE_HEAD_LEN = 4096


class EdbState(str, Enum):
    NORMAL = "normal"        # 可读且非全零（退出态）
    ZEROED = "zeroed"        # 文件全零（运行时反取证）
    LOCKED = "locked"        # 独占锁（运行时保护）
    MISSING = "missing"      # 文件不存在
    UNKNOWN = "unknown"


@dataclass
class ProbeResult:
    state: EdbState
    head_hex: str | None = None  # 仅 NORMAL 时有值
    size: int = 0


def _is_all_zero(data: bytes) -> bool:
    # 快速路径：检查前 4096 字节；全零再抽样中后段
    if not data:
        return True
    if any(b != 0 for b in data[:PROBE_HEAD_LEN]):
        return False
    step = max(1, len(data) // 16)
    return all(data[i] == 0 for i in range(0, len(data), step))


def probe_edb_state(path: Path, read_head: bool = True) -> ProbeResult:
    """检测单个 EDB 文件的运行时保护状态。"""
    path = Path(path)
    if not path.exists():
        return ProbeResult(EdbState.MISSING, size=0)
    try:
        size = path.stat().st_size
    except OSError:
        return ProbeResult(EdbState.MISSING, size=0)
    if size == 0:
        return ProbeResult(EdbState.ZEROED, size=0)

    # Windows 共享读尝试：运行时独占锁会抛 PermissionError
    try:
        # 用 os.open 带 FILE_SHARE_READ|FILE_SHARE_WRITE（Windows 语义）
        if os.name == "nt":
            import msvcrt  # noqa: F401  仅确保 Windows 环境
            fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_BINARY", 0))
            try:
                head = os.read(fd, PROBE_HEAD_LEN) if read_head else b""
            finally:
                os.close(fd)
        else:
            with path.open("rb") as f:
                head = f.read(PROBE_HEAD_LEN) if read_head else b""
    except (PermissionError, OSError) as ex:
        log.debug("probe %s 打开失败: %s", path.name, ex)
        return ProbeResult(EdbState.LOCKED, size=size)

    if not head:
        return ProbeResult(EdbState.UNKNOWN, size=size)

    # 全零检测：读整个文件抽样（大文件只读前 64KB + 中后段抽样）
    try:
        with path.open("rb") as f:
            sample = f.read(64 * 1024)
            if size > 64 * 1024:
                f.seek(size // 2)
                sample += f.read(4096)
                f.seek(max(0, size - 4096))
                sample += f.read(4096)
    except OSError:
        sample = head

    if _is_all_zero(sample):
        return ProbeResult(EdbState.ZEROED, size=size)

    return ProbeResult(EdbState.NORMAL, head_hex=head.hex(), size=size)


def build_probe_heads(edbs: list[Path]) -> dict[str, str]:
    """对一组 EDB 构建探针头缓存 {name: hex(page1[:4096])}。

    仅收录 NORMAL 态的文件；ZEROED/LOCKED 跳过（运行态无法读取真实页头）。
    """
    out: dict[str, str] = {}
    for p in edbs:
        r = probe_edb_state(Path(p))
        if r.state == EdbState.NORMAL and r.head_hex:
            out[Path(p).name] = r.head_hex
    return out
