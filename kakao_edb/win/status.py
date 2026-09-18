"""Windows 两步流状态机（对齐 JS 版 winTwoStepStatus）。

advice 枚举：
    decrypt-now       文件可读且密钥齐全 → 直接解密最新落盘数据
    decrypt-snapshot  有密钥有快照 → 解密快照
    snapshot          文件可读但无密钥 → 先快照，再引导启动 KakaoTalk 取密钥
    collect-keys      有探针缓存无密钥 → 启动并登录 KakaoTalk 后取密钥
    exit-kakao        文件被运行时保护 → 完全退出 KakaoTalk 后重新检测
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from ..cache import Cache
from .discover import EdbEntry, is_kakao_running, list_edb_files
from .probe import EdbState, probe_edb_state

log = logging.getLogger(__name__)


@dataclass
class TwoStepStatus:
    running: bool
    core_count: int
    readable: int
    key_count: int
    snapshot_count: int
    snapshot_at: int | None
    has_snapshot: bool
    advice: str
    edbs: list[EdbEntry]


def win_two_step_status(cache: Cache, base_dir: Path | None = None) -> TwoStepStatus:
    edbs = list_edb_files(base_dir)
    running = is_kakao_running()

    # 核心库可读性统计（探针三态）
    readable = 0
    for edb in edbs:
        st = probe_edb_state(edb.path, read_head=False)
        if st.state == EdbState.NORMAL:
            readable += 1

    keys = cache.load_keys()
    key_count = len(keys)
    snap_files = cache.list_snapshot()
    snapshot_count = len(snap_files)
    snapshot_at = cache.snapshot_at()
    has_snapshot = snapshot_count > 0

    # 决策树（与 JS 版 winTwoStepStatus 一致）
    if running and readable == 0:
        advice = "exit-kakao"
    elif readable > 0 and key_count > 0:
        advice = "decrypt-now"
    elif has_snapshot and key_count > 0:
        advice = "decrypt-snapshot"
    elif readable > 0 and key_count == 0:
        advice = "snapshot"
    elif cache.load_probes() and key_count == 0:
        advice = "collect-keys"
    elif running:
        advice = "exit-kakao"
    else:
        advice = "snapshot" if readable > 0 else "exit-kakao"

    return TwoStepStatus(
        running=running, core_count=len(edbs), readable=readable,
        key_count=key_count, snapshot_count=snapshot_count,
        snapshot_at=snapshot_at, has_snapshot=has_snapshot,
        advice=advice, edbs=edbs,
    )
