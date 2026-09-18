"""Windows 子模块（对齐 src/win/winKakao.cjs，按职责拆分）。

模块划分：
    discover  注册表设备材料 + KakaoTalk 目录发现 + 进程检测
    probe     全零页/独占锁三态检测 + 探针头缓存
    snapshot  退出态 EDB 快照（含 -wal/-shm/-journal）
    memscan   ctypes ReadProcessMemory + SQLCipher 密钥模式匹配
    decrypt   缓存密钥解密（走 db.sqlcipher 外部二进制）
    status    winTwoStepStatus 两步流状态机
"""
from .discover import (
    KakaoDiscovery, EdbEntry, discover_windows, list_edb_files,
    is_kakao_running, find_kakao_pids,
)
from .probe import probe_edb_state, EdbState, build_probe_heads
from .snapshot import snapshot_core_edbs, load_snapshot_edbs, SnapshotResult
from .memscan import collect_keys_to_cache, CollectKeysResult
from .decrypt import decrypt_with_cached_keys, DecryptFilesResult
from .status import win_two_step_status, TwoStepStatus

__all__ = [
    "KakaoDiscovery", "EdbEntry", "discover_windows", "list_edb_files",
    "is_kakao_running", "find_kakao_pids",
    "probe_edb_state", "EdbState", "build_probe_heads",
    "snapshot_core_edbs", "load_snapshot_edbs", "SnapshotResult",
    "collect_keys_to_cache", "CollectKeysResult",
    "decrypt_with_cached_keys", "DecryptFilesResult",
    "win_two_step_status", "TwoStepStatus",
]
